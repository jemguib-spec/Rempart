// Package oidc est un client OpenID Connect (partie « relying party ») pour
// connecter les administrateurs de Rempart via Keycloak ou tout fournisseur
// conforme : découverte, code d'autorisation avec PKCE (RFC 7636), vérification
// du jeton d'identité et déconnexion initiée par Rempart. Aucune dépendance
// externe ; TLS toujours vérifié ; les clés sont prises uniquement dans le
// JWKS annoncé par la découverte.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Skew tolère un léger décalage d'horloge avec le fournisseur.
const Skew = 60 * time.Second

// Config décrit le client enregistré chez le fournisseur.
type Config struct {
	Issuer       string // https://kc.example/realms/corp (sans « / » final)
	ClientID     string
	ClientSecret string // vide : client public (PKCE seul)
	RedirectURL  string // https://rempart.example:8080/api/oidc/callback
	Scopes       []string
	RootCAs      *x509.CertPool // nil : racines du système
}

// Metadata est l'extrait utile du document de découverte.
type Metadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	EndSessionEndpoint    string   `json:"end_session_endpoint"`
	IDTokenAlgs           []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
}

// Provider est un fournisseur découvert.
type Provider struct {
	cfg    Config
	client *http.Client
	Meta   Metadata
	Now    func() time.Time

	mu        sync.Mutex
	keys      []jwk
	keysAt    time.Time
	refreshAt time.Time
}

func httpsURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}

// ValidateConfig vérifie la forme de la configuration.
func ValidateConfig(c Config) error {
	if !httpsURL(c.Issuer) || strings.HasSuffix(c.Issuer, "/") || strings.Contains(c.Issuer, "?") {
		return errors.New("émetteur (issuer) : URL https:// sans « / » final attendue, par ex. https://keycloak.example/realms/corp")
	}
	if c.ClientID == "" || len(c.ClientID) > 255 {
		return errors.New("identifiant client requis")
	}
	if !httpsURL(c.RedirectURL) || strings.Contains(c.RedirectURL, "?") {
		return errors.New("URL de retour : https://<serveur>:<port>/api/oidc/callback attendu")
	}
	return nil
}

// NewHTTPClient renvoie un client HTTP aux délais courts, sans redirection et
// sans compromis sur la vérification TLS.
func NewHTTPClient(roots *x509.CertPool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (p *Provider) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s : HTTP %d", u, res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(v)
}

// Discover lit le document de découverte et les clés du fournisseur.
func Discover(ctx context.Context, c Config) (*Provider, error) {
	if err := ValidateConfig(c); err != nil {
		return nil, err
	}
	p := &Provider{cfg: c, client: NewHTTPClient(c.RootCAs), Now: time.Now}
	if err := p.getJSON(ctx, c.Issuer+"/.well-known/openid-configuration", &p.Meta); err != nil {
		return nil, fmt.Errorf("découverte OIDC : %w", err)
	}
	m := p.Meta
	if m.Issuer != c.Issuer {
		return nil, fmt.Errorf("découverte OIDC : émetteur annoncé %q différent de %q", m.Issuer, c.Issuer)
	}
	for _, u := range []string{m.AuthorizationEndpoint, m.TokenEndpoint, m.JWKSURI} {
		if !httpsURL(u) {
			return nil, errors.New("découverte OIDC : point d'accès manquant ou non https")
		}
	}
	if m.EndSessionEndpoint != "" && !httpsURL(m.EndSessionEndpoint) {
		p.Meta.EndSessionEndpoint = ""
	}
	if len(m.CodeChallengeMethods) > 0 && !slices.Contains(m.CodeChallengeMethods, "S256") {
		return nil, errors.New("le fournisseur ne prend pas en charge PKCE S256")
	}
	if err := p.refreshKeys(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Provider) refreshKeys(ctx context.Context) error {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := p.getJSON(ctx, p.Meta.JWKSURI, &set); err != nil {
		return fmt.Errorf("clés du fournisseur (JWKS) : %w", err)
	}
	var keys []jwk
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue // clés de chiffrement (Keycloak publie RSA-OAEP)
		}
		if k.parse() == nil {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return errors.New("aucune clé de signature utilisable dans le JWKS")
	}
	p.mu.Lock()
	p.keys, p.keysAt = keys, time.Now()
	p.mu.Unlock()
	return nil
}

// key trouve la clé d'un jeton ; un identifiant inconnu provoque au plus un
// rechargement du JWKS par minute (rotation des clés chez le fournisseur).
func (p *Provider) key(ctx context.Context, h jwsHeader) (*jwk, error) {
	find := func() *jwk {
		p.mu.Lock()
		defer p.mu.Unlock()
		var cand []*jwk
		for i := range p.keys {
			k := &p.keys[i]
			if (h.Kid == "" || k.Kid == h.Kid) && (k.Alg == "" || k.Alg == h.Alg) && algOK(h.Alg, k.pub) {
				cand = append(cand, k)
			}
		}
		if len(cand) == 1 {
			return cand[0]
		}
		return nil
	}
	if k := find(); k != nil {
		return k, nil
	}
	p.mu.Lock()
	may := time.Since(p.refreshAt) > time.Minute
	if may {
		p.refreshAt = time.Now()
	}
	p.mu.Unlock()
	if may {
		if err := p.refreshKeys(ctx); err != nil {
			return nil, err
		}
		if k := find(); k != nil {
			return k, nil
		}
	}
	return nil, errors.New("clé de signature du jeton inconnue")
}

// ---- code d'autorisation ----

// RandomToken renvoie 256 bits aléatoires encodés en base64url.
func RandomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b64.EncodeToString(b)
}

// Challenge calcule le code_challenge S256 d'un vérificateur PKCE.
func Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return b64.EncodeToString(h[:])
}

// AuthURL construit l'URL de redirection vers le fournisseur.
func (p *Provider) AuthURL(state, nonce, verifier, acr string) string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", p.cfg.ClientID)
	v.Set("redirect_uri", p.cfg.RedirectURL)
	scopes := []string{"openid"}
	for _, s := range p.cfg.Scopes {
		if s != "openid" && s != "" {
			scopes = append(scopes, s)
		}
	}
	v.Set("scope", strings.Join(scopes, " "))
	v.Set("state", state)
	v.Set("nonce", nonce)
	v.Set("code_challenge", Challenge(verifier))
	v.Set("code_challenge_method", "S256")
	if acr != "" {
		v.Set("acr_values", acr)
	}
	sep := "?"
	if strings.Contains(p.Meta.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return p.Meta.AuthorizationEndpoint + sep + v.Encode()
}

// Tokens est la réponse du point d'accès des jetons.
type Tokens struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

// Exchange échange le code contre les jetons.
func (p *Provider) Exchange(ctx context.Context, code, verifier string) (*Tokens, error) {
	v := url.Values{}
	v.Set("grant_type", "authorization_code")
	v.Set("code", code)
	v.Set("redirect_uri", p.cfg.RedirectURL)
	v.Set("code_verifier", verifier)
	v.Set("client_id", p.cfg.ClientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Meta.TokenEndpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.cfg.ClientSecret != "" {
		// client_secret_basic : identifiant et secret encodés (RFC 6749 §2.3.1).
		req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	}
	res, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("échange du code : %w", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if len(e.Error) > 64 {
			e.Error = e.Error[:64]
		}
		return nil, fmt.Errorf("échange du code refusé (HTTP %d %s)", res.StatusCode, strings.Map(func(r rune) rune {
			if r < 0x20 || r > 0x7e {
				return -1
			}
			return r
		}, e.Error))
	}
	var t Tokens
	if err := json.Unmarshal(body, &t); err != nil || t.IDToken == "" {
		return nil, errors.New("réponse du fournisseur sans jeton d'identité")
	}
	if t.TokenType != "" && !strings.EqualFold(t.TokenType, "bearer") {
		return nil, errors.New("type de jeton inattendu")
	}
	return &t, nil
}

// verify contrôle la signature et les dates d'un jeton, et son émetteur.
func (p *Provider) verify(ctx context.Context, raw string) (map[string]any, error) {
	h, claims, signed, sig, err := splitJWT(raw)
	if err != nil {
		return nil, err
	}
	if len(p.Meta.IDTokenAlgs) > 0 && !slices.Contains(p.Meta.IDTokenAlgs, h.Alg) {
		return nil, fmt.Errorf("algorithme %q non annoncé par le fournisseur", h.Alg)
	}
	k, err := p.key(ctx, h)
	if err != nil {
		return nil, err
	}
	if err := verifySig(h.Alg, k.pub, signed, sig); err != nil {
		return nil, err
	}
	if ClaimString(claims, "iss") != p.cfg.Issuer {
		return nil, errors.New("émetteur du jeton inattendu")
	}
	now := p.Now()
	exp, ok := num(claims, "exp")
	if !ok || now.After(time.Unix(exp, 0).Add(Skew)) {
		return nil, errors.New("jeton expiré")
	}
	if nbf, ok := num(claims, "nbf"); ok && now.Add(Skew).Before(time.Unix(nbf, 0)) {
		return nil, errors.New("jeton pas encore valide")
	}
	if iat, ok := num(claims, "iat"); ok && now.Add(Skew).Before(time.Unix(iat, 0)) {
		return nil, errors.New("jeton émis dans le futur : vérifiez l'horloge")
	}
	return claims, nil
}

// VerifyIDToken vérifie un jeton d'identité (OIDC Core §3.1.3.7).
func (p *Provider) VerifyIDToken(ctx context.Context, raw, nonce string) (map[string]any, error) {
	claims, err := p.verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	aud := ClaimStrings(claims, "aud")
	if !slices.Contains(aud, p.cfg.ClientID) {
		return nil, errors.New("jeton destiné à un autre client")
	}
	azp := ClaimString(claims, "azp")
	if (len(aud) > 1 || azp != "") && azp != p.cfg.ClientID {
		return nil, errors.New("partie autorisée (azp) inattendue")
	}
	got := ClaimString(claims, "nonce")
	if nonce == "" || subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return nil, errors.New("nonce du jeton incorrect (rejeu ?)")
	}
	if ClaimString(claims, "sub") == "" {
		return nil, errors.New("jeton sans sujet")
	}
	if _, ok := num(claims, "iat"); !ok {
		return nil, errors.New("jeton sans date d'émission")
	}
	return claims, nil
}

// VerifyAccessToken vérifie un jeton d'accès au format JWT (cas de Keycloak),
// pour y lire les rôles quand ils ne figurent pas dans le jeton d'identité.
// Il doit avoir été délivré à ce client (azp).
func (p *Provider) VerifyAccessToken(ctx context.Context, raw string) (map[string]any, error) {
	if strings.Count(raw, ".") != 2 {
		return nil, errors.New("jeton d'accès opaque")
	}
	claims, err := p.verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	if ClaimString(claims, "azp") != p.cfg.ClientID {
		return nil, errors.New("jeton d'accès délivré à un autre client")
	}
	return claims, nil
}

// LogoutURL renvoie l'URL de déconnexion du fournisseur (RP-initiated
// logout), ou "" s'il n'en annonce pas.
func (p *Provider) LogoutURL(idToken, postLogout string) string {
	if p.Meta.EndSessionEndpoint == "" {
		return ""
	}
	v := url.Values{}
	v.Set("client_id", p.cfg.ClientID)
	if idToken != "" {
		v.Set("id_token_hint", idToken)
	}
	if postLogout != "" {
		v.Set("post_logout_redirect_uri", postLogout)
	}
	sep := "?"
	if strings.Contains(p.Meta.EndSessionEndpoint, "?") {
		sep = "&"
	}
	return p.Meta.EndSessionEndpoint + sep + v.Encode()
}
