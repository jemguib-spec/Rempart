// identity.go - comptes externes : connexion par annuaire LDAP et par un
// fournisseur OpenID Connect (Keycloak), rôles déduits des groupes, et
// configuration de ces sources sous ré-authentification du compte local.
//
// Principes :
//   - le compte local reste toujours utilisable : c'est l'accès de secours si
//     l'annuaire ou Keycloak sont indisponibles ;
//   - seul le compte local, après mot de passe (et code TOTP s'il est actif),
//     peut changer ces sources : sinon, un administrateur d'annuaire pourrait
//     s'octroyer des droits ou détourner le compte de service ;
//   - un utilisateur externe sans groupe reconnu n'entre pas ;
//   - les secrets (compte de service, secret client) ne sont jamais renvoyés,
//     et doivent être ressaisis si le serveur auquel ils seront envoyés change.

package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/rempart-dns/rempart/internal/identity/ldap"
	"github.com/rempart-dns/rempart/internal/identity/oidc"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/upstream"
)

// Rôles d'une session.
const (
	RoleAdmin    = "admin"    // tout, y compris la sécurité (jetons, quorum, HSM)
	RoleOperator = "operator" // filtrage, zones, certificat : pas la sécurité
	RoleRead     = "read"     // consultation
)

const (
	oidcCookie   = "rempart_oidc"
	oidcPendTTL  = 10 * time.Minute
	oidcPendMax  = 500
	ldapParallel = 4
)

func roleAllows(role, scope string) bool {
	switch role {
	case RoleAdmin:
		return true
	case RoleOperator:
		return scope == "read" || scope == "admin" || scope == "tls" || scope == "dnssec" || scope == "metrics"
	case RoleRead:
		return scope == "read" || scope == "metrics"
	}
	return false
}

func roleLabel(r string) string {
	switch r {
	case RoleAdmin:
		return "administrateur"
	case RoleOperator:
		return "opérateur"
	case RoleRead:
		return "lecture seule"
	}
	return "aucun"
}

// resolveRole renvoie le rôle le plus élevé dont un groupe est reconnu.
func resolveRole(rg state.RoleGroups, has func(string) bool) string {
	for _, c := range []struct {
		role   string
		groups []string
	}{{RoleAdmin, rg.Admin}, {RoleOperator, rg.Operator}, {RoleRead, rg.Read}} {
		for _, g := range c.groups {
			if g != "" && has(g) {
				return c.role
			}
		}
	}
	return ""
}

func ldapGroupMatcher(groups []string) func(string) bool {
	set := map[string]bool{}
	for _, g := range groups {
		set[ldap.NormalizeDN(g)] = true
	}
	return func(g string) bool { return set[ldap.NormalizeDN(g)] }
}

// identityState : état en mémoire des connexions externes.
type identityState struct {
	mu      sync.Mutex
	prov    *oidc.Provider
	provKey string
	provAt  time.Time
	pending map[string]*oidcPending // sha256(state) -> connexion en cours
	ldapSem chan struct{}
}

type oidcPending struct {
	binding  string // sha256 du cookie qui lie le retour au navigateur
	nonce    string
	verifier string
	expires  time.Time
}

func (s *identityState) reset() {
	s.mu.Lock()
	s.prov, s.provKey = nil, ""
	s.pending = nil
	s.mu.Unlock()
}

// cleanName rend un nom venant d'un annuaire ou d'un jeton sûr pour l'audit
// et l'affichage : caractères de contrôle retirés, longueur bornée.
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == unicode.ReplacementChar || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > 128 {
		s = string(r[:128])
	}
	return s
}

// ---- sessions et fournisseurs publics ----

func (a *API) me(w http.ResponseWriter, r *http.Request, user string) {
	out := map[string]any{"user": user, "role": "", "source": "token", "name": user}
	if c, err := r.Cookie(cookieName); err == nil && !hasBearer(r) {
		if p, ok := a.sess.get(c.Value); ok {
			out["name"], out["role"], out["source"] = p.Name, p.Role, p.Source
		}
	}
	writeJSON(w, out)
}

// authProviders indique à la page de connexion les moyens disponibles.
func (a *API) authProviders(w http.ResponseWriter, _ *http.Request) {
	id := a.Store.Get().Identity
	label := id.OIDC.Label
	if label == "" {
		label = "Keycloak"
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{"ldap": id.LDAP.Enabled, "oidc": id.OIDC.Enabled, "oidc_label": label})
}

// ---- LDAP ----

func ldapDirectory(c state.LDAPConfig) (*ldap.Directory, error) {
	pool, err := upstream.CertPool(c.CABundle)
	if err != nil {
		return nil, err
	}
	return &ldap.Directory{URLs: c.URLs, Opts: ldap.Options{StartTLS: c.StartTLS, RootCAs: pool, Timeout: 8 * time.Second},
		BindDN: c.BindDN, BindPassword: c.BindPassword, UserBase: c.UserBase, UserFilter: c.UserFilter,
		UserAttr: c.UserAttr, DisplayAttr: c.DisplayAttr, GroupAttr: c.GroupAttr,
		GroupBase: c.GroupBase, GroupFilter: c.GroupFilter}, nil
}

func (a *API) loginLDAP(w http.ResponseWriter, r *http.Request, ip netip.Addr, username, password string) {
	cfg := a.Store.Get().Identity.LDAP
	dir, err := ldapDirectory(cfg)
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "annuaire mal configuré : utilisez le compte local")
		return
	}
	// Borne le nombre de liaisons simultanées : Rempart ne doit pas servir à
	// saturer l'annuaire ni à verrouiller des comptes en masse.
	select {
	case a.idp.ldapSem <- struct{}{}:
		defer func() { <-a.idp.ldapSem }()
	default:
		jsonError(w, http.StatusServiceUnavailable, "trop de connexions simultanées, réessayez")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	u, err := dir.Authenticate(ctx, username, password)
	if errors.Is(err, ldap.ErrInvalidCredentials) {
		a.guard.failed(ip)
		a.record("ldap:"+cleanName(username), "connexion.échec", "depuis "+ip.String()+" (LDAP)")
		jsonError(w, http.StatusUnauthorized, "identifiants incorrects")
		return
	}
	if err != nil {
		a.record("système", "connexion.annuaire-injoignable", err.Error())
		jsonError(w, http.StatusServiceUnavailable, "annuaire injoignable : réessayez, ou utilisez le compte local en secours")
		return
	}
	user := "ldap:" + cleanName(u.Username)
	role := resolveRole(cfg.Roles, ldapGroupMatcher(u.Groups))
	if role == "" {
		// Même réponse qu'un mauvais mot de passe : rien n'indique à un
		// attaquant que le mot de passe était bon.
		a.guard.failed(ip)
		a.record(user, "connexion.refusée", "depuis "+ip.String()+" : aucun groupe associé à un rôle de Rempart")
		jsonError(w, http.StatusUnauthorized, "identifiants incorrects ou accès non autorisé")
		return
	}
	name := cleanName(u.Display)
	if name == "" {
		name = cleanName(u.Username)
	}
	a.guard.success(ip)
	a.startSession(w, Principal{User: user, Name: name, Role: role, Source: "ldap"})
	a.record(user, "connexion", fmt.Sprintf("depuis %s (LDAP, rôle %s)", ip, roleLabel(role)))
	writeJSON(w, map[string]any{"user": user, "role": role, "otp_enabled": false})
}

// ---- OIDC ----

func oidcConfig(c state.OIDCConfig) (oidc.Config, error) {
	pool, err := upstream.CertPool(c.CABundle)
	if err != nil {
		return oidc.Config{}, err
	}
	return oidc.Config{Issuer: c.Issuer, ClientID: c.ClientID, ClientSecret: c.ClientSecret,
		RedirectURL: c.RedirectURL, Scopes: c.Scopes, RootCAs: pool}, nil
}

// oidcProvider renvoie le fournisseur découvert (gardé une heure).
func (a *API) oidcProvider(ctx context.Context) (*oidc.Provider, state.OIDCConfig, error) {
	c := a.Store.Get().Identity.OIDC
	if !c.Enabled {
		return nil, c, errors.New("connexion OIDC désactivée")
	}
	raw, _ := json.Marshal(c)
	sum := sha256.Sum256(raw)
	key := hex.EncodeToString(sum[:])
	a.idp.mu.Lock()
	if a.idp.prov != nil && a.idp.provKey == key && time.Since(a.idp.provAt) < time.Hour {
		p := a.idp.prov
		a.idp.mu.Unlock()
		return p, c, nil
	}
	a.idp.mu.Unlock()
	oc, err := oidcConfig(c)
	if err != nil {
		return nil, c, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p, err := oidc.Discover(ctx, oc)
	if err != nil {
		return nil, c, err
	}
	a.idp.mu.Lock()
	a.idp.prov, a.idp.provKey, a.idp.provAt = p, key, time.Now()
	a.idp.mu.Unlock()
	return p, c, nil
}

// loginRedirect renvoie vers la page de connexion avec un code d'erreur
// (jamais un texte libre : l'URL pourrait être forgée par un tiers).
func loginRedirect(w http.ResponseWriter, r *http.Request, code string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/?erreur="+url.QueryEscape(code), http.StatusSeeOther)
}

func (a *API) oidcLogin(w http.ResponseWriter, r *http.Request) {
	ip := a.clientIP(r)
	if a.guard.blocked(ip) > 0 {
		loginRedirect(w, r, "bloque")
		return
	}
	p, c, err := a.oidcProvider(r.Context())
	if err != nil {
		if c.Enabled {
			a.record("système", "oidc.indisponible", err.Error())
		}
		loginRedirect(w, r, "oidc-indisponible")
		return
	}
	st, nonce, verifier, binding := oidc.RandomToken(), oidc.RandomToken(), oidc.RandomToken(), oidc.RandomToken()
	now := time.Now()
	a.idp.mu.Lock()
	if a.idp.pending == nil {
		a.idp.pending = map[string]*oidcPending{}
	}
	for k, v := range a.idp.pending {
		if now.After(v.expires) {
			delete(a.idp.pending, k)
		}
	}
	full := len(a.idp.pending) >= oidcPendMax
	if !full {
		a.idp.pending[hashToken(st)] = &oidcPending{binding: hashToken(binding), nonce: nonce, verifier: verifier, expires: now.Add(oidcPendTTL)}
	}
	a.idp.mu.Unlock()
	if full {
		loginRedirect(w, r, "occupe")
		return
	}
	// SameSite=Lax : le retour depuis Keycloak est une navigation venant d'un
	// autre site, un cookie Strict n'y serait pas joint.
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: binding, Path: "/api/oidc/", HttpOnly: true,
		Secure: a.SecureCk, SameSite: http.SameSiteLaxMode, MaxAge: int(oidcPendTTL.Seconds())})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, p.AuthURL(st, nonce, verifier, c.RequiredACR), http.StatusFound)
}

func (a *API) oidcCallback(w http.ResponseWriter, r *http.Request) {
	ip := a.clientIP(r)
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: "/api/oidc/", MaxAge: -1, HttpOnly: true, Secure: a.SecureCk, SameSite: http.SameSiteLaxMode})
	if a.guard.blocked(ip) > 0 {
		loginRedirect(w, r, "bloque")
		return
	}
	q := r.URL.Query()
	a.idp.mu.Lock()
	pend := a.idp.pending[hashToken(q.Get("state"))]
	delete(a.idp.pending, hashToken(q.Get("state"))) // usage unique
	a.idp.mu.Unlock()
	ck, err := r.Cookie(oidcCookie)
	if pend == nil || time.Now().After(pend.expires) || err != nil ||
		subtle.ConstantTimeCompare([]byte(hashToken(ck.Value)), []byte(pend.binding)) != 1 {
		a.guard.failed(ip)
		a.record("oidc", "connexion.échec", "depuis "+ip.String()+" : retour OIDC sans connexion en cours (expirée, rejouée ou autre navigateur)")
		loginRedirect(w, r, "oidc-session")
		return
	}
	if e := q.Get("error"); e != "" {
		a.record("oidc", "connexion.annulée", "depuis "+ip.String()+" : "+cleanName(e))
		loginRedirect(w, r, "oidc-refus")
		return
	}
	fail := func(code, why string) {
		a.guard.failed(ip)
		a.record("oidc", "connexion.échec", "depuis "+ip.String()+" : "+why)
		loginRedirect(w, r, code)
	}
	p, c, err := a.oidcProvider(r.Context())
	if err != nil {
		fail("oidc-indisponible", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	tok, err := p.Exchange(ctx, q.Get("code"), pend.verifier)
	if err != nil {
		fail("oidc-echec", err.Error())
		return
	}
	claims, err := p.VerifyIDToken(ctx, tok.IDToken, pend.nonce)
	if err != nil {
		fail("oidc-echec", "jeton d'identité refusé : "+err.Error())
		return
	}
	username := cleanName(oidc.ClaimString(claims, c.UsernameClaim))
	if username == "" {
		username = cleanName(oidc.ClaimString(claims, "sub"))
	}
	user := "oidc:" + username
	if c.RequiredACR != "" && !slices.Contains(strings.Fields(c.RequiredACR), oidc.ClaimString(claims, "acr")) {
		a.guard.failed(ip)
		a.record(user, "connexion.refusée", "depuis "+ip.String()+" : niveau d'authentification (acr) insuffisant")
		loginRedirect(w, r, "oidc-acr")
		return
	}
	roles := oidc.ClaimStrings(claims, c.RolesClaim)
	if len(roles) == 0 && tok.AccessToken != "" {
		// Keycloak place par défaut les rôles dans le jeton d'accès seulement.
		if at, err := p.VerifyAccessToken(ctx, tok.AccessToken); err == nil {
			roles = oidc.ClaimStrings(at, c.RolesClaim)
		}
	}
	role := resolveRole(c.Roles, func(g string) bool { return slices.Contains(roles, g) })
	if role == "" {
		got := strings.Join(roles, ", ")
		if len(got) > 300 {
			got = got[:300] + "…"
		}
		a.guard.failed(ip)
		a.record(user, "connexion.refusée", fmt.Sprintf("depuis %s : aucun rôle Rempart (revendication %q : %s)", ip, c.RolesClaim, cleanName(got)))
		loginRedirect(w, r, "oidc-role")
		return
	}
	name := cleanName(oidc.ClaimString(claims, "name"))
	if name == "" {
		name = username
	}
	a.guard.success(ip)
	a.startSession(w, Principal{User: user, Name: name, Role: role, Source: "oidc", idToken: tok.IDToken})
	a.record(user, "connexion", fmt.Sprintf("depuis %s (OIDC, rôle %s)", ip, roleLabel(role)))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/#/dashboard", http.StatusSeeOther)
}

func (a *API) oidcLogoutURL(ctx context.Context, idToken string) string {
	p, c, err := a.oidcProvider(ctx)
	if err != nil {
		return ""
	}
	post := ""
	if u, err := url.Parse(c.RedirectURL); err == nil {
		post = u.Scheme + "://" + u.Host + "/"
	}
	return p.LogoutURL(idToken, post)
}

// ---- configuration ----

type identityIn struct {
	LDAP            state.LDAPConfig `json:"ldap"`
	OIDC            state.OIDCConfig `json:"oidc"`
	ClearOIDCSecret bool             `json:"clear_oidc_secret"`
	Password        string           `json:"password"`
	Code            string           `json:"code"`
}

func (a *API) getIdentity(w http.ResponseWriter, _ *http.Request, _ string) {
	st := a.Store.Get()
	id := st.Identity
	out := map[string]any{
		"ldap_bind_password_set": id.LDAP.BindPassword != "",
		"oidc_client_secret_set": id.OIDC.ClientSecret != "",
		"local_user":             st.Admin.Username,
		"local_otp":              st.Admin.TOTPSecret != "",
	}
	id.LDAP.BindPassword, id.OIDC.ClientSecret = "", ""
	out["ldap"], out["oidc"] = id.LDAP, id.OIDC
	writeJSON(w, out)
}

func cleanList(l []string) []string {
	out := []string{}
	for _, s := range l {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func cleanRoles(rg *state.RoleGroups) int {
	rg.Admin, rg.Operator, rg.Read = cleanList(rg.Admin), cleanList(rg.Operator), cleanList(rg.Read)
	return len(rg.Admin) + len(rg.Operator) + len(rg.Read)
}

var claimRe = regexp.MustCompile(`^[A-Za-z0-9_:/-]+(\.[A-Za-z0-9_:/-]+)*$`)
var scopeRe = regexp.MustCompile(`^[\x21\x23-\x5b\x5d-\x7e]{1,64}$`)

// mergeLDAPSecret garde le mot de passe du compte de service enregistré tant
// que l'annuaire et le compte ne changent pas.
func mergeLDAPSecret(old state.LDAPConfig, in *state.LDAPConfig) error {
	in.BindDN = strings.TrimSpace(in.BindDN)
	if in.BindDN == "" {
		in.BindPassword = ""
		return nil
	}
	if in.BindPassword != "" {
		return nil
	}
	if old.BindPassword == "" {
		return nil
	}
	if strings.Join(strings.Fields(old.URLs), " ") != strings.Join(strings.Fields(in.URLs), " ") || old.BindDN != in.BindDN {
		return errors.New("l'annuaire ou le compte de service a changé : ressaisissez le mot de passe du compte de service")
	}
	in.BindPassword = old.BindPassword
	return nil
}

func mergeOIDCSecret(old state.OIDCConfig, in *state.OIDCConfig, clear bool) error {
	if clear || in.ClientSecret != "" || old.ClientSecret == "" {
		if clear {
			in.ClientSecret = ""
		}
		return nil
	}
	if old.Issuer != in.Issuer || old.ClientID != in.ClientID {
		return errors.New("le fournisseur ou le client a changé : ressaisissez le secret du client (ou choisissez « client public »)")
	}
	in.ClientSecret = old.ClientSecret
	return nil
}

func validateLDAP(c *state.LDAPConfig) error {
	c.URLs = strings.Join(strings.Fields(c.URLs), " ")
	for _, p := range []*string{&c.UserBase, &c.UserFilter, &c.UserAttr, &c.DisplayAttr, &c.GroupAttr, &c.GroupBase, &c.GroupFilter} {
		*p = strings.TrimSpace(*p)
	}
	n := cleanRoles(&c.Roles)
	if !c.Enabled {
		return nil
	}
	urls := strings.Fields(c.URLs)
	if len(urls) == 0 || len(urls) > 5 {
		return errors.New("LDAP : indiquez de une à cinq URL d'annuaire")
	}
	for _, u := range urls {
		if _, _, _, err := ldap.ParseURL(u, c.StartTLS); err != nil {
			return errors.New("LDAP : " + err.Error())
		}
	}
	if c.UserBase == "" {
		return errors.New("LDAP : base de recherche des utilisateurs requise")
	}
	if !strings.Contains(c.UserFilter, "{user}") {
		return errors.New("LDAP : le filtre des utilisateurs doit contenir {user}")
	}
	f, err := ldap.Expand(c.UserFilter, map[string]string{"user": "x"})
	if err == nil {
		_, err = ldap.CompileFilter(f)
	}
	if err != nil {
		return errors.New("LDAP : filtre des utilisateurs : " + err.Error())
	}
	if c.GroupFilter != "" {
		f, err := ldap.Expand(c.GroupFilter, map[string]string{"user": "x", "dn": "cn=x"})
		if err == nil {
			_, err = ldap.CompileFilter(f)
		}
		if err != nil {
			return errors.New("LDAP : filtre des groupes : " + err.Error())
		}
	}
	if c.GroupAttr == "" && c.GroupFilter == "" {
		return errors.New("LDAP : indiquez un attribut de groupes (memberOf) ou un filtre de groupes")
	}
	if c.BindDN != "" && c.BindPassword == "" {
		return errors.New("LDAP : mot de passe du compte de service requis")
	}
	if _, err := upstream.CertPool(c.CABundle); err != nil {
		return errors.New("LDAP : " + err.Error())
	}
	if n == 0 {
		return errors.New("LDAP : associez au moins un groupe à un rôle, sinon personne ne pourra se connecter")
	}
	return nil
}

func validateOIDC(c *state.OIDCConfig) error {
	c.Issuer = strings.TrimSpace(c.Issuer)
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.RedirectURL = strings.TrimSpace(c.RedirectURL)
	c.Label = cleanName(c.Label)
	c.RequiredACR = strings.TrimSpace(c.RequiredACR)
	c.Scopes = cleanList(c.Scopes)
	n := cleanRoles(&c.Roles)
	if c.Label == "" {
		c.Label = "Keycloak"
	}
	if c.UsernameClaim = strings.TrimSpace(c.UsernameClaim); c.UsernameClaim == "" {
		c.UsernameClaim = "preferred_username"
	}
	if c.RolesClaim = strings.TrimSpace(c.RolesClaim); c.RolesClaim == "" {
		c.RolesClaim = "realm_access.roles"
	}
	if !c.Enabled {
		return nil
	}
	if len([]rune(c.Label)) > 40 {
		return errors.New("OIDC : libellé du bouton trop long (40 caractères au plus)")
	}
	if err := oidc.ValidateConfig(oidc.Config{Issuer: c.Issuer, ClientID: c.ClientID, RedirectURL: c.RedirectURL}); err != nil {
		return errors.New("OIDC : " + err.Error())
	}
	if u, _ := url.Parse(c.RedirectURL); u.Path != "/api/oidc/callback" {
		return errors.New("OIDC : l'URL de retour doit se terminer par /api/oidc/callback")
	}
	if !claimRe.MatchString(c.UsernameClaim) || !claimRe.MatchString(c.RolesClaim) {
		return errors.New("OIDC : nom de revendication invalide")
	}
	for _, s := range c.Scopes {
		if !scopeRe.MatchString(s) {
			return errors.New("OIDC : portée invalide : " + s)
		}
	}
	for _, v := range strings.Fields(c.RequiredACR) {
		if !scopeRe.MatchString(v) {
			return errors.New("OIDC : valeur acr invalide")
		}
	}
	if _, err := upstream.CertPool(c.CABundle); err != nil {
		return errors.New("OIDC : " + err.Error())
	}
	if n == 0 {
		return errors.New("OIDC : associez au moins un rôle ou groupe Keycloak à un rôle de Rempart")
	}
	return nil
}

func describeIdentity(id state.Identity) string {
	var parts []string
	if id.LDAP.Enabled {
		parts = append(parts, fmt.Sprintf("LDAP activé (%s ; groupes : %d admin, %d opérateur, %d lecture)",
			id.LDAP.URLs, len(id.LDAP.Roles.Admin), len(id.LDAP.Roles.Operator), len(id.LDAP.Roles.Read)))
	} else {
		parts = append(parts, "LDAP désactivé")
	}
	if id.OIDC.Enabled {
		parts = append(parts, fmt.Sprintf("OIDC activé (%s, client %s ; rôles : %d admin, %d opérateur, %d lecture)",
			id.OIDC.Issuer, id.OIDC.ClientID, len(id.OIDC.Roles.Admin), len(id.OIDC.Roles.Operator), len(id.OIDC.Roles.Read)))
	} else {
		parts = append(parts, "OIDC désactivé")
	}
	return strings.Join(parts, " ; ")
}

func (a *API) putIdentity(w http.ResponseWriter, r *http.Request, user string) {
	ip := a.clientIP(r)
	if d := a.guard.blocked(ip); d > 0 {
		jsonError(w, http.StatusTooManyRequests, fmt.Sprintf("trop d'échecs, réessayez dans %s", d.Round(time.Second)))
		return
	}
	var in identityIn
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	cur := a.Store.Get()
	if !CheckPassword(in.Password, cur.Admin.PasswordHash) {
		a.guard.failed(ip)
		a.record(user, "comptes-externes.refus", "mot de passe incorrect")
		jsonError(w, http.StatusForbidden, "mot de passe incorrect")
		return
	}
	for _, err := range []error{
		mergeLDAPSecret(cur.Identity.LDAP, &in.LDAP),
		mergeOIDCSecret(cur.Identity.OIDC, &in.OIDC, in.ClearOIDCSecret),
		validateLDAP(&in.LDAP),
		validateOIDC(&in.OIDC),
	} {
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	second := ""
	err := a.Store.Update(func(s *state.State) error {
		if s.Admin.TOTPSecret != "" {
			m, err := consumeSecondFactor(s, in.Code)
			if err != nil {
				return errSecondFactor{err}
			}
			second = " (" + m + ")"
		}
		s.Identity = state.Identity{LDAP: in.LDAP, OIDC: in.OIDC}
		return nil
	})
	var sf errSecondFactor
	if errors.As(err, &sf) {
		a.guard.failed(ip)
		a.record(user, "comptes-externes.refus", "second facteur incorrect")
		jsonError(w, http.StatusForbidden, sf.Error())
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.guard.success(ip)
	a.idp.reset()
	a.sess.clearExternal()
	a.record(user, "comptes-externes.modifiés", describeIdentity(state.Identity{LDAP: in.LDAP, OIDC: in.OIDC})+second)
	writeJSON(w, map[string]bool{"ok": true})
}

type errSecondFactor struct{ error }

func (a *API) testLDAP(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		LDAP     state.LDAPConfig `json:"ldap"`
		Username string           `json:"username"`
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	in.LDAP.Enabled = true
	if err := mergeLDAPSecret(a.Store.Get().Identity.LDAP, &in.LDAP); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateLDAP(&in.LDAP); err != nil && !strings.Contains(err.Error(), "associez") {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	dir, err := ldapDirectory(in.LDAP)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	u, err := dir.Lookup(ctx, strings.TrimSpace(in.Username))
	if err != nil {
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.record(user, "comptes-externes.test-ldap", in.LDAP.URLs)
	out := map[string]any{"ok": true}
	if u != nil {
		groups := u.Groups
		if groups == nil {
			groups = []string{}
		}
		out["dn"], out["name"], out["groups"] = u.DN, u.Display, groups
		out["role"] = resolveRole(in.LDAP.Roles, ldapGroupMatcher(u.Groups))
	}
	writeJSON(w, out)
}

func (a *API) testOIDC(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		OIDC state.OIDCConfig `json:"oidc"`
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	in.OIDC.Enabled = true
	if err := validateOIDC(&in.OIDC); err != nil && !strings.Contains(err.Error(), "associez") {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	oc, err := oidcConfig(in.OIDC)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	p, err := oidc.Discover(ctx, oc)
	if err != nil {
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.record(user, "comptes-externes.test-oidc", in.OIDC.Issuer)
	algs := p.Meta.IDTokenAlgs
	if algs == nil {
		algs = []string{}
	}
	writeJSON(w, map[string]any{"ok": true, "issuer": p.Meta.Issuer, "authorization_endpoint": p.Meta.AuthorizationEndpoint,
		"token_endpoint": p.Meta.TokenEndpoint, "end_session_endpoint": p.Meta.EndSessionEndpoint, "algorithms": algs})
}
