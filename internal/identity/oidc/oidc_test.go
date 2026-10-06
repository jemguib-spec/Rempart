package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeOP struct {
	srv     *httptest.Server
	rsa     *rsa.PrivateKey
	ec      *ecdsa.PrivateKey
	kid     string
	mu      sync.Mutex
	codes   map[string]map[string]any // code -> claims (avec nonce)
	gotVer  string
	gotAuth string
}

func newOP(t *testing.T) *fakeOP {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	op := &fakeOP{rsa: rk, ec: ek, kid: "k1", codes: map[string]map[string]any{}}
	mux := http.NewServeMux()
	op.srv = httptest.NewTLSServer(mux)
	t.Cleanup(op.srv.Close)
	iss := op.srv.URL + "/realms/corp"
	mux.HandleFunc("/realms/corp/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "authorization_endpoint": iss + "/auth",
			"token_endpoint": iss + "/token", "jwks_uri": iss + "/certs", "end_session_endpoint": iss + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256", "PS256", "ES256"}, "code_challenge_methods_supported": []string{"plain", "S256"}})
	})
	mux.HandleFunc("/realms/corp/certs", func(w http.ResponseWriter, r *http.Request) {
		op.mu.Lock()
		defer op.mu.Unlock()
		e := big.NewInt(int64(op.rsa.E)).Bytes()
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{
			{"kty": "RSA", "kid": op.kid, "use": "sig", "n": b64.EncodeToString(op.rsa.N.Bytes()), "e": b64.EncodeToString(e)},
			{"kty": "RSA", "kid": "enc", "use": "enc", "n": b64.EncodeToString(op.rsa.N.Bytes()), "e": b64.EncodeToString(e)},
			{"kty": "EC", "kid": "ec1", "crv": "P-256", "x": b64.EncodeToString(op.ec.X.FillBytes(make([]byte, 32))), "y": b64.EncodeToString(op.ec.Y.FillBytes(make([]byte, 32)))},
		}})
	})
	mux.HandleFunc("/realms/corp/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		op.mu.Lock()
		cl, ok := op.codes[r.Form.Get("code")]
		delete(op.codes, r.Form.Get("code"))
		op.gotVer = r.Form.Get("code_verifier")
		op.gotAuth = r.Header.Get("Authorization")
		op.mu.Unlock()
		if !ok || Challenge(r.Form.Get("code_verifier")) != cl["_challenge"] {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		delete(cl, "_challenge")
		json.NewEncoder(w).Encode(map[string]string{"id_token": op.sign("RS256", cl), "access_token": op.sign("RS256", map[string]any{
			"iss": iss, "azp": "rempart", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(),
			"realm_access": map[string]any{"roles": []string{"rempart-admin", "offline_access"}}}), "token_type": "Bearer"})
	})
	return op
}

func (op *fakeOP) iss() string { return op.srv.URL + "/realms/corp" }

func (op *fakeOP) sign(alg string, claims map[string]any) string {
	op.mu.Lock()
	kid := op.kid
	op.mu.Unlock()
	if alg == "ES256" {
		kid = "ec1"
	}
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	p, _ := json.Marshal(claims)
	in := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	d := sha256.Sum256([]byte(in))
	var sig []byte
	switch alg {
	case "RS256":
		sig, _ = rsa.SignPKCS1v15(rand.Reader, op.rsa, crypto.SHA256, d[:])
	case "PS256":
		sig, _ = rsa.SignPSS(rand.Reader, op.rsa, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "ES256":
		r, s, _ := ecdsa.Sign(rand.Reader, op.ec, d[:])
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case "HS256": // attaque par confusion : la clé publique RSA comme secret HMAC
		m := hmac.New(sha256.New, op.rsa.N.Bytes())
		m.Write([]byte(in))
		sig = m.Sum(nil)
	}
	return in + "." + b64.EncodeToString(sig)
}

func (op *fakeOP) claims(nonce string) map[string]any {
	return map[string]any{"iss": op.iss(), "aud": "rempart", "azp": "rempart", "sub": "u-123", "nonce": nonce,
		"preferred_username": "alice", "exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix()}
}

func (op *fakeOP) provider(t *testing.T, secret string) *Provider {
	pool := op.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	p, err := Discover(context.Background(), Config{Issuer: op.iss(), ClientID: "rempart", ClientSecret: secret,
		RedirectURL: "https://rempart.lan:8080/api/oidc/callback", Scopes: []string{"profile"}, RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCodeFlow(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, "s3cret/+")
	state, nonce, ver := RandomToken(), RandomToken(), RandomToken()
	u, _ := url.Parse(p.AuthURL(state, nonce, ver, "2"))
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("state") != state || q.Get("scope") != "openid profile" || q.Get("acr_values") != "2" {
		t.Fatal(u)
	}
	cl := op.claims(nonce)
	cl["_challenge"] = q.Get("code_challenge")
	op.codes["c1"] = cl
	tok, err := p.Exchange(context.Background(), "c1", ver)
	if err != nil {
		t.Fatal(err)
	}
	if op.gotVer != ver || !strings.HasPrefix(op.gotAuth, "Basic ") {
		t.Fatal("PKCE ou authentification client absents")
	}
	c, err := p.VerifyIDToken(context.Background(), tok.IDToken, nonce)
	if err != nil || ClaimString(c, "preferred_username") != "alice" {
		t.Fatal(c, err)
	}
	if _, err := p.VerifyIDToken(context.Background(), tok.IDToken, "autre"); err == nil {
		t.Fatal("nonce non vérifié")
	}
	at, err := p.VerifyAccessToken(context.Background(), tok.AccessToken)
	if err != nil || len(ClaimStrings(at, "realm_access.roles")) != 2 {
		t.Fatal(at, err)
	}
	// Code rejoué ou mauvais vérificateur : refus.
	if _, err := p.Exchange(context.Background(), "c1", ver); err == nil {
		t.Fatal("code rejoué accepté")
	}
	if !strings.Contains(p.LogoutURL(tok.IDToken, "https://rempart.lan:8080/"), "id_token_hint=") {
		t.Fatal("déconnexion")
	}
}

func TestIDTokenChecks(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, "")
	ctx := context.Background()
	ok := func(alg string, mut func(map[string]any)) error {
		c := op.claims("n")
		if mut != nil {
			mut(c)
		}
		_, err := p.VerifyIDToken(ctx, op.sign(alg, c), "n")
		return err
	}
	for _, alg := range []string{"RS256", "PS256", "ES256"} {
		if err := ok(alg, nil); err != nil {
			t.Fatalf("%s : %v", alg, err)
		}
	}
	bad := map[string]func(map[string]any){
		"audience":   func(c map[string]any) { c["aud"] = "autre" },
		"azp":        func(c map[string]any) { c["aud"] = []string{"rempart", "x"}; c["azp"] = "x" },
		"émetteur":   func(c map[string]any) { c["iss"] = "https://evil" },
		"expiré":     func(c map[string]any) { c["exp"] = time.Now().Add(-5 * time.Minute).Unix() },
		"futur":      func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() },
		"sans sujet": func(c map[string]any) { delete(c, "sub") },
		"sans exp":   func(c map[string]any) { delete(c, "exp") },
	}
	for name, m := range bad {
		if ok("RS256", m) == nil {
			t.Errorf("%s accepté", name)
		}
	}
	if ok("HS256", nil) == nil {
		t.Fatal("confusion d'algorithme HS256 acceptée")
	}
	// alg none et signature altérée.
	good := op.sign("RS256", op.claims("n"))
	parts := strings.Split(good, ".")
	none := b64.EncodeToString([]byte(`{"alg":"none"}`)) + "." + parts[1] + "."
	if _, err := p.VerifyIDToken(ctx, none, "n"); err == nil {
		t.Fatal("alg none accepté")
	}
	c := op.claims("n")
	c["preferred_username"] = "admin"
	forged, _ := json.Marshal(c)
	if _, err := p.VerifyIDToken(ctx, parts[0]+"."+b64.EncodeToString(forged)+"."+parts[2], "n"); err == nil {
		t.Fatal("contenu altéré accepté")
	}
	jku := b64.EncodeToString([]byte(`{"alg":"RS256","kid":"k1","jku":"https://evil/keys"}`)) + "." + parts[1] + "." + parts[2]
	if _, err := p.VerifyIDToken(ctx, jku, "n"); err == nil {
		t.Fatal("jku accepté")
	}
}

func TestKeyRotation(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, "")
	op.mu.Lock()
	op.kid = "k2"
	op.mu.Unlock()
	if _, err := p.VerifyIDToken(context.Background(), op.sign("RS256", op.claims("n")), "n"); err != nil {
		t.Fatalf("rotation de clé : %v", err)
	}
}

func TestDiscoveryChecks(t *testing.T) {
	op := newOP(t)
	pool := op.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	base := Config{Issuer: op.iss(), ClientID: "rempart", RedirectURL: "https://r/api/oidc/callback", RootCAs: pool}
	c := base
	c.Issuer = op.srv.URL + "/realms/corp/../corp"
	if _, err := Discover(context.Background(), c); err == nil {
		t.Fatal("émetteur différent accepté")
	}
	c = base
	c.RootCAs = nil // AC de test inconnue du système
	if _, err := Discover(context.Background(), c); err == nil {
		t.Fatal("certificat non vérifié")
	}
	for _, iss := range []string{"http://kc/realms/x", "https://kc/realms/x/", ""} {
		c = base
		c.Issuer = iss
		if ValidateConfig(c) == nil {
			t.Fatalf("%q accepté", iss)
		}
	}
}
