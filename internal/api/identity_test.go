package api

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/rempart-dns/rempart/internal/audit"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

const testPW = "un-mot-de-passe-solide"

type idEnv struct {
	t     *testing.T
	a     *API
	srv   *httptest.Server
	audit *audit.Log
}

func newIDEnv(t *testing.T) *idEnv {
	ks := testutil.Keystore(t)
	dir := t.TempDir()
	store, _, _ := state.Open(ks, filepath.Join(dir, "s"), state.State{Admin: state.Admin{Username: "admin", PasswordHash: HashPassword(testPW)}})
	al, _ := audit.Open(ks, dir)
	a := &API{Store: store, Audit: al, KS: ks, Web: fstest.MapFS{"index.html": {Data: []byte("ok")}}}
	srv := httptest.NewServer(a.Handler(time.Hour))
	t.Cleanup(srv.Close)
	return &idEnv{t: t, a: a, srv: srv, audit: al}
}

func (e *idEnv) client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (e *idEnv) do(c *http.Client, method, path string, body any) (*http.Response, map[string]any) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	u := path
	if !strings.HasPrefix(path, "http") {
		u = e.srv.URL + path
	}
	req, _ := http.NewRequest(method, u, rd)
	req.Header.Set("X-Rempart", "1")
	res, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res, out
}

// sessionClient ouvre une session avec un principal donné.
func (e *idEnv) sessionClient(p Principal) *http.Client {
	c := e.client()
	tok := e.a.sess.create(p)
	u, _ := url.Parse(e.srv.URL)
	c.Jar.SetCookies(u, []*http.Cookie{{Name: cookieName, Value: tok, Path: "/"}})
	return c
}

func TestRolesEnforced(t *testing.T) {
	e := newIDEnv(t)
	read := e.sessionClient(Principal{User: "ldap:lea", Role: RoleRead, Source: "ldap"})
	op := e.sessionClient(Principal{User: "ldap:olga", Role: RoleOperator, Source: "ldap"})
	adm := e.sessionClient(Principal{User: "oidc:alice", Role: RoleAdmin, Source: "oidc"})
	none := e.sessionClient(Principal{User: "oidc:x", Role: "", Source: "oidc"})
	set := map[string]any{"blocking_enabled": true, "blocking_mode": "zero", "log_mode": "stats", "retention_days": 7, "client_ids": "pseudonymize"}
	cases := []struct {
		c      *http.Client
		method string
		path   string
		body   any
		want   int
	}{
		{read, "GET", "/api/settings", nil, 200},
		{read, "PUT", "/api/settings", set, 403},
		{op, "PUT", "/api/settings", set, 200},
		{op, "GET", "/api/tokens", nil, 403},
		{op, "GET", "/api/identity", nil, 403},
		{adm, "GET", "/api/tokens", nil, 200},
		{adm, "GET", "/api/identity", nil, 200},
		{adm, "POST", "/api/password", map[string]string{"old": testPW, "new": "nouveau-mot-de-passe"}, 403},
		{adm, "GET", "/api/otp", nil, 403},
		{adm, "PUT", "/api/identity", map[string]any{"password": testPW}, 403},
		{none, "GET", "/api/settings", nil, 403},
	}
	for i, c := range cases {
		if r, out := e.do(c.c, c.method, c.path, c.body); r.StatusCode != c.want {
			t.Errorf("cas %d %s %s : %d (attendu %d) %v", i, c.method, c.path, r.StatusCode, c.want, out)
		}
	}
	_, me := e.do(op, "GET", "/api/me", nil)
	if me["role"] != RoleOperator || me["source"] != "ldap" {
		t.Fatal(me)
	}
}

func (e *idEnv) localAdmin() *http.Client {
	c := e.client()
	if r, _ := e.do(c, "POST", "/api/login", map[string]string{"username": "admin", "password": testPW}); r.StatusCode != 200 {
		e.t.Fatal("connexion locale", r.StatusCode)
	}
	return c
}

func TestLDAPUnreachableKeepsLocal(t *testing.T) {
	e := newIDEnv(t)
	adm := e.localAdmin()
	ldapCfg := map[string]any{"enabled": true, "urls": "ldaps://127.0.0.1:1", "user_base": "dc=corp",
		"user_filter": "(uid={user})", "group_attr": "memberOf", "bind_dn": "cn=svc,dc=corp", "bind_password": "pw-service",
		"roles": map[string]any{"admin": []string{"cn=admins,dc=corp"}}}
	body := map[string]any{"ldap": ldapCfg, "oidc": map[string]any{}, "password": "faux"}
	if r, _ := e.do(adm, "PUT", "/api/identity", body); r.StatusCode != 403 {
		t.Fatal("mot de passe local non exigé", r.StatusCode)
	}
	body["password"] = testPW
	bad := map[string]any{}
	for k, v := range ldapCfg {
		bad[k] = v
	}
	bad["user_filter"] = "(uid=x)"
	if r, out := e.do(adm, "PUT", "/api/identity", map[string]any{"ldap": bad, "oidc": map[string]any{}, "password": testPW}); r.StatusCode != 400 {
		t.Fatal("filtre sans {user} accepté", out)
	}
	if r, out := e.do(adm, "PUT", "/api/identity", body); r.StatusCode != 200 {
		t.Fatal(out)
	}
	_, got := e.do(adm, "GET", "/api/identity", nil)
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "pw-service") || got["ldap_bind_password_set"] != true {
		t.Fatal("secret renvoyé par l'API", string(raw))
	}
	// Même annuaire sans ressaisie : le secret est conservé ; autre annuaire : refus.
	ldapCfg["bind_password"] = ""
	if r, out := e.do(adm, "PUT", "/api/identity", body); r.StatusCode != 200 {
		t.Fatal(out)
	}
	if e.a.Store.Get().Identity.LDAP.BindPassword != "pw-service" {
		t.Fatal("secret perdu")
	}
	ldapCfg["urls"] = "ldaps://evil.example:636"
	if r, _ := e.do(adm, "PUT", "/api/identity", body); r.StatusCode != 400 {
		t.Fatal("secret envoyé à un nouvel annuaire sans ressaisie")
	}
	c := e.client()
	if r, _ := e.do(c, "POST", "/api/login", map[string]string{"username": "alice", "password": "x"}); r.StatusCode != 503 {
		t.Fatal("annuaire injoignable", r.StatusCode)
	}
	if r, _ := e.do(c, "POST", "/api/login", map[string]string{"username": "admin", "password": testPW}); r.StatusCode != 200 {
		t.Fatal("le compte local doit rester utilisable")
	}
	if r, _ := e.do(c, "GET", "/api/auth/providers", nil); r.StatusCode != 200 {
		t.Fatal("fournisseurs")
	}
}

// ---- faux Keycloak ----

type fakeKC struct {
	srv   *httptest.Server
	key   *rsa.PrivateKey
	mu    sync.Mutex
	codes map[string]map[string]any
	roles []string
}

func newKC(t *testing.T) *fakeKC {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	kc := &fakeKC{key: k, codes: map[string]map[string]any{}, roles: []string{"rempart-admin"}}
	mux := http.NewServeMux()
	kc.srv = httptest.NewTLSServer(mux)
	t.Cleanup(kc.srv.Close)
	iss := kc.iss()
	enc := base64.RawURLEncoding
	mux.HandleFunc("/realms/corp/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "authorization_endpoint": iss + "/protocol/openid-connect/auth",
			"token_endpoint": iss + "/protocol/openid-connect/token", "jwks_uri": iss + "/protocol/openid-connect/certs",
			"end_session_endpoint": iss + "/protocol/openid-connect/logout", "code_challenge_methods_supported": []string{"S256"}})
	})
	mux.HandleFunc("/realms/corp/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "RSA", "kid": "k", "alg": "RS256", "use": "sig",
			"n": enc.EncodeToString(k.N.Bytes()), "e": enc.EncodeToString(big.NewInt(int64(k.E)).Bytes())}}})
	})
	mux.HandleFunc("/realms/corp/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		id, sec, _ := r.BasicAuth()
		kc.mu.Lock()
		cl, ok := kc.codes[r.Form.Get("code")]
		delete(kc.codes, r.Form.Get("code"))
		roles := kc.roles
		kc.mu.Unlock()
		h := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || id != "rempart" || sec != "kc-secret" || enc.EncodeToString(h[:]) != cl["_ch"] {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		delete(cl, "_ch")
		at := map[string]any{"iss": iss, "azp": "rempart", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(),
			"realm_access": map[string]any{"roles": roles}}
		json.NewEncoder(w).Encode(map[string]string{"id_token": kc.sign(cl), "access_token": kc.sign(at), "token_type": "Bearer"})
	})
	return kc
}

func (kc *fakeKC) iss() string { return kc.srv.URL + "/realms/corp" }

func (kc *fakeKC) sign(c map[string]any) string {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k"})
	p, _ := json.Marshal(c)
	in := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	d := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, kc.key, crypto.SHA256, d[:])
	return in + "." + enc.EncodeToString(sig)
}

func (kc *fakeKC) caPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: kc.srv.Certificate().Raw}))
}

// login simule le passage par Keycloak : récupère state et nonce de la
// redirection, prépare un code et appelle le retour.
func (e *idEnv) oidcLogin(c *http.Client, kc *fakeKC, user string) *http.Response {
	r, _ := e.do(c, "GET", "/api/oidc/login", nil)
	if r.StatusCode != http.StatusFound {
		e.t.Fatalf("login OIDC : %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	loc, _ := url.Parse(r.Header.Get("Location"))
	q := loc.Query()
	if !strings.HasPrefix(loc.String(), kc.iss()) || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" {
		e.t.Fatal(loc)
	}
	code := oidcRandom()
	kc.mu.Lock()
	kc.codes[code] = map[string]any{"iss": kc.iss(), "aud": "rempart", "azp": "rempart", "sub": "uid-1", "nonce": q.Get("nonce"),
		"preferred_username": user, "name": "Alice Martin", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(),
		"_ch": q.Get("code_challenge")}
	kc.mu.Unlock()
	res, _ := e.do(c, "GET", "/api/oidc/callback?code="+code+"&state="+url.QueryEscape(q.Get("state")), nil)
	return res
}

func oidcRandom() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestOIDCFlow(t *testing.T) {
	e := newIDEnv(t)
	kc := newKC(t)
	adm := e.localAdmin()
	oc := map[string]any{"enabled": true, "issuer": kc.iss(), "client_id": "rempart", "client_secret": "kc-secret",
		"redirect_url": "https://rempart.test:8080/api/oidc/callback", "ca_bundle": kc.caPEM(),
		"roles": map[string]any{"admin": []string{"rempart-admin"}, "read": []string{"rempart-lecture"}}}
	if r, out := e.do(adm, "POST", "/api/identity/oidc/test", map[string]any{"oidc": oc}); r.StatusCode != 200 {
		t.Fatal(out)
	}
	if r, out := e.do(adm, "PUT", "/api/identity", map[string]any{"ldap": map[string]any{}, "oidc": oc, "password": testPW}); r.StatusCode != 200 {
		t.Fatal(out)
	}
	_, prov := e.do(e.client(), "GET", "/api/auth/providers", nil)
	if prov["oidc"] != true || prov["oidc_label"] != "Keycloak" {
		t.Fatal(prov)
	}

	// Connexion réussie : rôles lus dans le jeton d'accès (cas Keycloak par défaut).
	c := e.client()
	res := e.oidcLogin(c, kc, "alice")
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/#/dashboard" {
		t.Fatalf("retour : %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	_, me := e.do(c, "GET", "/api/me", nil)
	if me["user"] != "oidc:alice" || me["role"] != RoleAdmin || me["name"] != "Alice Martin" {
		t.Fatal(me)
	}
	if r, _ := e.do(c, "GET", "/api/tokens", nil); r.StatusCode != 200 {
		t.Fatal("admin OIDC")
	}
	_, lo := e.do(c, "POST", "/api/logout", nil)
	if s, _ := lo["redirect"].(string); !strings.Contains(s, "/protocol/openid-connect/logout?") || !strings.Contains(s, "id_token_hint=") {
		t.Fatal("déconnexion chez le fournisseur absente", lo)
	}

	// Rejeu du retour : refusé.
	c2 := e.client()
	r, _ := e.do(c2, "GET", "/api/oidc/login", nil)
	loc, _ := url.Parse(r.Header.Get("Location"))
	st := loc.Query().Get("state")
	if r, _ := e.do(e.client(), "GET", "/api/oidc/callback?code=x&state="+url.QueryEscape(st), nil); !strings.Contains(r.Header.Get("Location"), "erreur=oidc-session") {
		t.Fatal("retour sans cookie de liaison accepté", r.Header.Get("Location"))
	}
	if r, _ := e.do(c2, "GET", "/api/oidc/callback?code=x&state="+url.QueryEscape(st), nil); !strings.Contains(r.Header.Get("Location"), "erreur=oidc-session") {
		t.Fatal("state réutilisable après une tentative", r.Header.Get("Location"))
	}

	// Utilisateur sans rôle Rempart : refusé.
	kc.mu.Lock()
	kc.roles = []string{"offline_access"}
	kc.mu.Unlock()
	if r := e.oidcLogin(e.client(), kc, "bob"); !strings.Contains(r.Header.Get("Location"), "erreur=oidc-role") {
		t.Fatal("utilisateur sans rôle accepté", r.Header.Get("Location"))
	}
	// Rôle lecture.
	kc.mu.Lock()
	kc.roles = []string{"rempart-lecture"}
	kc.mu.Unlock()
	c3 := e.client()
	e.oidcLogin(c3, kc, "lea")
	if r, _ := e.do(c3, "POST", "/api/pause", map[string]any{"minutes": 5}); r.StatusCode != 403 {
		t.Fatal("rôle lecture peut modifier")
	}
	// Changer la configuration ferme les sessions externes.
	if r, out := e.do(adm, "PUT", "/api/identity", map[string]any{"ldap": map[string]any{}, "oidc": oc, "password": testPW}); r.StatusCode != 200 {
		t.Fatal(out)
	}
	if r, _ := e.do(c3, "GET", "/api/me", nil); r.StatusCode != 401 {
		t.Fatal("session externe conservée après changement de configuration")
	}
	if r, _ := e.do(adm, "GET", "/api/me", nil); r.StatusCode != 200 {
		t.Fatal("session locale fermée à tort")
	}
	// Nouvel émetteur sans ressaisie du secret : refus.
	oc2 := map[string]any{}
	for k, v := range oc {
		oc2[k] = v
	}
	oc2["client_secret"] = ""
	oc2["issuer"] = "https://autre.example/realms/x"
	if r, _ := e.do(adm, "PUT", "/api/identity", map[string]any{"ldap": map[string]any{}, "oidc": oc2, "password": testPW}); r.StatusCode != 400 {
		t.Fatal("secret client envoyé à un nouveau fournisseur")
	}
	if rep := e.audit.Verify(); !rep.OK {
		t.Fatal("audit")
	}
}

// TestLDAPIntegration s'exécute contre un vrai annuaire si
// REMPART_TEST_LDAP_URL est défini (voir scripts de test).
func TestLDAPIntegration(t *testing.T) {
	u := os.Getenv("REMPART_TEST_LDAP_URL")
	if u == "" {
		t.Skip("REMPART_TEST_LDAP_URL non défini")
	}
	ca, _ := os.ReadFile(os.Getenv("REMPART_TEST_LDAP_CA"))
	e := newIDEnv(t)
	adm := e.localAdmin()
	cfg := map[string]any{"enabled": true, "urls": u, "starttls": strings.HasPrefix(u, "ldap://"), "ca_bundle": string(ca),
		"bind_dn": "cn=svc,dc=rempart,dc=test", "bind_password": "service-secret",
		"user_base": "ou=people,dc=rempart,dc=test", "user_filter": "(&(objectClass=inetOrgPerson)(uid={user}))",
		"user_attr": "uid", "display_attr": "cn", "group_base": "ou=groups,dc=rempart,dc=test",
		"group_filter": "(&(objectClass=groupOfNames)(member={dn}))",
		"roles":        map[string]any{"admin": []string{"cn=rempart-admins,ou=groups,dc=rempart,dc=test"}, "read": []string{"cn=rempart-readers,ou=groups,dc=rempart,dc=test"}}}
	if r, out := e.do(adm, "POST", "/api/identity/ldap/test", map[string]any{"ldap": cfg, "username": "alice"}); r.StatusCode != 200 || out["role"] != RoleAdmin {
		t.Fatal(out)
	}
	if r, out := e.do(adm, "PUT", "/api/identity", map[string]any{"ldap": cfg, "oidc": map[string]any{}, "password": testPW}); r.StatusCode != 200 {
		t.Fatal(out)
	}
	c := e.client()
	if r, out := e.do(c, "POST", "/api/login", map[string]string{"username": "alice", "password": "alice-secret"}); r.StatusCode != 200 || out["role"] != RoleAdmin {
		t.Fatal(r.StatusCode, out)
	}
	if r, _ := e.do(e.client(), "POST", "/api/login", map[string]string{"username": "alice", "password": "faux"}); r.StatusCode != 401 {
		t.Fatal("mauvais mot de passe")
	}
	cb := e.client()
	if r, out := e.do(cb, "POST", "/api/login", map[string]string{"username": "bob", "password": "bob-secret"}); r.StatusCode != 200 || out["role"] != RoleRead {
		t.Fatal(out)
	}
	if r, _ := e.do(e.client(), "POST", "/api/login", map[string]string{"username": "carol", "password": "carol-secret"}); r.StatusCode != 401 {
		t.Fatal("utilisateur sans groupe accepté")
	}
	if r, _ := e.do(e.client(), "POST", "/api/login", map[string]string{"username": "*", "password": "alice-secret"}); r.StatusCode != 401 {
		t.Fatal("injection")
	}
	_ = context.Background
}
