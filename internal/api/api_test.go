package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/rempart-dns/rempart/internal/audit"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

func TestAuthAndCSRF(t *testing.T) {
	ks := testutil.Keystore(t)
	dir := t.TempDir()
	store, _, _ := state.Open(ks, filepath.Join(dir, "s"), state.State{Admin: state.Admin{Username: "admin", PasswordHash: HashPassword("un-mot-de-passe-solide")}})
	al, _ := audit.Open(ks, dir)
	a := &API{Store: store, Audit: al, KS: ks, Web: fstest.MapFS{"index.html": {Data: []byte("ok")}}}
	srv := httptest.NewServer(a.Handler(time.Hour))
	defer srv.Close()

	do := func(method, path, body string, hdr bool, cookie *http.Cookie) *http.Response {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if hdr {
			req.Header.Set("X-Rempart", "1")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if r := do("GET", "/api/settings", "", true, nil); r.StatusCode != 401 {
		t.Fatalf("sans session: %d", r.StatusCode)
	}
	if r := do("POST", "/api/login", `{"username":"admin","password":"un-mot-de-passe-solide"}`, false, nil); r.StatusCode != 403 {
		t.Fatalf("CSRF: requête sans en-tête acceptée (%d)", r.StatusCode)
	}
	if r := do("POST", "/api/login", `{"username":"admin","password":"faux"}`, true, nil); r.StatusCode != 401 {
		t.Fatalf("mauvais mot de passe: %d", r.StatusCode)
	}
	r := do("POST", "/api/login", `{"username":"admin","password":"un-mot-de-passe-solide"}`, true, nil)
	if r.StatusCode != 200 {
		t.Fatalf("login: %d", r.StatusCode)
	}
	var ck *http.Cookie
	for _, c := range r.Cookies() {
		if c.Name == cookieName {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie de session mal protégé: %+v", ck)
	}
	if r := do("GET", "/api/settings", "", false, ck); r.StatusCode != 200 {
		t.Fatalf("avec session: %d", r.StatusCode)
	}
	if r := do("GET", "/", "", false, nil); r.Header.Get("Content-Security-Policy") == "" || r.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatal("en-têtes de sécurité manquants")
	}
	// brute force lockout after 5 failures
	for i := 0; i < 5; i++ {
		do("POST", "/api/login", `{"username":"admin","password":"x"}`, true, nil)
	}
	if r := do("POST", "/api/login", `{"username":"admin","password":"un-mot-de-passe-solide"}`, true, nil); r.StatusCode != 429 {
		t.Fatalf("verrouillage anti brute-force absent: %d", r.StatusCode)
	}
	if rep := al.Verify(); !rep.OK || rep.Count < 7 {
		t.Fatalf("les connexions doivent être auditées: %+v", rep)
	}
}
