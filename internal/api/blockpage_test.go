// blockpage_test.go - tests de la page de blocage et du traitement des demandes de déblocage.
// La page ne montre que le nom ; une demande ne vient que de la page elle-même ; l'acceptation ajoute une exception.
// Contexte : Rempart ; API sans serveur DNS (pas de groupe détecté), état scellé de test.
package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rempart-dns/rempart/internal/audit"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

func newPageAPI(t *testing.T, bp state.BlockPage) *API {
	ks := testutil.Keystore(t)
	dir := t.TempDir()
	store, _, err := state.Open(ks, filepath.Join(dir, "s"), state.State{BlockPage: bp,
		Groups: []state.Group{{ID: "g1", Name: "Enfants"}}})
	if err != nil {
		t.Fatal(err)
	}
	al, _ := audit.Open(ks, dir)
	return &API{Store: store, Audit: al, KS: ks}
}

func pageReq(a *API, method, host, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/", strings.NewReader(body))
	r.Host, r.RemoteAddr = host, "192.168.1.20:5000"
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	a.blockPage(w, r)
	return w
}

func TestBlockPageView(t *testing.T) {
	a := newPageAPI(t, state.BlockPage{IPv4: "192.168.1.2"})
	w := pageReq(a, "GET", "Tracker.Example:443", "", nil)
	b := w.Body.String()
	if w.Code != http.StatusForbidden || !strings.Contains(b, "<code>tracker.example</code>") {
		t.Fatalf("page attendue : %d %s", w.Code, b)
	}
	if strings.Contains(b, "<form") || strings.Contains(b, "<script") || strings.Contains(b, "/api") {
		t.Fatal("formulaire, script ou lien vers l'API sur une page sans demandes")
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "unsafe-inline") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("en-têtes de la page : %q", csp)
	}
	if w := pageReq(a, "GET", "tracker.example", "", map[string]string{"Sec-Fetch-Dest": "script"}); w.Code != 403 || w.Body.Len() != 0 {
		t.Fatal("une sous-ressource ne doit recevoir aucun contenu")
	}
	if w := pageReq(a, "POST", "tracker.example", "message=x", nil); w.Code != 403 || len(a.Store.Get().UnblockRequests) != 0 {
		t.Fatal("demande acceptée alors qu'elles sont désactivées")
	}
	if w := pageReq(a, "GET", "<script>", "", nil); w.Code != 404 {
		t.Fatalf("nom invalide : %d", w.Code)
	}
}

func TestUnblockRequests(t *testing.T) {
	a := newPageAPI(t, state.BlockPage{IPv4: "192.168.1.2", Requests: true})
	if b := pageReq(a, "GET", "tracker.example", "", nil).Body.String(); !strings.Contains(b, `<form method="post" action="/">`) {
		t.Fatal("formulaire absent")
	}
	// Envoyée par un autre site : refusée.
	w := pageReq(a, "POST", "tracker.example", "message=x", map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"})
	if w.Code != 403 || len(a.Store.Get().UnblockRequests) != 0 {
		t.Fatalf("demande d'un autre site acceptée : %d", w.Code)
	}
	msg := url.Values{"message": {"Pour un devoir <b>\x00\r\nmerci"}}.Encode()
	w = pageReq(a, "POST", "tracker.example", msg, map[string]string{"Origin": "https://tracker.example", "Sec-Fetch-Site": "same-origin"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Demande envoyée") {
		t.Fatalf("demande : %d %s", w.Code, w.Body.String())
	}
	reqs := a.Store.Get().UnblockRequests
	if len(reqs) != 1 || reqs[0].Domain != "tracker.example" || reqs[0].Message != "Pour un devoir <b>\nmerci" || reqs[0].Count != 1 {
		t.Fatalf("demande enregistrée : %+v", reqs)
	}
	if b := pageReq(a, "GET", "tracker.example", "", nil).Body.String(); !strings.Contains(b, "déjà en attente") {
		t.Fatal("demande en attente non signalée")
	}
	pageReq(a, "POST", "tracker.example", "", nil)
	if reqs = a.Store.Get().UnblockRequests; len(reqs) != 1 || reqs[0].Count != 2 || reqs[0].Message == "" {
		t.Fatalf("demande répétée : %+v", reqs)
	}
	// Limite par appareil.
	for i := 0; i < pageRateBurst; i++ {
		w = pageReq(a, "POST", "other.example", "", nil)
	}
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("limite par appareil absente : %d", w.Code)
	}

	// Traitement par l'administrateur.
	srv := httptest.NewServer(a.Handler(time.Hour))
	defer srv.Close()
	ck := pageLogin(t, a, srv.URL)
	call := func(method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("X-Rempart", "1")
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(ck)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(raw)
	}
	id := a.Store.Get().UnblockRequests[0].ID
	if c, _ := call("POST", "/api/unblock-requests/"+id+"/approve", `{"scope":"group"}`); c != http.StatusConflict {
		t.Fatalf("appareil sans groupe : 409 attendu, %d", c)
	}
	if c, _ := call("POST", "/api/unblock-requests/"+id+"/approve", `{"scope":"global"}`); c != 200 {
		t.Fatalf("acceptation : %d", c)
	}
	st := a.Store.Get()
	if len(st.Rules) != 1 || st.Rules[0].Domain != "tracker.example" || !st.Rules[0].Allow {
		t.Fatalf("exception non ajoutée : %+v", st.Rules)
	}
	for _, u := range st.UnblockRequests {
		if u.Domain == "tracker.example" {
			t.Fatal("demande acceptée encore en attente")
		}
	}

	// Demande d'un appareil du groupe : exception propre au groupe.
	_ = a.Store.Update(func(s *state.State) error {
		s.UnblockRequests = append(s.UnblockRequests, state.UnblockRequest{ID: "r2", Domain: "jeu.example", Client: "c", GroupID: "g1", GroupName: "Enfants"})
		return nil
	})
	if c, _ := call("POST", "/api/unblock-requests/r2/approve", `{"scope":"group"}`); c != 200 {
		t.Fatalf("acceptation pour le groupe : %d", c)
	}
	if g := a.Store.Get().Groups[0]; len(g.Rules) != 1 || g.Rules[0].Domain != "jeu.example" || !g.Rules[0].Allow {
		t.Fatalf("exception du groupe : %+v", g.Rules)
	}
	other := a.Store.Get().UnblockRequests[0].ID
	if c, _ := call("DELETE", "/api/unblock-requests/"+other, ""); c != 200 {
		t.Fatalf("refus : %d", c)
	}
	if c, _ := call("DELETE", "/api/unblock-requests/"+other, ""); c != 404 {
		t.Fatalf("demande déjà refusée : %d", c)
	}
	if c, _ := call("PUT", "/api/blockpage", `{"ipv4":"127.0.0.1","requests":true}`); c != 400 {
		t.Fatalf("adresse de bouclage acceptée : %d", c)
	}
	if c, _ := call("PUT", "/api/blockpage", `{"ipv4":"192.168.1.3","ipv6":"fd00::3","requests":false}`); c != 200 || a.Store.Get().BlockPage.IPv4 != "192.168.1.3" {
		t.Fatalf("configuration : %d", c)
	}
	if rep := a.Audit.Verify(); !rep.OK {
		t.Fatalf("audit : %+v", rep)
	}
}

// pageLogin crée le compte administrateur et ouvre une session.
func pageLogin(t *testing.T, a *API, base string) *http.Cookie {
	t.Helper()
	_ = a.Store.Update(func(s *state.State) error {
		s.Admin = state.Admin{Username: "admin", PasswordHash: HashPassword("un-mot-de-passe-solide")}
		return nil
	})
	req, _ := http.NewRequest("POST", base+"/api/login", strings.NewReader(`{"username":"admin","password":"un-mot-de-passe-solide"}`))
	req.Header.Set("X-Rempart", "1")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	for _, c := range res.Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatalf("connexion impossible : %d", res.StatusCode)
	return nil
}
