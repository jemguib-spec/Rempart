// encrypted_test.go - tests des options de l'écoute DoH et de DoT : interface servie sur le port DoH, jeton DoT depuis Internet.
// L'interface n'est servie qu'aux clients des réseaux autorisés, et seulement si l'administrateur l'a choisi.
// Contexte : Rempart ; le gestionnaire d'interface est remplacé par un gestionnaire factice.
package server

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

func TestWebOnDoHGate(t *testing.T) {
	srv := &Server{Logger: testutil.Logger(), ACL: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}}
	e := NewEncrypted(srv, nil, "", "", "/dns-query", "")
	e.SetWebHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("interface")) }))
	get := func(remote string) int {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		e.webGate(w, r)
		return w.Code
	}
	if c := get("192.168.1.20:5000"); c != http.StatusNotFound {
		t.Fatalf("option désactivée : %d, 404 attendu", c)
	}
	if err := e.Apply(state.Encryption{WebOnDoH: true, DoTTokenAdmit: true}); err != nil {
		t.Fatal(err)
	}
	if c := get("192.168.1.20:5000"); c != http.StatusOK {
		t.Fatalf("réseau local : %d, 200 attendu", c)
	}
	if c := get("203.0.113.9:5000"); c != http.StatusNotFound {
		t.Fatalf("Internet : %d, 404 attendu", c)
	}
	if !srv.dotAdmit.Load() {
		t.Fatal("jeton DoT depuis Internet non transmis au serveur")
	}
	if st := e.Status(); !st.WebOnDoH || !st.DoTTokenAdmit {
		t.Fatalf("état non rendu : %+v", st)
	}
	_ = e.Apply(state.Encryption{})
	if c := get("192.168.1.20:5000"); c != http.StatusNotFound || srv.dotAdmit.Load() {
		t.Fatal("options non retirées à chaud")
	}
}
