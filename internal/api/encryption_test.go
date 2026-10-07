// encryption_test.go - tests de l'API Réglages → Chiffrement (interrupteur DoT / DoH).
// Vérifie les droits, l'enregistrement dans l'état scellé, l'audit et le refus d'une écoute non configurée.
// Contexte : Rempart ; les écoutes réelles (TLS, arrêt, port occupé) sont testées dans internal/upstream.
package api

import (
	"net"
	"testing"

	"github.com/rempart-dns/rempart/internal/server"
	"github.com/rempart-dns/rempart/internal/testutil"
)

func TestEncryptionToggle(t *testing.T) {
	e := newIDEnv(t)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	// DoH configuré, DoT absent du fichier de configuration.
	enc := server.NewEncrypted(&server.Server{Logger: testutil.Logger()}, nil, "", addr, "/dns-query", "")
	if err := enc.Apply(e.a.Store.Get().Encryption); err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	e.a.Encrypted = enc
	read := e.sessionClient(Principal{User: "ldap:lea", Role: RoleRead, Source: "ldap"})
	adm := e.localAdmin()

	if r, out := e.do(read, "GET", "/api/encryption", nil); r.StatusCode != 200 || out["doh"].(map[string]any)["running"] != true {
		t.Fatalf("lecture : %d %v", r.StatusCode, out)
	}
	if r, _ := e.do(read, "PUT", "/api/encryption", map[string]any{"doh_enabled": false}); r.StatusCode != 403 {
		t.Fatalf("lecture seule : %d", r.StatusCode)
	}
	if r, _ := e.do(adm, "PUT", "/api/encryption", map[string]any{"doh_enabled": true, "dot_enabled": true}); r.StatusCode != 409 {
		t.Fatalf("DoT sans dot.listen accepté : %d", r.StatusCode)
	}
	r, out := e.do(adm, "PUT", "/api/encryption", map[string]any{"doh_enabled": false})
	if r.StatusCode != 200 || out["doh"].(map[string]any)["running"] != false {
		t.Fatalf("désactivation : %d %v", r.StatusCode, out)
	}
	if !e.a.Store.Get().Encryption.DoHDisabled {
		t.Fatal("choix non enregistré dans l'état")
	}
	if e.a.dohURL("dns.example", "x") != "" {
		t.Fatal("profil d'appareil proposé avec DoH désactivé")
	}
	if _, ok := e.a.listeners()["doh "+addr]; ok {
		t.Fatal("DoH arrêté encore affiché comme écoute")
	}
	if r, out := e.do(adm, "PUT", "/api/encryption", map[string]any{"doh_enabled": true}); r.StatusCode != 200 || out["doh"].(map[string]any)["running"] != true {
		t.Fatalf("réactivation : %d %v", r.StatusCode, out)
	}
	// Options : enregistrées, et conservées quand une requête ne les cite pas.
	if r, out := e.do(adm, "PUT", "/api/encryption", map[string]any{"doh_enabled": true, "web_on_doh": true, "dot_token_admit": true}); r.StatusCode != 200 || out["web_on_doh"] != true || out["dot_token_admit"] != true {
		t.Fatalf("options : %d %v", r.StatusCode, out)
	}
	if r, _ := e.do(adm, "PUT", "/api/encryption", map[string]any{"doh_enabled": true}); r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	if st := e.a.Store.Get().Encryption; !st.WebOnDoH || !st.DoTTokenAdmit {
		t.Fatalf("options perdues : %+v", st)
	}
}
