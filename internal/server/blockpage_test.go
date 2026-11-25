// blockpage_test.go - tests du mode de blocage « page » et de l'aiguillage de l'écoute DoH.
// Un nom bloqué reçoit l'adresse de Rempart ; seul ce nom reçoit la page, et seulement depuis un réseau autorisé.
// Contexte : Rempart ; serveur de test de server_test.go, gestionnaires HTTP factices.
package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

func TestBlockPageMode(t *testing.T) {
	s := newTestServerWith(t, func(st *state.State) { st.Settings.BlockingMode = "page" })
	const c = "127.0.0.1"

	// Sans adresse configurée : comme « adresse nulle ».
	r := ask(s, "banner.ads.example.", dns.TypeA, c, false)
	if a, ok := r.Answer[0].(*dns.A); !ok || !a.A.Equal(net.IPv4zero) {
		t.Fatalf("sans adresse, 0.0.0.0 attendu : %v", r)
	}
	if s.BlockedRecently("banner.ads.example") {
		t.Fatal("nom retenu alors que la page n'est pas servie")
	}

	s.SetBlockPage(netip.MustParseAddr("192.168.1.2"), netip.Addr{})
	r = ask(s, "banner.ads.example.", dns.TypeA, c, false)
	if a, ok := r.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("192.168.1.2")) || a.Hdr.Ttl != blockedTTL {
		t.Fatalf("adresse de la page attendue : %v", r)
	}
	if !s.BlockedRecently("Banner.Ads.Example.") {
		t.Fatal("nom bloqué non retenu pour la page")
	}
	if s.BlockedRecently("normal.example") {
		t.Fatal("un nom non bloqué ne doit pas recevoir la page")
	}
	// AAAA sans IPv6 configurée, HTTPS : réponse vide.
	for _, qt := range []uint16{dns.TypeAAAA, dns.TypeHTTPS} {
		r = ask(s, "banner.ads.example.", qt, c, false)
		if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 || len(r.Ns) != 1 {
			t.Fatalf("%s : réponse vide attendue, %v", dns.TypeToString[qt], r)
		}
	}
	s.SetBlockPage(netip.MustParseAddr("192.168.1.2"), netip.MustParseAddr("fd00::2"))
	r = ask(s, "banner.ads.example.", dns.TypeAAAA, c, false)
	if a, ok := r.Answer[0].(*dns.AAAA); !ok || !a.AAAA.Equal(net.ParseIP("fd00::2")) {
		t.Fatalf("IPv6 de la page attendue : %v", r)
	}
	// Une exception reste résolue normalement.
	if r = ask(s, "ok.ads.example.", dns.TypeA, c, false); s.BlockedRecently("ok.ads.example") {
		t.Fatalf("exception traitée comme bloquée : %v", r)
	}

	s.ForgetBlocked("ads.example")
	if s.BlockedRecently("banner.ads.example") {
		t.Fatal("nom débloqué encore retenu")
	}
	// Adresses de mauvaise famille : ignorées.
	s.SetBlockPage(netip.MustParseAddr("fd00::2"), netip.MustParseAddr("192.168.1.2"))
	r = ask(s, "x.ads.example.", dns.TypeA, c, false)
	if a, ok := r.Answer[0].(*dns.A); !ok || !a.A.Equal(net.IPv4zero) {
		t.Fatalf("IPv4 invalide : 0.0.0.0 attendu, %v", r)
	}
}

func TestBlockPageRouting(t *testing.T) {
	srv := &Server{Logger: testutil.Logger(), ACL: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}}
	srv.SetBlockPage(netip.MustParseAddr("192.168.1.2"), netip.Addr{})
	e := NewEncrypted(srv, nil, "", "", "/dns-query", "")
	e.SetWebHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("interface")) }))
	e.SetBlockPageHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("page")) }))
	_ = e.Apply(state.Encryption{WebOnDoH: true})

	m := new(dns.Msg)
	m.SetQuestion("tracker.example.", dns.TypeA)
	if _, ok := srv.pageAnswer(m); !ok {
		t.Fatal("réponse de page attendue")
	}
	get := func(host, path, remote string) (int, string) {
		r := httptest.NewRequest("GET", path, nil)
		r.Host, r.RemoteAddr = host, remote
		w := httptest.NewRecorder()
		e.root(w, r)
		return w.Code, w.Body.String()
	}
	for _, path := range []string{"/", "/api/settings", "/index.html", "/pub.js"} {
		if c, b := get("tracker.example:443", path, "192.168.1.20:5000"); c != 200 || b != "page" {
			t.Fatalf("%s : la page seule attendue pour un nom bloqué, %d %q", path, c, b)
		}
	}
	if c, b := get("tracker.example", "/", "203.0.113.9:5000"); c != http.StatusNotFound || b == "page" {
		t.Fatalf("Internet : 404 attendu, %d %q", c, b)
	}
	if _, b := get("rempart.lan", "/", "192.168.1.20:5000"); b != "interface" {
		t.Fatalf("nom de Rempart : interface attendue, %q", b)
	}
}
