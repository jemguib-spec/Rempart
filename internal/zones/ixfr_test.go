package zones

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

func axfrSet(rrs []dns.RR) map[string]bool {
	m := map[string]bool{}
	for _, rr := range rrs {
		if rr.Header().Rrtype != dns.TypeSOA {
			m[rrKey(rr)] = true
		}
	}
	return m
}

func TestIXFRAndSignatureReuse(t *testing.T) {
	for _, nsec3 := range []bool{false, true} {
		ks := testutil.Keystore(t)
		m := NewManager(ks, testutil.Logger())
		sz := state.Zone{Name: "maison.lan.", DNSSEC: true, Algorithm: "ECDSAP256", Policy: state.ZonePolicy{NSEC3: nsec3},
			Records: []string{"nas IN A 192.168.1.10", "imprimante IN A 192.168.1.20", "www IN CNAME nas"}, Serial: 100}
		if err := m.Load([]state.Zone{sz}); err != nil {
			t.Fatal(err)
		}
		v1 := m.Get("maison.lan.")
		s1 := v1.Serial()

		time.Sleep(1100 * time.Millisecond) // numéro de série = heure Unix
		sz.Records = []string{"nas IN A 192.168.1.11", "imprimante IN A 192.168.1.20", "www IN CNAME nas"}
		if err := m.Load([]state.Zone{sz}); err != nil {
			t.Fatal(err)
		}
		v2 := m.Get("maison.lan.")
		if v2.reused == 0 {
			t.Fatal("aucune signature reprise")
		}
		// Les RRsets inchangés gardent leur signature.
		if v1.sigs["imprimante.maison.lan."][dns.TypeA][0].String() != v2.sigs["imprimante.maison.lan."][dns.TypeA][0].String() {
			t.Fatal("RRset inchangé re-signé")
		}
		if v1.sigs["nas.maison.lan."][dns.TypeA][0].String() == v2.sigs["nas.maison.lan."][dns.TypeA][0].String() {
			t.Fatal("RRset modifié avec l'ancienne signature")
		}
		// Toutes les signatures restent valides.
		for name, set := range v2.nodes {
			for ty := range set {
				verifySigs(t, v2, append(append([]dns.RR{}, v2.nodes[name][ty]...), v2.sigs[name][ty]...))
			}
		}

		inc, ok := m.IXFR("maison.lan.", s1)
		if !ok {
			t.Fatal("IXFR indisponible")
		}
		if inc[0].(*dns.SOA).Serial != v2.Serial() || inc[len(inc)-1].(*dns.SOA).Serial != v2.Serial() || inc[1].(*dns.SOA).Serial != s1 {
			t.Fatal("structure IXFR (RFC 1995 §4)")
		}
		if len(inc) >= len(v2.AXFR()) {
			t.Fatalf("IXFR (%d) pas plus petit que l'AXFR (%d)", len(inc), len(v2.AXFR()))
		}
		// Appliquer les différences à la version 1 redonne la version 2.
		cur := axfrSet(v1.AXFR())
		phase := 0
		for _, rr := range inc[1 : len(inc)-1] {
			if rr.Header().Rrtype == dns.TypeSOA {
				phase++
				continue
			}
			if phase%2 == 1 {
				delete(cur, rrKey(rr))
			} else {
				cur[rrKey(rr)] = true
			}
		}
		want := axfrSet(v2.AXFR())
		if len(cur) != len(want) {
			t.Fatalf("après IXFR : %d enregistrements, attendu %d", len(cur), len(want))
		}
		for k := range want {
			if !cur[k] {
				t.Fatalf("manquant après IXFR : %s", k)
			}
		}
		if _, ok := m.IXFR("maison.lan.", 12345); ok {
			t.Fatal("IXFR depuis une version inconnue")
		}
		// Re-signature forcée : aucune reprise.
		if err := m.Resign([]state.Zone{sz}); err != nil {
			t.Fatal(err)
		}
		if m.Get("maison.lan.").reused != 0 {
			t.Fatal("re-signature forcée avec reprise")
		}
	}
}
