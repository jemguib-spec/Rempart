package zones

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

func query(name string, t uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, t)
	m.SetEdns0(1232, true)
	return m
}

func verifySet(t *testing.T, z *Zone, rrs []dns.RR) {
	t.Helper()
	sets := map[uint16][]dns.RR{}
	var sigs []*dns.RRSIG
	for _, rr := range rrs {
		if s, ok := rr.(*dns.RRSIG); ok {
			sigs = append(sigs, s)
		} else {
			sets[rr.Header().Rrtype] = append(sets[rr.Header().Rrtype], rr)
		}
	}
	if len(sigs) == 0 {
		t.Fatal("aucune signature RRSIG")
	}
	for _, s := range sigs {
		key := z.ZSK
		if s.TypeCovered == dns.TypeDNSKEY {
			key = z.KSK
		}
		var set []dns.RR
		for _, rr := range sets[s.TypeCovered] {
			if rr.Header().Name == s.Hdr.Name {
				set = append(set, rr)
			}
		}
		if err := s.Verify(key, set); err != nil {
			t.Fatalf("signature %s invalide: %v", dns.TypeToString[s.TypeCovered], err)
		}
	}
}

func testZone(t *testing.T, ks keystore.Keystore, alg string) {
	z, err := Build(ks, state.Zone{Name: "maison.lan", DNSSEC: true, Algorithm: alg, Records: []string{
		"@ IN A 192.168.1.1",
		"nas 300 IN A 192.168.1.10",
		"nas IN AAAA fd00::10",
		"www IN CNAME nas",
		"a.b IN TXT \"profond\"",
	}})
	if err != nil {
		t.Fatal(err)
	}
	r := z.Answer(query("nas.maison.lan.", dns.TypeA), true)
	if r.Rcode != dns.RcodeSuccess || !r.Authoritative || len(r.Answer) != 2 {
		t.Fatalf("réponse inattendue: %v", r)
	}
	verifySet(t, z, r.Answer)

	r = z.Answer(query("maison.lan.", dns.TypeDNSKEY), true)
	verifySet(t, z, r.Answer)

	r = z.Answer(query("www.maison.lan.", dns.TypeA), true)
	if len(r.Answer) != 4 { // CNAME + sig + A + sig
		t.Fatalf("CNAME non suivi: %v", r.Answer)
	}

	// NXDOMAIN with NSEC proofs
	r = z.Answer(query("inconnu.maison.lan.", dns.TypeA), true)
	if r.Rcode != dns.RcodeNameError {
		t.Fatalf("NXDOMAIN attendu, obtenu %s", dns.RcodeToString[r.Rcode])
	}
	var nsecs []*dns.NSEC
	for _, rr := range r.Ns {
		if n, ok := rr.(*dns.NSEC); ok {
			nsecs = append(nsecs, n)
		}
	}
	if len(nsecs) == 0 {
		t.Fatal("aucune preuve NSEC")
	}
	covered := false
	for _, n := range nsecs {
		if canonicalLess(n.Hdr.Name, "inconnu.maison.lan.") && (canonicalLess("inconnu.maison.lan.", n.NextDomain) || n.NextDomain == z.Origin) {
			covered = true
		}
	}
	if !covered {
		t.Fatalf("aucun NSEC ne couvre le nom: %v", nsecs)
	}
	verifySet(t, z, r.Ns)

	// NODATA
	r = z.Answer(query("nas.maison.lan.", dns.TypeMX), true)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 || len(r.Ns) == 0 {
		t.Fatalf("NODATA attendu: %v", r)
	}
	// Empty non-terminal
	r = z.Answer(query("b.maison.lan.", dns.TypeA), true)
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("ENT: NOERROR attendu, obtenu %s", dns.RcodeToString[r.Rcode])
	}
	if len(z.DS()) != 1 {
		t.Fatal("DS manquant")
	}
}

func TestSignedZoneSoftware(t *testing.T) {
	for _, alg := range []string{"ECDSAP256SHA256", "ECDSAP384SHA384", "ED25519"} {
		t.Run(alg, func(t *testing.T) { testZone(t, testutil.Keystore(t), alg) })
	}
}

func TestCanonicalOrder(t *testing.T) {
	// RFC 4034 §6.1 example ordering
	names := []string{"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.", "zABC.a.EXAMPLE.", "z.example.", "\\001.z.example.", "*.z.example.", "\\200.z.example."}
	for i := 0; i+1 < len(names); i++ {
		if !canonicalLess(names[i], names[i+1]) {
			t.Errorf("%s devrait précéder %s", names[i], names[i+1])
		}
	}
}

func TestRejectManagedRecords(t *testing.T) {
	if _, err := Build(testutil.Keystore(t), state.Zone{Name: "x.lan", Records: []string{"@ IN DNSKEY 257 3 13 AAAA"}}); err == nil {
		t.Fatal("un DNSKEY manuel devrait être refusé")
	}
	if _, err := Build(testutil.Keystore(t), state.Zone{Name: "x.lan", Records: []string{"evil.com. IN A 1.2.3.4"}}); err == nil {
		t.Fatal("un enregistrement hors zone devrait être refusé")
	}
}
