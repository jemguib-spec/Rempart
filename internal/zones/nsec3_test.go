package zones

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

func nsec3Zone(t *testing.T) *Zone {
	t.Helper()
	z, err := Build(testutil.Keystore(t), state.Zone{Name: "maison.lan", DNSSEC: true, Algorithm: "ecdsap256",
		Policy: state.ZonePolicy{NSEC3: true}, Records: []string{
			"nas IN A 192.168.1.10",
			"a.b.c IN TXT \"profond\"",
			"www IN CNAME nas",
		}})
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func nsec3s(rrs []dns.RR) []*dns.NSEC3 {
	var out []*dns.NSEC3
	for _, rr := range rrs {
		if n, ok := rr.(*dns.NSEC3); ok {
			out = append(out, n)
		}
	}
	return out
}

// verifyAll vérifie chaque RRSIG d'une section avec les clés de la zone.
func verifySigs(t *testing.T, z *Zone, rrs []dns.RR) {
	t.Helper()
	keys := map[uint16]*dns.DNSKEY{}
	for _, k := range z.Keys {
		keys[k.Tag] = k.key
	}
	sets := map[string][]dns.RR{}
	for _, rr := range rrs {
		if _, ok := rr.(*dns.RRSIG); !ok {
			h := rr.Header()
			k := strings.ToLower(h.Name) + "/" + dns.TypeToString[h.Rrtype]
			sets[k] = append(sets[k], rr)
		}
	}
	n := 0
	for _, rr := range rrs {
		s, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		n++
		set := sets[strings.ToLower(s.Hdr.Name)+"/"+dns.TypeToString[s.TypeCovered]]
		if err := s.Verify(keys[s.KeyTag], set); err != nil {
			t.Fatalf("RRSIG %s/%s : %v", s.Hdr.Name, dns.TypeToString[s.TypeCovered], err)
		}
	}
	if n == 0 {
		t.Fatal("aucune signature")
	}
}

func TestNSEC3NoNSECAndParam(t *testing.T) {
	z := nsec3Zone(t)
	for _, rr := range z.AXFR() {
		if rr.Header().Rrtype == dns.TypeNSEC {
			t.Fatal("NSEC publié dans une zone NSEC3")
		}
	}
	r := z.Answer(query("maison.lan.", dns.TypeNSEC3PARAM), true)
	if len(r.Answer) != 2 {
		t.Fatalf("NSEC3PARAM : %v", r.Answer)
	}
	p := r.Answer[0].(*dns.NSEC3PARAM)
	if p.Hash != dns.SHA1 || p.Iterations != 0 || p.Salt != "" || p.Flags != 0 {
		t.Fatalf("paramètres non conformes à la RFC 9276 : %v", p)
	}
	verifySigs(t, z, r.Answer)
}

func TestNSEC3NXDOMAINProof(t *testing.T) {
	z := nsec3Zone(t)
	for _, q := range []string{"inconnu.maison.lan.", "x.y.nas.maison.lan.", "z.c.maison.lan."} {
		r := z.Answer(query(q, dns.TypeA), true)
		if r.Rcode != dns.RcodeNameError {
			t.Fatalf("%s : %s", q, dns.RcodeToString[r.Rcode])
		}
		verifySigs(t, z, r.Ns)
		ns := nsec3s(r.Ns)
		ce := z.closestEncloser(q)
		nc := nextCloser(q, ce)
		var matchCE, coverNC, coverWC bool
		for _, n := range ns {
			matchCE = matchCE || n.Match(ce)
			coverNC = coverNC || n.Cover(nc)
			coverWC = coverWC || n.Cover("*."+ce)
		}
		if !matchCE || !coverNC || !coverWC {
			t.Fatalf("%s : preuve incomplète (encloser %s=%v, suivant %s=%v, joker=%v)", q, ce, matchCE, nc, coverNC, coverWC)
		}
		// Aucun NSEC3 ne doit révéler un nom en clair.
		for _, n := range ns {
			if strings.Contains(n.Hdr.Name, "nas") {
				t.Fatal("nom en clair dans un propriétaire NSEC3")
			}
		}
	}
}

func TestNSEC3NoData(t *testing.T) {
	z := nsec3Zone(t)
	for _, c := range []struct {
		q    string
		ent  bool
		have uint16
	}{{"nas.maison.lan.", false, dns.TypeA}, {"b.c.maison.lan.", true, 0}, {"c.maison.lan.", true, 0}} {
		r := z.Answer(query(c.q, dns.TypeMX), true)
		if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
			t.Fatalf("%s : NODATA attendu, %v", c.q, r)
		}
		verifySigs(t, z, r.Ns)
		ns := nsec3s(r.Ns)
		if len(ns) != 1 || !ns[0].Match(c.q) {
			t.Fatalf("%s : NSEC3 correspondant absent : %v", c.q, ns)
		}
		bm := ns[0].TypeBitMap
		for _, ty := range bm {
			if ty == dns.TypeMX {
				t.Fatal("le bitmap annonce le type nié")
			}
		}
		if c.ent && len(bm) != 0 {
			t.Fatalf("nom intermédiaire vide avec un bitmap non vide : %v", bm)
		}
		if !c.ent {
			found := false
			for _, ty := range bm {
				found = found || ty == c.have
			}
			if !found {
				t.Fatalf("type existant absent du bitmap : %v", bm)
			}
		}
	}
}

func TestNSEC3ChainClosed(t *testing.T) {
	z := nsec3Zone(t)
	// apex, nas, www, a.b.c, b.c, c : 6 noms, donc 6 NSEC3 en anneau.
	if len(z.n3.owners) != 6 {
		t.Fatalf("%d NSEC3 : %v", len(z.n3.owners), z.n3.owners)
	}
	seen := map[string]bool{}
	o := z.n3.owners[0]
	for i := 0; i < len(z.n3.owners); i++ {
		if seen[o] {
			t.Fatal("anneau NSEC3 trop court")
		}
		seen[o] = true
		o = strings.ToLower(z.n3.recs[o].NextDomain) + "." + z.Origin
	}
	if o != z.n3.owners[0] {
		t.Fatal("anneau NSEC3 non refermé")
	}
	// Un propriétaire haché n'est pas un nom de la zone.
	r := z.Answer(query(z.n3.owners[0], dns.TypeNSEC3), true)
	if r.Rcode != dns.RcodeNameError {
		t.Fatalf("requête sur un nom haché : %s", dns.RcodeToString[r.Rcode])
	}
}

func TestNSEC3TransferRoundTrip(t *testing.T) {
	z := nsec3Zone(t)
	sec, err := FromTransfer("maison.lan.", z.AXFR())
	if err != nil {
		t.Fatal(err)
	}
	if sec.n3 == nil || len(sec.n3.owners) != len(z.n3.owners) {
		t.Fatal("chaîne NSEC3 perdue au transfert")
	}
	r := sec.Answer(query("inconnu.maison.lan.", dns.TypeA), true)
	if r.Rcode != dns.RcodeNameError || len(nsec3s(r.Ns)) < 2 {
		t.Fatalf("secondaire : preuve absente : %v", r.Ns)
	}
	verifySigs(t, z, r.Ns)
	if len(sec.AXFR()) != len(z.AXFR()) {
		t.Fatal("le secondaire ne retransmet pas la zone complète")
	}
}

func TestNSECStillDefault(t *testing.T) {
	z, err := Build(testutil.Keystore(t), state.Zone{Name: "maison.lan", DNSSEC: true, Algorithm: "ecdsap256", Records: []string{"nas IN A 192.168.1.10"}})
	if err != nil {
		t.Fatal(err)
	}
	if z.n3 != nil || len(z.nodes[z.Origin][dns.TypeNSEC]) != 1 {
		t.Fatal("zone sans NSEC3 demandé : chaîne NSEC attendue")
	}
}
