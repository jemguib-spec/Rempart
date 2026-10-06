package zones

import (
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

// checkAlgorithms vérifie la règle de la RFC 4035 §2.2 : chaque RRset est
// signé (signature valide) par au moins une clé de chaque algorithme publié
// dans le DNSKEY de l'apex. Il renvoie les algorithmes publiés et ceux qui
// signent.
func checkAlgorithms(t *testing.T, z *Zone, stage string) (published, signing map[uint8]bool) {
	t.Helper()
	published, signing = map[uint8]bool{}, map[uint8]bool{}
	keys := map[uint16]*dns.DNSKEY{}
	for _, rr := range z.nodes[z.Origin][dns.TypeDNSKEY] {
		k := rr.(*dns.DNSKEY)
		published[k.Algorithm] = true
	}
	for _, k := range z.Keys {
		keys[k.Tag] = k.key
	}
	sets := map[string][]dns.RR{}
	sigs := map[string][]*dns.RRSIG{}
	for _, rr := range z.AXFR()[1:] {
		h := rr.Header()
		if s, ok := rr.(*dns.RRSIG); ok {
			k := strings.ToLower(h.Name) + "/" + dns.TypeToString[s.TypeCovered]
			sigs[k] = append(sigs[k], s)
			continue
		}
		k := strings.ToLower(h.Name) + "/" + dns.TypeToString[h.Rrtype]
		sets[k] = append(sets[k], rr)
	}
	for k, set := range sets {
		if strings.HasSuffix(k, "/SOA") {
			set = set[:1] // le SOA de fin de transfert est un doublon
		}
		got := map[uint8]bool{}
		for _, s := range sigs[k] {
			key := keys[s.KeyTag]
			if key == nil {
				t.Fatalf("%s : %s signé par une clé inconnue %d", stage, k, s.KeyTag)
			}
			if err := s.Verify(key, set); err != nil {
				t.Fatalf("%s : signature %s invalide : %v", stage, k, err)
			}
			got[s.Algorithm] = true
			signing[s.Algorithm] = true
		}
		for alg := range published {
			if !got[alg] {
				t.Fatalf("%s : %s n'est pas signé en algorithme %d alors qu'il est publié (RFC 4035 §2.2)", stage, k, alg)
			}
		}
	}
	return published, signing
}

func TestAlgorithmRollover(t *testing.T) {
	for _, nsec3 := range []bool{false, true} {
		ks := testutil.Keystore(t)
		now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		sz := state.Zone{Name: "maison.lan.", DNSSEC: true, Algorithm: "ECDSAP256", Policy: state.ZonePolicy{NSEC3: nsec3},
			Records: []string{"@ 300 IN A 192.168.1.1", "nas 600 IN A 192.168.1.10"}}
		Normalize(&sz, now)
		if err := GenerateKeys(ks, sz); err != nil {
			t.Fatal(err)
		}
		if _, err := StartAlgorithmRollover(&sz, "ecdsap256sha256", now); err == nil {
			t.Fatal("rotation vers le même algorithme acceptée")
		}
		if _, err := StartAlgorithmRollover(&sz, "ED25519", now); err != nil {
			t.Fatal(err)
		}
		if _, err := StartAlgorithmRollover(&sz, "ECDSAP384", now); err == nil {
			t.Fatal("seconde rotation d'algorithme acceptée")
		}
		if _, err := StartRollover(&sz, "zsk", now); err == nil {
			t.Fatal("rotation de ZSK acceptée pendant une rotation d'algorithme")
		}

		var z *Zone
		var destroyed []string
		step := func(d time.Duration, stage string) {
			t.Helper()
			now = now.Add(d)
			var err error
			z, err = Build(ks, sz)
			if err != nil {
				t.Fatalf("%s : %v", stage, err)
			}
			live := map[string]bool{}
			for _, k := range z.Keys {
				live[k.Label] = true
			}
			_, d2 := Advance(&sz, now, z.MaxTTL, DefaultTiming, live)
			destroyed = append(destroyed, d2...)
			z, err = Build(ks, sz)
			if err != nil {
				t.Fatalf("%s : %v", stage, err)
			}
		}
		const p256, ed = dns.ECDSAP256SHA256, dns.ED25519

		// 1. Nouvel algorithme : signe sans être publié.
		step(0, "presign")
		pub, sig := checkAlgorithms(t, z, "presign")
		if pub[ed] || !sig[ed] || !pub[p256] {
			t.Fatalf("presign : publiés %v, signent %v", pub, sig)
		}
		step(30*time.Minute, "presign (attente)")
		if pub, _ := checkAlgorithms(t, z, "presign attente"); pub[ed] {
			t.Fatal("nouvelles clés publiées avant la propagation des signatures")
		}
		// 2. Publication après le plus grand TTL + marge.
		step(2*time.Hour, "publication")
		pub, sig = checkAlgorithms(t, z, "publication")
		if !pub[ed] || !pub[p256] || !sig[ed] || !sig[p256] {
			t.Fatalf("publication : publiés %v, signent %v", pub, sig)
		}
		step(3*time.Hour, "prête")
		if got := ReadyDS(sz, z); len(got) != 1 || !strings.Contains(got[0], " 15 2 ") {
			t.Fatalf("DS de la nouvelle KSK attendu : %v", got)
		}
		// Rien ne bouge tant que le DS n'est pas constaté.
		step(48*time.Hour, "attente DS")
		if sz.NextAlgorithm == "" {
			t.Fatal("rotation terminée sans DS")
		}
		// 3. DS constaté : nouvelle KSK active, ancienne retirée.
		ConfirmDS(&sz, now, 3600)
		step(time.Minute, "DS")
		checkAlgorithms(t, z, "DS")
		if ds := z.DS(); len(ds) != 1 || !strings.Contains(ds[0], " 15 2 ") {
			t.Fatalf("DS servi : %v", ds)
		}
		// Après l'expiration de l'ancien DS : anciennes clés hors du DNSKEY.
		step(26*time.Hour, "postsign")
		pub, sig = checkAlgorithms(t, z, "postsign")
		if pub[p256] || !sig[p256] || !pub[ed] {
			t.Fatalf("postsign : publiés %v, signent %v", pub, sig)
		}
		// 4. Anciennes signatures retirées, clés détruites.
		step(3*time.Hour, "fin")
		pub, sig = checkAlgorithms(t, z, "fin")
		if pub[p256] || sig[p256] {
			t.Fatalf("fin : publiés %v, signent %v", pub, sig)
		}
		if sz.NextAlgorithm != "" || sz.Algorithm != "ED25519" || len(destroyed) != 2 || len(sz.Keys) != 2 {
			t.Fatalf("fin : alg=%s next=%s détruites=%v clés=%+v", sz.Algorithm, sz.NextAlgorithm, destroyed, sz.Keys)
		}
		// Une rotation de ZSK ordinaire fonctionne ensuite.
		if _, err := StartRollover(&sz, "zsk", now); err != nil {
			t.Fatal(err)
		}
		step(0, "zsk après")
		checkAlgorithms(t, z, "zsk après")
	}
}
