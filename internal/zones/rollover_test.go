// rollover_test.go - tests des rotations ZSK/KSK, CDS, délais et clés manquantes.
// Chaque RRSIG vérifiée avec la clé du DNSKEY.
// Rempart ; go test ./internal/zones.

package zones

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

// verifyAll vérifie chaque RRSIG d'une réponse avec la clé du DNSKEY de la
// zone qui porte le même key tag.
func verifyAll(t *testing.T, z *Zone, rrs []dns.RR) {
	t.Helper()
	keys := map[uint16]*dns.DNSKEY{}
	for _, rr := range z.nodes[z.Origin][dns.TypeDNSKEY] {
		k := rr.(*dns.DNSKEY)
		keys[k.KeyTag()] = k
	}
	n := 0
	for _, rr := range rrs {
		s, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		var set []dns.RR
		for _, x := range rrs {
			if x.Header().Rrtype == s.TypeCovered && x.Header().Name == s.Hdr.Name {
				set = append(set, x)
			}
		}
		k := keys[s.KeyTag]
		if k == nil {
			t.Fatalf("RRSIG %s faite par une clé %d absente du DNSKEY", dns.TypeToString[s.TypeCovered], s.KeyTag)
		}
		if err := s.Verify(k, set); err != nil {
			t.Fatalf("RRSIG %s (clé %d) invalide : %v", dns.TypeToString[s.TypeCovered], s.KeyTag, err)
		}
		n++
	}
	if n == 0 {
		t.Fatal("aucune signature")
	}
}

func states(sz state.Zone, role string) []string {
	var out []string
	for _, k := range sz.Keys {
		if k.Role == role {
			out = append(out, k.State)
		}
	}
	return out
}

func build(t *testing.T, ks keystore.Keystore, sz state.Zone) *Zone {
	t.Helper()
	z, err := Build(ks, sz)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []uint16{dns.TypeDNSKEY, dns.TypeA, dns.TypeSOA} {
		verifyAll(t, z, z.Answer(query("maison.lan.", q), true).Answer)
	}
	return z
}

func TestZSKRollover(t *testing.T) {
	ks := testutil.Keystore(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sz := state.Zone{Name: "maison.lan.", DNSSEC: true, Algorithm: "ECDSAP256SHA256", Records: []string{"@ 300 IN A 192.168.1.1"}}
	Normalize(&sz, now)
	if err := GenerateKeys(ks, sz); err != nil {
		t.Fatal(err)
	}
	z := build(t, ks, sz)
	oldZSK := z.ZSK.KeyTag()

	if _, err := StartRollover(&sz, "zsk", now); err != nil {
		t.Fatal(err)
	}
	if _, err := StartRollover(&sz, "zsk", now); err == nil {
		t.Fatal("une seconde rotation simultanée devrait être refusée")
	}
	z = build(t, ks, sz)
	if z.ZSK.KeyTag() != oldZSK || len(z.nodes[z.Origin][dns.TypeDNSKEY]) != 3 {
		t.Fatal("pré-publication : la nouvelle ZSK doit être publiée sans signer")
	}

	// Avant la fin de la propagation, rien ne bouge.
	if ch, _ := Advance(&sz, now.Add(30*time.Minute), z.MaxTTL, DefaultTiming, nil); len(ch) != 0 {
		t.Fatalf("transition prématurée : %v", ch)
	}
	now = now.Add(2 * time.Hour)
	Advance(&sz, now, z.MaxTTL, DefaultTiming, nil)
	if got := states(sz, "zsk"); len(got) != 2 || got[0] != StateRetired || got[1] != StateActive {
		t.Fatalf("états ZSK inattendus : %v", got)
	}
	z = build(t, ks, sz)
	if z.ZSK.KeyTag() == oldZSK {
		t.Fatal("la nouvelle ZSK devrait signer")
	}

	now = now.Add(3 * time.Hour)
	_, destroy := Advance(&sz, now, z.MaxTTL, DefaultTiming, nil)
	if len(destroy) != 1 || len(states(sz, "zsk")) != 1 {
		t.Fatalf("l'ancienne ZSK aurait dû être retirée : %v", sz.Keys)
	}
	for _, l := range destroy {
		if err := ks.Destroy(l); err != nil {
			t.Fatal(err)
		}
	}
	z = build(t, ks, sz)
	if len(z.nodes[z.Origin][dns.TypeDNSKEY]) != 2 {
		t.Fatal("DNSKEY devrait contenir une KSK et une ZSK")
	}
}

func TestKSKRolloverWithCDS(t *testing.T) {
	ks := testutil.Keystore(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sz := state.Zone{Name: "maison.lan.", DNSSEC: true, Algorithm: "ED25519", Records: []string{"@ IN A 192.168.1.1"}}
	Normalize(&sz, now)
	if err := GenerateKeys(ks, sz); err != nil {
		t.Fatal(err)
	}
	z := build(t, ks, sz)
	if len(z.nodes[z.Origin][dns.TypeCDS]) != 1 || len(z.DS()) != 1 {
		t.Fatal("CDS attendu pour la KSK active")
	}
	oldDS := z.DS()[0]

	StartRollover(&sz, "ksk", now)
	z = build(t, ks, sz)
	if len(z.sigs[z.Origin][dns.TypeDNSKEY]) != 2 {
		t.Fatal("le DNSKEY doit être signé par les deux KSK")
	}
	if len(z.nodes[z.Origin][dns.TypeCDS]) != 1 {
		t.Fatal("la KSK publiée ne doit pas encore apparaître dans le CDS")
	}

	now = now.Add(2 * time.Hour)
	Advance(&sz, now, z.MaxTTL, DefaultTiming, nil)
	z = build(t, ks, sz)
	if len(z.nodes[z.Origin][dns.TypeCDS]) != 2 || len(ReadyDS(sz, z)) != 1 {
		t.Fatal("la KSK prête doit être annoncée dans le CDS")
	}
	// Sans DS constaté, la KSK reste prête indéfiniment.
	Advance(&sz, now.Add(30*24*time.Hour), z.MaxTTL, DefaultTiming, nil)
	if got := states(sz, "ksk"); got[1] != StateReady {
		t.Fatalf("KSK : %v", got)
	}
	if !ConfirmDS(&sz, now, 3600) {
		t.Fatal("ConfirmDS sans effet")
	}
	Advance(&sz, now, z.MaxTTL, DefaultTiming, nil)
	if got := states(sz, "ksk"); got[0] != StateRetired || got[1] != StateActive {
		t.Fatalf("KSK : %v", got)
	}
	z = build(t, ks, sz)
	if len(z.DS()) != 1 || z.DS()[0] == oldDS {
		t.Fatal("le DS attendu doit être celui de la nouvelle KSK")
	}
	// L'ancienne KSK signe encore le DNSKEY jusqu'à expiration du DS (au moins 24 h + marge).
	if len(z.sigs[z.Origin][dns.TypeDNSKEY]) != 2 {
		t.Fatal("double signature attendue pendant le retrait")
	}
	if _, d := Advance(&sz, now.Add(3*time.Hour), z.MaxTTL, DefaultTiming, nil); len(d) != 0 {
		t.Fatal("un TTL de DS observé en cache ne doit pas raccourcir l'attente")
	}
	now = now.Add(25*time.Hour + time.Minute)
	_, destroy := Advance(&sz, now, z.MaxTTL, DefaultTiming, nil)
	if len(destroy) != 1 {
		t.Fatalf("KSK retirée non détruite : %v", sz.Keys)
	}
	build(t, ks, sz)
}

func TestMissingActiveKeyIsNotRegenerated(t *testing.T) {
	ks := testutil.Keystore(t)
	now := time.Now().UTC()
	sz := state.Zone{Name: "x.lan.", DNSSEC: true}
	Normalize(&sz, now)
	if _, err := Build(ks, sz); err == nil {
		t.Fatal("des clés actives absentes du keystore doivent être une erreur")
	}
	if err := GenerateKeys(ks, sz); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(ks, sz); err != nil {
		t.Fatal(err)
	}
}

func TestPublicationMustBeLive(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sz := state.Zone{Name: "x.lan.", DNSSEC: true}
	Normalize(&sz, now)
	label, _ := StartRollover(&sz, "zsk", now)
	live := map[string]bool{"zone-x.lan-ksk": true, "zone-x.lan-zsk": true}
	Advance(&sz, now.Add(3*time.Hour), time.Hour, DefaultTiming, live)
	if !InProgress(sz, "zsk") || states(sz, "zsk")[1] != StatePublished {
		t.Fatal("une clé non servie ne doit pas devenir active")
	}
	live[label] = true
	Advance(&sz, now.Add(4*time.Hour), time.Hour, DefaultTiming, live)
	if states(sz, "zsk")[1] != StatePublished {
		t.Fatal("le délai doit repartir de la publication effective")
	}
	Advance(&sz, now.Add(6*time.Hour+time.Minute), time.Hour, DefaultTiming, live)
	if states(sz, "zsk")[1] != StateActive {
		t.Fatalf("états : %v", states(sz, "zsk"))
	}
}

func TestAutoRollover(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sz := state.Zone{Name: "x.lan.", DNSSEC: true}
	Normalize(&sz, now)
	if ch, _ := Advance(&sz, now.Add(89*24*time.Hour), time.Hour, DefaultTiming, nil); len(ch) != 0 {
		t.Fatalf("rotation trop tôt : %v", ch)
	}
	Advance(&sz, now.Add(90*24*time.Hour), time.Hour, DefaultTiming, nil)
	if !InProgress(sz, "zsk") || InProgress(sz, "ksk") {
		t.Fatal("seule la ZSK doit tourner automatiquement par défaut")
	}
}
