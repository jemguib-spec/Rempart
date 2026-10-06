package tsig

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestAlgorithmsAndSingle(t *testing.T) {
	for _, alg := range []string{"hmac-md5.sig-alg.reg.int.", "hmac-sha1."} {
		if _, err := NewKey("k", alg); err == nil {
			t.Fatalf("algorithme obsolète accepté : %s", alg)
		}
	}
	if _, err := ImportKey("k", "hmac-sha256", "c2hvcnQ="); err == nil {
		t.Fatal("secret de moins de 128 bits accepté")
	}
	a, _ := NewKey("a.test", "hmac-sha256")
	b, _ := NewKey("b.test", "hmac-sha256")
	_ = b
	s := NewSingle(a)
	if err := s.Verify(nil, &dns.TSIG{Hdr: dns.RR_Header{Name: "b.test."}, Algorithm: dns.HmacSHA256}); err == nil {
		t.Fatal("Single accepte une autre clé")
	}
	var r Replay
	now := time.Now()
	if !r.Fresh("m1", now, now.Add(time.Minute)) || r.Fresh("m1", now, now.Add(time.Minute)) {
		t.Fatal("anti-rejeu")
	}
	if !r.Fresh("m1", now.Add(2*time.Minute), now.Add(3*time.Minute)) {
		t.Fatal("MAC expiré non purgé")
	}
}
