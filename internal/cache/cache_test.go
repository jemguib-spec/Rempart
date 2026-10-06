package cache

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func answer(name string, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.Response = true
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.IPv4(192, 0, 2, 1)}}
	return m
}

func TestKey(t *testing.T) {
	q := dns.Question{Name: "Example.COM.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	q2 := q
	q2.Name = "example.com."
	if Key(q, false) != Key(q2, false) {
		t.Fatal("la casse change la clé")
	}
	if Key(q, false) == Key(q, true) {
		t.Fatal("le bit DO ne change pas la clé")
	}
	q3 := q
	q3.Qtype = dns.TypeAAAA
	if Key(q, false) == Key(q3, false) {
		t.Fatal("le type ne change pas la clé")
	}
	// Un type dont l'octet de poids faible vaut A ne doit pas se confondre.
	q4 := q
	q4.Qtype = 256 + dns.TypeA
	if Key(q, false) == Key(q4, false) {
		t.Fatal("collision de types")
	}
}

func TestSetGetCopyAndTTL(t *testing.T) {
	c := New(1000, 0, time.Hour)
	k := Key(dns.Question{Name: "a.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, false)
	c.Set(k, answer("a.example.", 300))
	m, ok := c.Get(k)
	if !ok || len(m.Answer) != 1 {
		t.Fatal("absent du cache")
	}
	m.Answer[0].(*dns.A).A = net.IPv4(6, 6, 6, 6) // la copie rendue est indépendante
	m2, _ := c.Get(k)
	if m2.Answer[0].(*dns.A).A.String() != "192.0.2.1" {
		t.Fatal("le cache partage ses réponses")
	}
	if ttl := m2.Answer[0].Header().Ttl; ttl > 300 || ttl < 299 {
		t.Fatalf("TTL %d", ttl)
	}
	_, hits, miss := c.Stats()
	if hits != 2 || miss != 0 {
		t.Fatalf("hits=%d miss=%d", hits, miss)
	}
}

func TestTTLDecrementsAndExpires(t *testing.T) {
	c := New(1000, 0, time.Hour)
	k := "k"
	c.Set(k, answer("a.example.", 300))
	s := c.shard(k)
	s.mu.Lock()
	e := s.m[k]
	e.stored = e.stored.Add(-100 * time.Second)
	s.m[k] = e
	s.mu.Unlock()
	m, _ := c.Get(k)
	if ttl := m.Answer[0].Header().Ttl; ttl != 200 {
		t.Fatalf("TTL après 100 s : %d", ttl)
	}
	s.mu.Lock()
	e.expires = time.Now().Add(-time.Second)
	s.m[k] = e
	s.mu.Unlock()
	if _, ok := c.Get(k); ok {
		t.Fatal("entrée expirée servie")
	}
}

func TestMinMaxTTL(t *testing.T) {
	c := New(1000, 60*time.Second, 120*time.Second)
	c.Set("low", answer("a.", 5))
	c.Set("high", answer("b.", 86400))
	for k, want := range map[string]time.Duration{"low": 60 * time.Second, "high": 120 * time.Second} {
		s := c.shard(k)
		s.mu.RLock()
		e := s.m[k]
		s.mu.RUnlock()
		if d := e.expires.Sub(e.stored); d != want {
			t.Fatalf("%s : durée %v, attendu %v", k, d, want)
		}
	}
}

func TestNotCacheable(t *testing.T) {
	c := New(1000, 0, time.Hour)
	tr := answer("t.", 300)
	tr.Truncated = true
	sf := answer("s.", 300)
	sf.Rcode = dns.RcodeServerFailure
	ref := answer("r.", 300)
	ref.Rcode = dns.RcodeRefused
	zero := answer("z.", 0)
	empty := new(dns.Msg) // ni réponse ni SOA : rien pour fixer un TTL
	empty.SetQuestion("e.", dns.TypeA)
	for k, m := range map[string]*dns.Msg{"t": tr, "s": sf, "r": ref, "z": zero, "e": empty, "nil": nil} {
		c.Set(k, m)
		if _, ok := c.Get(k); ok {
			t.Fatalf("%s mis en cache", k)
		}
	}
}

func TestNegativeCachingUsesSOAMinimum(t *testing.T) {
	c := New(1000, 0, time.Hour)
	m := new(dns.Msg)
	m.SetQuestion("nx.example.", dns.TypeA)
	m.Rcode = dns.RcodeNameError
	m.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns: "ns.example.", Mbox: "h.example.", Minttl: 30}}
	c.Set("nx", m)
	s := c.shard("nx")
	e := s.m["nx"]
	if d := e.expires.Sub(e.stored); d != 30*time.Second {
		t.Fatalf("TTL négatif %v, attendu 30 s (RFC 2308)", d)
	}
}

func TestOPTTTLUntouched(t *testing.T) {
	c := New(1000, 0, time.Hour)
	m := answer("o.", 300)
	m.SetEdns0(1232, true)
	c.Set("o", m)
	s := c.shard("o")
	e := s.m["o"]
	e.stored = e.stored.Add(-10 * time.Second)
	s.m["o"] = e
	got, _ := c.Get("o")
	if opt := got.IsEdns0(); opt == nil || !opt.Do() {
		t.Fatal("OPT altéré (le bit DO est porté par son TTL)")
	}
}

func TestEvictionBounded(t *testing.T) {
	c := New(64*16, 0, time.Hour) // 16 par fragment
	for i := 0; i < 10000; i++ {
		c.Set(fmt.Sprint(i), answer("a.", 300))
	}
	if n, _, _ := c.Stats(); n > 64*16 {
		t.Fatalf("%d entrées pour 1024 au plus", n)
	}
	c.Flush()
	if n, _, _ := c.Stats(); n != 0 {
		t.Fatal("Flush incomplet")
	}
}

func TestConcurrent(t *testing.T) {
	c := New(1000, 0, time.Hour)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				k := fmt.Sprint(i % 50)
				if i%3 == 0 {
					c.Set(k, answer("a.", 300))
				} else {
					c.Get(k)
				}
				if i%500 == 0 {
					c.Flush()
				}
			}
		}(g)
	}
	wg.Wait()
}
