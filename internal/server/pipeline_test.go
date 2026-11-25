package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/cache"
	"github.com/rempart-dns/rempart/internal/state"
)

// slowResolver répond lentement pour slow.example. et tout de suite sinon.
type slowResolver struct{ delay time.Duration }

func (r slowResolver) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, string, error) {
	if q.Question[0].Name == "slow.example." {
		select {
		case <-time.After(r.delay):
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	m := new(dns.Msg)
	m.SetReply(q)
	a, _ := dns.NewRR(q.Question[0].Name + " 300 IN A 93.184.216.34")
	m.Answer = []dns.RR{a}
	return m, "test", nil
}

// Une requête lente ne doit pas retenir les suivantes de la même connexion
// (Android envoie tout son DNS sur une seule connexion DoT).
func TestTCPPipelining(t *testing.T) {
	s := newTestServer(t)
	s.Upstreams = slowResolver{delay: 1500 * time.Millisecond}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Net: "tcp", Handler: s, Listener: &pipeListener{Listener: ln, s: s},
		IdleTimeout: func() time.Duration { return 10 * time.Second }, MsgAcceptFunc: acceptMsg}
	if err := s.start(srv); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown() })

	co, err := dns.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer co.Close()
	slow, fast := new(dns.Msg), new(dns.Msg)
	slow.SetQuestion("slow.example.", dns.TypeA)
	fast.SetQuestion("normal.example.", dns.TypeA)
	start := time.Now()
	if err := co.WriteMsg(slow); err != nil {
		t.Fatal(err)
	}
	if err := co.WriteMsg(fast); err != nil {
		t.Fatal(err)
	}
	_ = co.SetReadDeadline(time.Now().Add(5 * time.Second))
	first, err := co.ReadMsg()
	if err != nil {
		t.Fatal(err)
	}
	if first.Id != fast.Id || time.Since(start) > time.Second {
		t.Fatalf("la requête rapide a attendu la lente (%v, id %d)", time.Since(start), first.Id)
	}
	second, err := co.ReadMsg()
	if err != nil || second.Id != slow.Id || len(second.Answer) != 1 {
		t.Fatalf("réponse lente : %v %v", second, err)
	}
}

// À la fermeture par le serveur (nombre maximal de requêtes atteint), les
// réponses en cours partent encore.
func TestPipelineDrainsOnClose(t *testing.T) {
	s := newTestServer(t)
	s.Upstreams = slowResolver{delay: 300 * time.Millisecond}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Net: "tcp", Handler: s, MaxTCPQueries: 1, Listener: &pipeListener{Listener: ln, s: s}, MsgAcceptFunc: acceptMsg}
	if err := s.start(srv); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown() })
	co, err := dns.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer co.Close()
	m := new(dns.Msg)
	m.SetQuestion("slow.example.", dns.TypeA)
	_ = co.WriteMsg(m)
	_ = co.SetReadDeadline(time.Now().Add(5 * time.Second))
	r, err := co.ReadMsg()
	if err != nil || r.Id != m.Id {
		t.Fatalf("réponse perdue à la fermeture : %v", err)
	}
}

// failingResolver échoue pour tout, ou attend la fin du contexte.
type failingResolver struct{ hang bool }

func (r failingResolver) Exchange(ctx context.Context, _ *dns.Msg) (*dns.Msg, string, error) {
	if r.hang {
		<-ctx.Done()
		return nil, "", ctx.Err()
	}
	return nil, "", context.DeadlineExceeded
}

func expire(s *Server, name string) string {
	k := cache.Key(dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}, false)
	// Plus simple que d'attendre : on remet en cache une copie déjà expirée.
	r, _ := s.Cache.Get(k)
	for _, rr := range r.Answer {
		rr.Header().Ttl = 1
	}
	s.Cache.Set(k, r)
	time.Sleep(1100 * time.Millisecond)
	return k
}

func TestServeStaleWhenUpstreamsFail(t *testing.T) {
	for _, hang := range []bool{false, true} {
		s := newTestServer(t)
		if r := ask(s, "normal.example.", dns.TypeA, "127.0.0.1", false); r.Rcode != dns.RcodeSuccess {
			t.Fatal(r)
		}
		expire(s, "normal.example.")
		s.Upstreams = failingResolver{hang: hang}
		start := time.Now()
		r := ask(s, "normal.example.", dns.TypeA, "127.0.0.1", false)
		if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 || r.Answer[0].Header().Ttl != cache.StaleTTL {
			t.Fatalf("hang=%v : pas de réponse expirée : %v", hang, r)
		}
		if hang && time.Since(start) > 3*time.Second {
			t.Fatalf("réponse expirée servie trop tard : %v", time.Since(start))
		}
	}
}

// Une liste qui vise miui.com ne doit pas casser le test de connectivité de
// Xiaomi (Wi-Fi jugé « sans Internet » au changement de réseau).
func TestConnectivityProbeNeverBlocked(t *testing.T) {
	s := newTestServerWith(t, func(st *state.State) {
		st.Rules = append(st.Rules, state.Rule{Domain: "miui.com"})
	})
	r := ask(s, "tracking.miui.com.", dns.TypeA, "127.0.0.1", false)
	if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "0.0.0.0" {
		t.Fatalf("la règle ne bloque pas : %v", r)
	}
	r = ask(s, "connect.rom.miui.com.", dns.TypeA, "127.0.0.1", false)
	if len(r.Answer) == 1 {
		if a, ok := r.Answer[0].(*dns.A); ok && a.A.String() == "0.0.0.0" {
			t.Fatal("test de connectivité bloqué")
		}
	}
}
