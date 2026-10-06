package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/blocker"
	"github.com/rempart-dns/rempart/internal/cache"
	"github.com/rempart-dns/rempart/internal/policy"
	"github.com/rempart-dns/rempart/internal/querylog"
	"github.com/rempart-dns/rempart/internal/rpz"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
	"github.com/rempart-dns/rempart/internal/upstream"
	"github.com/rempart-dns/rempart/internal/zones"
)

// fakeUpstream answers a few fixed names.
func fakeUpstream(t testing.TB) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		rr := func(s string) dns.RR { x, _ := dns.NewRR(s); return x }
		switch q.Name {
		case "normal.example.":
			m.Answer = []dns.RR{rr("normal.example. 300 IN A 93.184.216.34")}
		case "metrics.shop.example.":
			m.Answer = []dns.RR{rr("metrics.shop.example. 300 IN CNAME track.adtech.example."), rr("track.adtech.example. 300 IN A 5.6.7.8")}
		case "rebind.evil.example.":
			m.Answer = []dns.RR{rr("rebind.evil.example. 300 IN A 192.168.1.1")}
		case "forcesafesearch.google.com.":
			m.Answer = []dns.RR{rr("forcesafesearch.google.com. 300 IN A 216.239.38.120")}
		case "www.evil.example.":
			m.Answer = []dns.RR{rr("www.evil.example. 300 IN A 93.184.216.35")}
		case "evil.example.":
			if q.Qtype == dns.TypeNS {
				m.Answer = []dns.RR{rr("evil.example. 300 IN NS ns1.badhost.example.")}
			}
		case "printer.lan.":
			m.Answer = []dns.RR{rr("printer.lan. 300 IN A 192.168.1.50")}
		default:
			m.Rcode = dns.RcodeNameError
		}
		// Upstream ECS must never be visible to us: assert the query has none.
		if o := r.IsEdns0(); o != nil {
			for _, opt := range o.Option {
				if opt.Option() == dns.EDNS0SUBNET {
					m.Rcode = dns.RcodeRefused
				}
			}
		}
		w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func newTestServer(t testing.TB) *Server { return newTestServerWith(t, nil) }

func newTestServerWith(t testing.TB, mutate func(*state.State)) *Server {
	ks := testutil.Keystore(t)
	dir := t.TempDir()
	st := state.State{
		Settings: state.Settings{BlockingEnabled: true, BlockingMode: "zero", LogMode: "full", RetentionDays: 7,
			ClientIDs: "pseudonymize", BlockCNAMECloak: true, RebindProtect: true, BlockDoHCanary: true},
		Rules: []state.Rule{{Domain: "adtech.example"}, {Domain: "ads.example"}, {Domain: "ok.ads.example", Allow: true}},
		Zones: []state.Zone{{Name: "maison.lan.", DNSSEC: true, Records: []string{"nas IN A 192.168.1.10"}}},
	}
	if mutate != nil {
		mutate(&st)
	}
	store, _, err := state.Open(ks, filepath.Join(dir, "state.sealed"), st)
	if err != nil {
		t.Fatal(err)
	}
	eng, _ := blocker.New(store, dir, nil, testutil.Logger())
	eng.Rebuild()
	zm := zones.NewManager(ks, testutil.Logger())
	if err := zm.Load(st.Zones); err != nil {
		t.Fatal(err)
	}
	u, _ := upstream.Parse(fakeUpstream(t), upstream.Options{})
	g, _ := upstream.NewGroup([]upstream.Upstream{u})
	ql, _ := querylog.New(ks, dir, testutil.Logger())
	ql.Configure("full", "pseudonymize", 7)
	t.Cleanup(ql.Flush) // avant la suppression du dossier temporaire
	s := &Server{Zones: zm, Blocker: eng, Cache: cache.New(1000, 0, time.Hour), Upstreams: g, Log: ql, Logger: testutil.Logger(),
		ACL:           []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8")},
		RebindAllowed: []string{"lan"}, Limiter: NewLimiter(1000, 1000)}
	s.SetSettings(store.Get())
	if mutate != nil {
		p, err := policy.Compile(store.Get())
		if err != nil {
			t.Fatal(err)
		}
		s.SetPolicy(p)
	}
	return s
}

func ask(s *Server, name string, qt uint16, ip string, do bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qt)
	m.SetEdns0(1232, do)
	m.IsEdns0().Option = append(m.IsEdns0().Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("10.1.2.0")})
	return s.Handle(context.Background(), m, netip.MustParseAddr(ip), "udp")
}

func TestPipeline(t *testing.T) {
	s := newTestServer(t)
	const c = "127.0.0.1"

	r := ask(s, "normal.example.", dns.TypeA, c, false)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("résolution normale: %v", r)
	}
	if r2 := ask(s, "normal.example.", dns.TypeA, c, false); len(r2.Answer) != 1 {
		t.Fatal("réponse depuis le cache attendue")
	}
	if _, hits, _ := s.Cache.Stats(); hits != 1 {
		t.Fatalf("1 hit de cache attendu, %d", hits)
	}

	r = ask(s, "banner.ads.example.", dns.TypeA, c, false)
	if a, ok := r.Answer[0].(*dns.A); !ok || !a.A.Equal(net.IPv4zero) {
		t.Fatalf("blocage attendu (0.0.0.0): %v", r)
	}
	if r = ask(s, "ok.ads.example.", dns.TypeA, c, false); r.Rcode != dns.RcodeNameError {
		t.Fatalf("exception: la requête doit partir vers l'upstream (NXDOMAIN du faux upstream), obtenu %v", r)
	}

	r = ask(s, "metrics.shop.example.", dns.TypeA, c, false)
	if a, ok := r.Answer[0].(*dns.A); !ok || !a.A.Equal(net.IPv4zero) {
		t.Fatalf("CNAME cloaking non bloqué: %v", r)
	}

	if r = ask(s, "rebind.evil.example.", dns.TypeA, c, false); r.Rcode != dns.RcodeNameError {
		t.Fatalf("rebinding non bloqué: %v", r)
	}
	if r = ask(s, "printer.lan.", dns.TypeA, c, false); len(r.Answer) != 1 {
		t.Fatalf("les domaines locaux autorisés ne doivent pas être bloqués: %v", r)
	}

	r = ask(s, "nas.maison.lan.", dns.TypeA, c, true)
	if !r.Authoritative || len(r.Answer) != 2 {
		t.Fatalf("zone locale signée attendue: %v", r)
	}
	if r = ask(s, "nas.maison.lan.", dns.TypeA, c, false); len(r.Answer) != 1 {
		t.Fatalf("sans DO, pas de RRSIG: %v", r.Answer)
	}

	if r = ask(s, "use-application-dns.net.", dns.TypeA, c, false); r.Rcode != dns.RcodeNameError {
		t.Fatal("canari DoH non bloqué")
	}
	if r = ask(s, "normal.example.", dns.TypeANY, c, false); r.Answer[0].Header().Rrtype != dns.TypeHINFO {
		t.Fatal("ANY doit recevoir une réponse RFC 8482")
	}
	if r = ask(s, "normal.example.", dns.TypeA, "8.8.8.8", false); r != nil {
		t.Fatal("un client hors ACL doit être ignoré en UDP")
	}

	snap := s.Log.Stats.Snapshot()
	if snap.Blocked < 4 || snap.Local < 2 || snap.Cached != 1 {
		t.Fatalf("statistiques inattendues: %+v", snap)
	}
}

func TestRealUDPListener(t *testing.T) {
	s := newTestServer(t)
	l, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := l.LocalAddr().String()
	l.Close()
	if err := s.ListenDNS(addr); err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(context.Background())
	m := new(dns.Msg)
	m.SetQuestion("banner.ads.example.", dns.TypeAAAA)
	r, _, err := (&dns.Client{}).Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := r.Answer[0].(*dns.AAAA); !ok || !a.AAAA.Equal(net.IPv6unspecified) {
		t.Fatalf("%v", r)
	}
	r, _, err = (&dns.Client{Net: "tcp"}).Exchange(m, addr)
	if err != nil || len(r.Answer) != 1 {
		t.Fatalf("TCP: %v %v", r, err)
	}
}

func BenchmarkHandleCached(b *testing.B) {
	s := newTestServer(b)
	ask(s, "normal.example.", dns.TypeA, "127.0.0.1", false)
	s.Log.Configure("none", "pseudonymize", 1)
	m := new(dns.Msg)
	m.SetQuestion("normal.example.", dns.TypeA)
	ip := netip.MustParseAddr("127.0.0.1")
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Handle(context.Background(), m.Copy(), ip, "udp")
		}
	})
}

func TestGroups(t *testing.T) {
	s := newTestServerWith(t, func(st *state.State) {
		st.Devices = []state.Device{{ID: "d1", Name: "téléphone", TokenHash: policy.HashToken("jetonsecret")}}
		st.Groups = []state.Group{
			{ID: "kids", Name: "Enfants", Blocking: true, InheritLists: true, InheritRules: false,
				Clients: []string{"127.0.0.2", "device:d1"}, Services: []string{"tiktok"}, SafeSearch: true,
				Rules: []state.Rule{{Domain: "normal.example"}}},
			{ID: "srv", Name: "Serveurs", Blocking: false, Clients: []string{"127.0.0.3"}},
		}
	})
	const kid, srv = "127.0.0.2", "127.0.0.3"
	if r := ask(s, "www.tiktok.com.", dns.TypeA, kid, false); r.Answer == nil || !r.Answer[0].(*dns.A).A.Equal(net.IPv4zero) {
		t.Fatalf("service bloqué attendu : %v", r)
	}
	if r := ask(s, "normal.example.", dns.TypeA, kid, false); !r.Answer[0].(*dns.A).A.Equal(net.IPv4zero) {
		t.Fatal("règle du groupe attendue")
	}
	// Le groupe ne reprend pas « Ma liste » générale : ads.example passe.
	if r := ask(s, "banner.ads.example.", dns.TypeA, kid, false); r.Rcode != dns.RcodeNameError {
		t.Fatalf("« Ma liste » ne doit pas s'appliquer au groupe : %v", r)
	}
	if r := ask(s, "banner.ads.example.", dns.TypeA, srv, false); r.Rcode != dns.RcodeNameError {
		t.Fatal("groupe sans filtrage : rien n'est bloqué")
	}
	if r := ask(s, "banner.ads.example.", dns.TypeA, "127.0.0.1", false); r.Rcode != dns.RcodeSuccess {
		t.Fatal("politique générale inchangée hors groupe")
	}
	r := ask(s, "www.google.fr.", dns.TypeA, kid, false)
	if len(r.Answer) != 2 || r.Answer[0].(*dns.CNAME).Target != "forcesafesearch.google.com." {
		t.Fatalf("SafeSearch attendu : %v", r)
	}
	// Jeton d'appareil : servi hors ACL, avec la politique de son groupe.
	m := new(dns.Msg)
	m.SetQuestion("www.tiktok.com.", dns.TypeA)
	r = s.Handle(WithDevice(context.Background(), "jetonsecret"), m, netip.MustParseAddr("198.51.100.7"), "doh")
	if r == nil || len(r.Answer) != 1 || !r.Answer[0].(*dns.A).A.Equal(net.IPv4zero) || s.DeviceSeen("d1").IsZero() {
		t.Fatalf("appareil identifié attendu : %v", r)
	}
	m.SetQuestion("normal.example.", dns.TypeA)
	if r = s.Handle(WithDevice(context.Background(), "mauvais"), m, netip.MustParseAddr("198.51.100.7"), "doh"); r.Rcode != dns.RcodeRefused {
		t.Fatal("jeton inconnu hors ACL : refus attendu")
	}
	// Admis par jeton hors réseau : pas de zone interne.
	m.SetQuestion("nas.maison.lan.", dns.TypeA)
	if r = s.Handle(WithDevice(context.Background(), "jetonsecret"), m, netip.MustParseAddr("198.51.100.7"), "doh"); r.Rcode != dns.RcodeRefused {
		t.Fatalf("zone interne servie hors réseau : %v", r)
	}
	// Jeton lu dans le SNI (DoT) : identifie, mais n'ouvre pas l'accès.
	m.SetQuestion("normal.example.", dns.TypeA)
	if r = s.Handle(withSNIDevice(context.Background(), "jetonsecret"), m, netip.MustParseAddr("198.51.100.7"), "dot"); r.Rcode != dns.RcodeRefused {
		t.Fatal("le jeton SNI ne doit pas franchir l'ACL")
	}
	m.SetQuestion("www.tiktok.com.", dns.TypeA)
	if r = s.Handle(withSNIDevice(context.Background(), "jetonsecret"), m, netip.MustParseAddr("127.0.0.9"), "dot"); !r.Answer[0].(*dns.A).A.Equal(net.IPv4zero) {
		t.Fatal("le jeton SNI identifie l'appareil dans le réseau")
	}
}

// Les catégories d'un groupe restent actives quand son filtrage est en pause.
func TestCategoriesSurvivePause(t *testing.T) {
	list := filepath.Join(t.TempDir(), "adult.txt")
	if err := os.WriteFile(list, []byte("adulte.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestServerWith(t, func(st *state.State) {
		st.Lists = []state.List{{ID: "cat-adult", Name: "Adultes", URL: list}}
		st.Groups = []state.Group{{ID: "k", Name: "Enfants", Blocking: true, Lists: []string{"cat-adult"},
			Clients: []string{"127.0.0.2"}, PausedUntil: time.Now().Add(time.Hour)}}
	})
	s.Blocker.Rebuild()
	if r := ask(s, "www.adulte.example.", dns.TypeA, "127.0.0.2", false); r.Answer == nil || !r.Answer[0].(*dns.A).A.Equal(net.IPv4zero) {
		t.Fatalf("catégorie non appliquée pendant la pause : %v", r)
	}
	if r := ask(s, "www.adulte.example.", dns.TypeA, "127.0.0.1", false); r.Rcode != dns.RcodeNameError {
		t.Fatal("la catégorie ne concerne que son groupe")
	}
}

// Une réponse mise en cache pour un client non filtré ne contourne pas le
// démasquage CNAME pour les autres.
func TestCacheReplaysCNAMECheck(t *testing.T) {
	s := newTestServerWith(t, func(st *state.State) {
		st.Groups = []state.Group{{ID: "srv", Name: "Serveurs", Blocking: false, Clients: []string{"127.0.0.3"}}}
	})
	if r := ask(s, "metrics.shop.example.", dns.TypeA, "127.0.0.3", false); len(r.Answer) != 2 {
		t.Fatalf("groupe non filtré : réponse complète attendue : %v", r)
	}
	if r := ask(s, "metrics.shop.example.", dns.TypeA, "127.0.0.1", false); !r.Answer[0].(*dns.A).A.Equal(net.IPv4zero) {
		t.Fatalf("CNAME cloaking contourné par le cache : %v", r)
	}
}

func TestRPZ(t *testing.T) {
	zone := "$TTL 60\n@ SOA localhost. root.localhost. 1 3600 600 86400 60\n" +
		"ads.example CNAME rpz-passthru.\nbanner.ads.example CNAME .\nlocal.example A 10.9.9.9\n" +
		"32.34.216.184.93.rpz-ip CNAME .\n32.9.0.0.10.rpz-client-ip CNAME rpz-drop.\nns1.badhost.example.rpz-nsdname CNAME .\n"
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(zone)) }))
	defer ts.Close()
	s := newTestServer(t)
	e := &rpz.Engine{KS: testutil.Keystore(t), DataDir: t.TempDir(), Log: testutil.Logger(), Client: ts.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Reconcile(ctx, state.State{RPZ: []state.RPZFeed{{ID: "a", Name: "Éditeur", Zone: "rpz.test", Source: "https", URL: ts.URL, Enabled: true}}})
	for i := 0; i < 100 && e.MatchName("banner.ads.example.") == nil; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	s.RPZ = e
	s.SetSettings(state.State{Settings: state.Settings{BlockingEnabled: false, BlockingMode: "zero"}})
	if r := ask(s, "banner.ads.example.", dns.TypeA, "127.0.0.1", false); r.Rcode != dns.RcodeNameError {
		t.Fatalf("RPZ NXDOMAIN attendu, filtrage désactivé ou non : %v", r)
	}
	if r := ask(s, "local.example.", dns.TypeA, "127.0.0.1", false); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "10.9.9.9" {
		t.Fatalf("données locales RPZ : %v", r)
	}
	if r := ask(s, "normal.example.", dns.TypeA, "127.0.0.1", false); r.Rcode != dns.RcodeNameError {
		t.Fatalf("déclencheur d'adresse : %v", r)
	}
	// En cache aussi.
	if r := ask(s, "normal.example.", dns.TypeA, "127.0.0.1", false); r.Rcode != dns.RcodeNameError {
		t.Fatalf("déclencheur d'adresse sur le cache : %v", r)
	}
	// rpz-client-ip : requête abandonnée pour ce client seulement.
	if r := ask(s, "printer.lan.", dns.TypeA, "10.0.0.9", false); r != nil {
		t.Fatalf("rpz-client-ip : requête abandonnée attendue : %v", r)
	}
	if r := ask(s, "printer.lan.", dns.TypeA, "10.0.0.8", false); r == nil || len(r.Answer) != 1 {
		t.Fatalf("autre client : %v", r)
	}
	// rpz-nsdname : le domaine est servi par un serveur de noms listé.
	if r := ask(s, "www.evil.example.", dns.TypeA, "127.0.0.1", false); r.Rcode != dns.RcodeNameError {
		t.Fatalf("rpz-nsdname : %v", r)
	}
}
