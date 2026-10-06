package rpz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

const zoneText = `$TTL 300
@ SOA localhost. root.localhost. 42 3600 600 86400 60
@ NS localhost.
bad.example CNAME .
*.bad.example CNAME .
nodata.example CNAME *.
ok.bad.example CNAME rpz-passthru.
drop.example CNAME rpz-drop.
tcp.example CNAME rpz-tcp-only.
redir.example CNAME walled.garden.example.
local.example A 10.9.9.9
local.example TXT "bloqué"
32.66.2.0.192.rpz-ip CNAME .
48.zz.db8.2001.rpz-ip CNAME .
ns.example.rpz-nsdname CNAME .
*.evilns.example.rpz-nsdname CNAME rpz-drop.
24.0.113.0.203.rpz-nsip CNAME .
32.7.0.0.10.rpz-client-ip CNAME rpz-drop.
garbage.rpz-client-ip CNAME .
`

func TestParseAndMatch(t *testing.T) {
	p, _, err := parseText(state.RPZFeed{Name: "f", Zone: "rpz.test"}, []byte(zoneText))
	if err != nil {
		t.Fatal(err)
	}
	if p.Skipped != 1 {
		t.Fatalf("un déclencheur mal formé doit être ignoré et compté : %d", p.Skipped)
	}
	if !p.HasNS() {
		t.Fatal("déclencheurs NS absents")
	}
	if r := p.MatchNSName("NS.example."); r == nil || r.Action != NXDomain {
		t.Fatal("rpz-nsdname exact")
	}
	if r := p.MatchNSName("a.b.evilns.example"); r == nil || r.Action != Drop {
		t.Fatal("rpz-nsdname joker")
	}
	if p.MatchNSName("evilns.example.") != nil || p.MatchNSName("other.example.") != nil {
		t.Fatal("rpz-nsdname faux positif")
	}
	if p.MatchNSIP(netip.MustParseAddr("203.0.113.9")) == nil || p.MatchNSIP(netip.MustParseAddr("203.0.114.9")) != nil {
		t.Fatal("rpz-nsip")
	}
	if r := p.MatchClient(netip.MustParseAddr("::ffff:10.0.0.7")); r == nil || r.Action != Drop {
		t.Fatal("rpz-client-ip (adresse IPv4 mappée)")
	}
	if p.MatchClient(netip.MustParseAddr("10.0.0.8")) != nil {
		t.Fatal("rpz-client-ip faux positif")
	}
	cases := map[string]Action{"bad.example.": NXDomain, "x.y.bad.example.": NXDomain, "ok.bad.example.": Passthru,
		"nodata.example.": NoData, "drop.example.": Drop, "tcp.example.": TCPOnly, "redir.example.": Rewrite, "local.example.": Local}
	for n, want := range cases {
		r := p.MatchName(n)
		if r == nil || r.Action != want {
			t.Errorf("%s : %v, attendu %v", n, r, want)
		}
	}
	if p.MatchName("good.example.") != nil || p.MatchName("example.") != nil {
		t.Fatal("faux positif")
	}
	if r := p.MatchName("local.example."); len(r.Local) != 2 {
		t.Fatal("données locales")
	}
	if p.MatchIP(netip.MustParseAddr("192.0.2.66")) == nil || p.MatchIP(netip.MustParseAddr("192.0.2.67")) != nil {
		t.Fatal("déclencheur IPv4")
	}
	if p.MatchIP(netip.MustParseAddr("2001:db8::1")) == nil || p.MatchIP(netip.MustParseAddr("2001:db9::1")) != nil {
		t.Fatal("déclencheur IPv6")
	}
}

func TestHTTPSFeed(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte(zoneText))
	}))
	defer ts.Close()
	e := &Engine{KS: testutil.Keystore(t), DataDir: t.TempDir(), Log: testutil.Logger(), Client: ts.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := state.State{RPZ: []state.RPZFeed{{ID: "f1", Name: "Menaces", Zone: "rpz.test", Source: "https", URL: ts.URL, Enabled: true}}}
	e.Reconcile(ctx, st)
	for i := 0; i < 100 && e.MatchName("bad.example.") == nil; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	h := e.MatchName("bad.example.")
	if h == nil || h.Feed != "Menaces" {
		t.Fatal("flux HTTPS non appliqué")
	}
	m := new(dns.Msg)
	rr, _ := dns.NewRR("x.example. 60 IN A 192.0.2.66")
	m.Answer = []dns.RR{rr}
	if e.MatchResponse(m, 1<<30) == nil {
		t.Fatal("déclencheur d'adresse sur la réponse")
	}
	if e.MatchResponse(m, 0) != nil {
		t.Fatal("un PASSTHRU d'un flux prioritaire écarte les suivants")
	}
	// Un nom listé ne se cache pas derrière un CNAME.
	c, _ := dns.NewRR("innocent.example. 60 IN CNAME bad.example.")
	m.Answer = []dns.RR{c}
	if e.MatchResponse(m, 1<<30) == nil {
		t.Fatal("déclencheur QNAME sur la cible CNAME")
	}
	if _, _, err := parseText(st.RPZ[0], []byte("$GENERATE 1-65535 h$ CNAME .\n")); err == nil {
		t.Fatal("$GENERATE accepté")
	}
	// Copie scellée relue par une nouvelle instance, sans réseau.
	cancel()
	e2 := &Engine{KS: e.KS, DataDir: e.DataDir, Log: testutil.Logger(), Client: &http.Client{Timeout: time.Millisecond}}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	e2.Reconcile(ctx2, st)
	for i := 0; i < 100 && e2.MatchName("bad.example.") == nil; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if e2.MatchName("bad.example.") == nil {
		t.Fatal("copie locale non relue")
	}
	// Flux désactivé : plus aucune règle.
	st.RPZ[0].Enabled = false
	e2.Reconcile(ctx2, st)
	if e2.MatchName("bad.example.") != nil {
		t.Fatal("flux désactivé encore appliqué")
	}
}

func TestEngineQueryAndNS(t *testing.T) {
	a, _, _ := parseText(state.RPZFeed{Name: "a", Zone: "a.rpz"}, []byte("$TTL 300\n@ SOA l. r. 1 1 1 1 1\n32.5.0.0.10.rpz-client-ip CNAME rpz-drop.\nns1.evil.example.rpz-nsdname CNAME .\n"))
	b, _, _ := parseText(state.RPZFeed{Name: "b", Zone: "b.rpz"}, []byte("$TTL 300\n@ SOA l. r. 1 1 1 1 1\nwww.example CNAME rpz-passthru.\n32.9.113.0.203.rpz-nsip CNAME .\n"))
	e := &Engine{}
	ps := []*Policy{a, b}
	e.pols.Store(&ps)
	if h := e.MatchQuery("www.example.", netip.MustParseAddr("10.0.0.5")); h == nil || h.Feed != a.Feed || h.Rule.Action != Drop {
		t.Fatalf("client-ip du premier flux prioritaire : %+v", h)
	}
	if h := e.MatchQuery("www.example.", netip.MustParseAddr("10.0.0.6")); h == nil || h.Rule.Action != Passthru {
		t.Fatalf("QNAME du second flux : %+v", h)
	}
	calls := 0
	lookup := func(_ context.Context, q string, addrs bool) ([]string, []netip.Addr) {
		calls++
		if q == "x.evil.example." {
			return []string{"ns1.evil.example."}, nil
		}
		if !addrs {
			return []string{"ns.ok.example."}, nil
		}
		return []string{"ns.ok.example."}, []netip.Addr{netip.MustParseAddr("203.0.113.9")}
	}
	if h := e.MatchNS(context.Background(), "x.evil.example.", 99, lookup); h == nil || h.Feed != a.Feed {
		t.Fatalf("rpz-nsdname : %+v", h)
	}
	if h := e.MatchNS(context.Background(), "y.other.example.", 99, lookup); h == nil || h.Feed != b.Feed {
		t.Fatalf("rpz-nsip : %+v", h)
	}
	// Un PASSTHRU du premier flux (limit 1) écarte le second.
	if h := e.MatchNS(context.Background(), "y.other.example.", 1, lookup); h != nil {
		t.Fatalf("limite de rang ignorée : %+v", h)
	}
	// Sans déclencheur NS, aucune requête supplémentaire.
	only := []*Policy{b}
	b2, _, _ := parseText(state.RPZFeed{Name: "c", Zone: "c.rpz"}, []byte("$TTL 300\n@ SOA l. r. 1 1 1 1 1\nbad.example CNAME .\n"))
	only[0] = b2
	e.pols.Store(&only)
	before := calls
	e.MatchNS(context.Background(), "z.example.", 99, lookup)
	if calls != before {
		t.Fatal("recherche des serveurs de noms sans déclencheur NS")
	}
}
