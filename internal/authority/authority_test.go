package authority_test

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/authority"
	"github.com/rempart-dns/rempart/internal/blocker"
	"github.com/rempart-dns/rempart/internal/cache"
	"github.com/rempart-dns/rempart/internal/querylog"
	"github.com/rempart-dns/rempart/internal/server"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
	"github.com/rempart-dns/rempart/internal/tsig"
	"github.com/rempart-dns/rempart/internal/zones"
)

type node struct {
	addr  string
	store *state.Store
	zm    *zones.Manager
	auth  *authority.Authority
	prov  *tsig.Provider
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

func newNode(t *testing.T, st state.State) *node {
	ks := testutil.Keystore(t)
	dir := t.TempDir()
	store, _, err := state.Open(ks, filepath.Join(dir, "state.sealed"), st)
	if err != nil {
		t.Fatal(err)
	}
	prov := tsig.NewProvider()
	prov.Set(store.Get().TSIGKeys)
	zm := zones.NewManager(ks, testutil.Logger())
	au := &authority.Authority{Store: store, Zones: zm, Prov: prov, KS: ks, DataDir: dir, Log: testutil.Logger(), Record: func(string, string, string) {}}
	zm.OnLoad = au.NotifyAll
	if err := zm.Load(store.Get().Zones); err != nil {
		t.Fatal(err)
	}
	eng, _ := blocker.New(store, dir, nil, testutil.Logger())
	ql, _ := querylog.New(ks, dir, testutil.Logger())
	t.Cleanup(ql.Flush)
	srv := &server.Server{Zones: zm, Blocker: eng, Cache: cache.New(100, 0, time.Hour), Log: ql, Logger: testutil.Logger(),
		ACL: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Limiter: server.NewLimiter(1000, 1000), TSIG: prov, Authority: au}
	srv.SetSettings(store.Get())
	addr := freeAddr(t)
	if err := srv.ListenDNS(addr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	return &node{addr, store, zm, au, prov}
}

func TestTransferNotifyUpdate(t *testing.T) {
	xfr, _ := tsig.NewKey("xfr.maison.lan", "hmac-sha256")
	upd, _ := tsig.NewKey("dhcp.maison.lan", "hmac-sha512")
	other, _ := tsig.NewKey("xfr.maison.lan", "hmac-sha256") // même nom, autre secret
	// Le secondaire écoute d'abord : son adresse est déclarée chez le primaire.
	sec := newNode(t, state.State{TSIGKeys: []state.TSIGKey{xfr}})
	pri := newNode(t, state.State{
		TSIGKeys: []state.TSIGKey{xfr, upd},
		Zones: []state.Zone{{Name: "maison.lan.", DNSSEC: true, Records: []string{"nas IN A 192.168.1.10"},
			Transfer: state.ZoneTransfer{Secondaries: []string{sec.addr}, Key: "xfr.maison.lan", UpdateKey: "dhcp.maison.lan", UpdateFrom: []string{"127.0.0.0/8"}}}},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// AXFR : refusé sans TSIG, ou avec un mauvais secret.
	m := new(dns.Msg)
	m.SetAxfr("maison.lan.")
	if _, err := (&dns.Transfer{}).In(m, pri.addr); err == nil {
		env, _ := (&dns.Transfer{}).In(m, pri.addr)
		for e := range env {
			if e.Error == nil && len(e.RR) > 0 {
				t.Fatal("AXFR servi sans signature")
			}
		}
	}
	if _, err := authority.Transfer(ctx, pri.addr, "maison.lan.", other); err == nil {
		t.Fatal("AXFR servi avec un mauvais secret")
	}
	rrs, err := authority.Transfer(ctx, pri.addr, "maison.lan.", xfr)
	if err != nil {
		t.Fatal(err)
	}
	z, err := zones.FromTransfer("maison.lan.", rrs)
	if err != nil || !z.DNSSEC {
		t.Fatalf("zone transférée : %v", err)
	}

	// Secondaire : configuration, transfert, réponses signées du primaire.
	if err := sec.store.Update(func(s *state.State) error {
		s.Secondaries = []state.SecondaryZone{{Name: "maison.lan", Primary: pri.addr, Key: "xfr.maison.lan"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sec.auth.Reconcile(ctx, sec.store.Get())
	waitFor(t, func() bool { return sec.zm.Find("nas.maison.lan.") != nil })
	q := new(dns.Msg)
	q.SetQuestion("nas.maison.lan.", dns.TypeA)
	q.SetEdns0(1232, true)
	r, _, err := (&dns.Client{}).Exchange(q, sec.addr)
	if err != nil || len(r.Answer) != 2 || !r.Authoritative {
		t.Fatalf("réponse du secondaire (A + RRSIG attendus) : %v %v", r, err)
	}
	serial := sec.zm.Find("maison.lan.").Serial()

	// Mise à jour dynamique signée, puis NOTIFY vers le secondaire.
	u := new(dns.Msg)
	u.SetUpdate("maison.lan.")
	rr, _ := dns.NewRR("pc-lea.maison.lan. 300 IN A 192.168.1.42")
	u.Insert([]dns.RR{rr})
	u.SetTsig(upd.Name, upd.Algorithm, 300, time.Now().Unix())
	c := &dns.Client{Net: "tcp", TsigProvider: pri.prov}
	// Message signé une fois, envoyé deux fois tel quel : le second est un rejeu.
	raw, _, err := dns.TsigGenerateWithProvider(u, pri.prov, "", false)
	if err != nil {
		t.Fatal(err)
	}
	send := func() *dns.Msg {
		conn, err := dns.Dial("tcp", pri.addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write(raw); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, dns.MaxMsgSize)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		r := new(dns.Msg)
		if err := r.Unpack(buf[:n]); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r = send(); r.Rcode != dns.RcodeSuccess {
		t.Fatalf("mise à jour : %v", r)
	}
	if got := pri.store.Get().Zones[0].Dynamic; len(got) != 1 {
		t.Fatalf("enregistrement dynamique non conservé : %v", got)
	}
	if r = send(); r.Rcode != dns.RcodeRefused {
		t.Fatalf("rejeu accepté : %v", r)
	}
	waitFor(t, func() bool {
		z := sec.zm.Find("pc-lea.maison.lan.")
		return z != nil && zones.SerialNewer(z.Serial(), serial) && z.Answer(q2("pc-lea.maison.lan."), false).Answer != nil
	})

	// Un nom de l'administrateur ne peut pas être modifié.
	u = new(dns.Msg)
	u.SetUpdate("maison.lan.")
	rr, _ = dns.NewRR("nas.maison.lan. 300 IN A 10.6.6.6")
	u.Insert([]dns.RR{rr})
	u.SetTsig(upd.Name, upd.Algorithm, 300, time.Now().Unix())
	if r, _, _ = c.Exchange(u, pri.addr); r == nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("modification d'un nom statique acceptée : %v", r)
	}
	// La clé de transfert ne permet pas de mettre à jour.
	u.SetTsig(xfr.Name, xfr.Algorithm, 300, time.Now().Unix())
	if r, _, _ = c.Exchange(u, pri.addr); r == nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("mise à jour avec la clé de transfert acceptée : %v", r)
	}
	// Prérequis : « le nom n'existe pas » échoue pour pc-lea.
	u = new(dns.Msg)
	u.SetUpdate("maison.lan.")
	pre, _ := dns.NewRR("pc-lea.maison.lan. 0 NONE ANY")
	u.Answer = []dns.RR{pre}
	rr, _ = dns.NewRR("pc-lea.maison.lan. 300 IN TXT \"x\"")
	u.Insert([]dns.RR{rr})
	u.SetTsig(upd.Name, upd.Algorithm, 300, time.Now().Unix())
	if r, _, _ = c.Exchange(u, pri.addr); r == nil || r.Rcode != dns.RcodeYXDomain {
		t.Fatalf("prérequis non respecté : %v", r)
	}
	// Suppression du RRset.
	u = new(dns.Msg)
	u.SetUpdate("maison.lan.")
	rr, _ = dns.NewRR("pc-lea.maison.lan. 300 IN A 192.168.1.42")
	u.RemoveRRset([]dns.RR{rr})
	u.SetTsig(upd.Name, upd.Algorithm, 300, time.Now().Unix())
	if r, _, _ = c.Exchange(u, pri.addr); r == nil || r.Rcode != dns.RcodeSuccess || len(pri.store.Get().Zones[0].Dynamic) != 0 {
		t.Fatalf("suppression : %v", r)
	}
}

func q2(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	return m
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("délai dépassé")
}
