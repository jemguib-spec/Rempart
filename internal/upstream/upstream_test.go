package upstream_test

import (
	"context"
	"crypto/x509"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/blocker"
	"github.com/rempart-dns/rempart/internal/cache"
	"github.com/rempart-dns/rempart/internal/querylog"
	"github.com/rempart-dns/rempart/internal/server"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
	"github.com/rempart-dns/rempart/internal/tlsutil"
	"github.com/rempart-dns/rempart/internal/upstream"
	"github.com/rempart-dns/rempart/internal/zones"
)

func freeAddr(t *testing.T) string {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	return l.Addr().String()
}

// TestEncryptedTransports runs Rempart's DoT and DoH servers and queries them
// with Rempart's own DoT and DoH clients (TLS key from the keystore).
func TestEncryptedTransports(t *testing.T) {
	ks := testutil.Keystore(t)
	dir := t.TempDir()
	st := state.State{Settings: state.Settings{LogMode: "none"}, Zones: []state.Zone{{Name: "maison.lan.", DNSSEC: true, Records: []string{"nas IN A 192.168.1.10"}}}}
	store, _, _ := state.Open(ks, filepath.Join(dir, "s"), st)
	zm := zones.NewManager(ks, testutil.Logger())
	if err := zm.Load(st.Zones); err != nil {
		t.Fatal(err)
	}
	eng, _ := blocker.New(store, dir, nil, testutil.Logger())
	ql, _ := querylog.New(ks, dir, testutil.Logger())
	dummy, _ := upstream.Parse("127.0.0.1:1", upstream.Options{})
	g, _ := upstream.NewGroup([]upstream.Upstream{dummy})
	srv := &server.Server{Zones: zm, Blocker: eng, Cache: cache.New(100, 0, time.Hour), Upstreams: g, Log: ql, Logger: testutil.Logger(),
		ACL: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Limiter: server.NewLimiter(0, 0)}
	srv.SetSettings(store.Get())

	tm, err := tlsutil.New(ks, tlsutil.Options{KeyLabel: "rempart-tls", SelfSignedNames: []string{"rempart.test", "127.0.0.1"}, DataDir: dir}, "selfsigned", nil, testutil.Logger())
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(tm.Leaf())
	tlsConf := tm.Config()

	// Écoutes démarrées par le contrôleur de production (Réglages → Chiffrement).
	dotAddr, dohAddr := freeAddr(t), freeAddr(t)
	enc := server.NewEncrypted(srv, tlsConf, dotAddr, dohAddr, "/dns-query", "")
	if err := enc.Apply(state.Encryption{}); err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	_, dohPort, _ := net.SplitHostPort(dohAddr)
	dohSpec := "https://rempart.test:" + dohPort + "/dns-query#127.0.0.1"
	dotSpec := "tls://" + dotAddr + "#rempart.test"

	for _, spec := range []string{dotSpec, dohSpec} {
		u, err := upstream.Parse(spec, upstream.Options{RootCAs: pool})
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ { // several queries: exercises connection reuse
			m := new(dns.Msg)
			m.SetQuestion("nas.maison.lan.", dns.TypeA)
			m.SetEdns0(1232, true)
			r, err := u.Exchange(context.Background(), m)
			if err != nil {
				t.Fatalf("%s: %v", spec, err)
			}
			if len(r.Answer) != 2 || !r.Authoritative {
				t.Fatalf("%s: réponse inattendue %v", spec, r)
			}
			opt := r.IsEdns0()
			padded := false
			for _, o := range opt.Option {
				if o.Option() == dns.EDNS0PADDING {
					padded = true
				}
			}
			r.Compress = true
			if !padded || r.Len()%468 != 0 {
				t.Fatalf("%s: réponse non paddée (taille %d)", spec, r.Len())
			}
		}
	}

	// Interrupteur à chaud : chaque vérification part d'un client neuf, pour
	// ne pas réutiliser une connexion ouverte avant l'arrêt.
	answers := func(spec string) bool {
		u, err := upstream.Parse(spec, upstream.Options{RootCAs: pool})
		if err != nil {
			t.Fatal(err)
		}
		m := new(dns.Msg)
		m.SetQuestion("nas.maison.lan.", dns.TypeA)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err = u.Exchange(ctx, m)
		return err == nil
	}
	if err := enc.Apply(state.Encryption{DoHDisabled: true}); err != nil {
		t.Fatal(err)
	}
	if answers(dohSpec) || !answers(dotSpec) {
		t.Fatal("DoH désactivé : DoH doit être fermé et DoT rester ouvert")
	}
	if st := enc.Status(); st.DoH.Running || st.DoH.Enabled || !st.DoT.Running {
		t.Fatalf("état inattendu %+v", st)
	}
	if err := enc.Apply(state.Encryption{DoTDisabled: true}); err != nil {
		t.Fatal(err)
	}
	if !answers(dohSpec) || answers(dotSpec) {
		t.Fatal("DoH réactivé et DoT désactivé : état des écoutes inattendu")
	}
	if l := enc.Listeners(); len(l) != 1 || l["doh "+dohAddr] == "" {
		t.Fatalf("écoutes affichées %v", l)
	}

	// Port occupé : erreur rendue et visible, sans arrêter le processus.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	enc2 := server.NewEncrypted(srv, tlsConf, "", busy.Addr().String(), "/dns-query", "")
	if err := enc2.Apply(state.Encryption{}); err == nil {
		t.Fatal("port occupé accepté")
	}
	if st := enc2.Status(); st.DoH.Running || st.DoH.Error == "" || st.DoT.Enabled {
		t.Fatalf("état inattendu %+v", st)
	}
}
