package dhcp

import (
	"encoding/binary"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

func request(typ byte, mac string, ciaddr string, opts map[byte][]byte) []byte {
	b := make([]byte, minLen)
	b[0], b[1], b[2] = 1, 1, 6
	binary.BigEndian.PutUint32(b[4:8], 0xdeadbeef)
	copy(b[12:16], netip.MustParseAddr(ciaddr).AsSlice())
	hw, _ := net.ParseMAC(mac)
	copy(b[28:], hw)
	copy(b[headerLen:], magicCookie[:])
	b = append(b, optMsgType, 1, typ)
	for k, v := range opts {
		b = append(b, k, byte(len(v)))
		b = append(b, v...)
	}
	return append(b, optEnd)
}

func ip4(s string) []byte { return netip.MustParseAddr(s).AsSlice() }

func decode(t *testing.T, b []byte) (byte, netip.Addr, map[byte][]byte) {
	t.Helper()
	if b == nil {
		t.Fatal("réponse attendue")
	}
	b2 := append([]byte{}, b...)
	b2[0] = 1 // relire avec le même décodeur
	p, err := Parse(b2)
	if err != nil {
		t.Fatal(err)
	}
	return p.Type(), p.YIAddr, p.Options
}

func newTestServer(t *testing.T) *Server {
	ks := testutil.Keystore(t)
	path := filepath.Join(t.TempDir(), "dhcp-leases.sealed")
	s, err := New(ks, path, testutil.Logger())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Compile(state.DHCPConfig{Interface: "eth0", ServerIP: "192.168.1.2", Netmask: "255.255.255.0", RangeStart: "192.168.1.100",
		RangeEnd: "192.168.1.102", Router: "192.168.1.1", LeaseHours: 12, Domain: "lan",
		Static: []state.StaticLease{{MAC: "02:00:00:00:00:99", IP: "192.168.1.50", Hostname: "nas"}}}, []string{"maison.lan."})
	if err == nil {
		t.Fatal("le domaine recouvre une zone locale : refus attendu")
	}
	cfg, err = Compile(state.DHCPConfig{Interface: "eth0", ServerIP: "192.168.1.2", Netmask: "255.255.255.0", RangeStart: "192.168.1.100",
		RangeEnd: "192.168.1.102", Router: "192.168.1.1", LeaseHours: 12, Domain: "lan",
		Static: []state.StaticLease{{MAC: "02:00:00:00:00:99", IP: "192.168.1.50", Hostname: "nas"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.cfg.Store(cfg) // sans socket : Handle est appelé directement
	return s
}

func TestDORA(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	const mac = "02:00:00:00:00:01"
	p, _ := Parse(request(Discover, mac, "0.0.0.0", map[byte][]byte{optHostname: []byte("Tablette de Léa")}))
	out, dst := s.Handle(p, now)
	typ, yi, opts := decode(t, out)
	if typ != Offer || yi != netip.MustParseAddr("192.168.1.100") || dst.Port != 68 || !dst.IP.Equal(net.IPv4bcast) {
		t.Fatalf("OFFER inattendue : %d %s %v", typ, yi, dst)
	}
	if string(opts[optDNS]) != string(ip4("192.168.1.2")) || string(opts[optDomainName]) != "lan" || binary.BigEndian.Uint32(opts[optLeaseTime]) != 12*3600 {
		t.Fatalf("options : %v", opts)
	}
	// Un autre appareil ne reçoit pas l'adresse réservée par l'offre.
	p2, _ := Parse(request(Discover, "02:00:00:00:00:02", "0.0.0.0", nil))
	if _, yi2, _ := decode(t, first(s.Handle(p2, now))); yi2 == yi {
		t.Fatal("adresse offerte deux fois")
	}
	p, _ = Parse(request(Request, mac, "0.0.0.0", map[byte][]byte{optServerID: ip4("192.168.1.2"), optRequested: yi.AsSlice(), optHostname: []byte("Tablette de Léa")}))
	if typ, yi3, _ := decode(t, first(s.Handle(p, now))); typ != Ack || yi3 != yi {
		t.Fatal("ACK attendu")
	}
	r, ok := s.Answer(dns.Question{Name: "tablette-de-la.lan.", Qtype: dns.TypeA})
	if !ok || len(r) != 1 || r[0].(*dns.A).A.String() != "192.168.1.100" {
		t.Fatalf("nom d'appareil : %v", r)
	}
	if r, ok := s.Answer(dns.Question{Name: "100.1.168.192.in-addr.arpa.", Qtype: dns.TypePTR}); !ok || r[0].(*dns.PTR).Ptr != "tablette-de-la.lan." {
		t.Fatalf("PTR : %v", r)
	}
	if r, ok := s.Answer(dns.Question{Name: "inconnu.lan.", Qtype: dns.TypeA}); !ok || r != nil {
		t.Fatal("NXDOMAIN attendu")
	}
	if r, _ := s.Answer(dns.Question{Name: "nas.lan.", Qtype: dns.TypeA}); len(r) != 1 || r[0].(*dns.A).A.String() != "192.168.1.50" {
		t.Fatal("bail statique nommé")
	}
	if s.MAC(yi) != mac {
		t.Fatal("MAC d'après le bail")
	}
	// Renouvellement (ciaddr renseigné) : réponse en unicast.
	p, _ = Parse(request(Request, mac, yi.String(), nil))
	if out, dst := s.Handle(p, now.Add(6*time.Hour)); out == nil || !dst.IP.Equal(yi.AsSlice()) {
		t.Fatal("renouvellement en unicast attendu")
	}
	// Une adresse détenue par un autre appareil est refusée (NAK).
	p, _ = Parse(request(Request, "02:00:00:00:00:03", "0.0.0.0", map[byte][]byte{optRequested: yi.AsSlice()}))
	if typ, _, _ := decode(t, first(s.Handle(p, now))); typ != Nak {
		t.Fatal("NAK attendu")
	}
	// Bail statique : l'appareil réservé reçoit son adresse, hors plage.
	p, _ = Parse(request(Discover, "02:00:00:00:00:99", "0.0.0.0", nil))
	if _, y, _ := decode(t, first(s.Handle(p, now))); y.String() != "192.168.1.50" {
		t.Fatal("bail statique")
	}
	// Persistance scellée (écriture différée : forcée ici).
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	s2, err := New(s.ks, s.path, testutil.Logger())
	if err != nil || len(s2.leases) != 1 {
		t.Fatalf("baux non relus : %v %d", err, len(s2.leases))
	}
	// Plage épuisée : plus d'offre.
	s.cfg.Load().End = netip.MustParseAddr("192.168.1.100")
	p, _ = Parse(request(Discover, "02:00:00:00:00:04", "0.0.0.0", nil))
	if out, _ := s.Handle(p, now); out != nil {
		t.Fatal("aucune offre attendue")
	}
}

func first(b []byte, _ *net.UDPAddr) []byte { return b }

func TestParseRejects(t *testing.T) {
	ok := request(Discover, "02:00:00:00:00:01", "0.0.0.0", nil)
	if _, err := Parse(ok); err != nil {
		t.Fatal(err)
	}
	bad := [][]byte{ok[:100], append(append([]byte{}, ok[:len(ok)-1]...), 12, 200, 1)}
	reply := append([]byte{}, ok...)
	reply[0] = 2
	bad = append(bad, reply)
	for i, b := range bad {
		if _, err := Parse(b); err == nil {
			t.Errorf("message %d accepté", i)
		}
	}
	if sanitizeHost("  iPhone_de.Paul ") != "iphone-de" || sanitizeHost("---") != "" {
		t.Fatal("nom d'appareil mal nettoyé")
	}
}

func TestDHCPAbuse(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	ack := func(mac, ip, host string) byte {
		opts := map[byte][]byte{optRequested: ip4(ip)}
		if host != "" {
			opts[optHostname] = []byte(host)
		}
		p, _ := Parse(request(Request, mac, "0.0.0.0", opts))
		out, _ := s.Handle(p, now)
		if out == nil {
			return 0
		}
		typ, _, _ := decode(t, out)
		return typ
	}
	if ack("02:00:00:00:00:01", "192.168.1.100", "imprimante") != Ack {
		t.Fatal("ACK attendu")
	}
	// Un second appareil ne vole pas le nom, ni wpad.
	if ack("02:00:00:00:00:02", "192.168.1.101", "imprimante") != Ack || ack("02:00:00:00:00:03", "192.168.1.102", "wpad") != Ack {
		t.Fatal("ACK attendus")
	}
	if r, _ := s.Answer(dns.Question{Name: "imprimante.lan.", Qtype: dns.TypeA}); r[0].(*dns.A).A.String() != "192.168.1.100" {
		t.Fatal("nom volé")
	}
	if r, _ := s.Answer(dns.Question{Name: "wpad.lan.", Qtype: dns.TypeA}); r != nil {
		t.Fatal("wpad ne doit jamais être servi")
	}
	// DECLINE d'un tiers : ignoré.
	p, _ := Parse(request(Decline, "02:00:00:00:00:09", "0.0.0.0", map[byte][]byte{optRequested: ip4("192.168.1.100")}))
	s.Handle(p, now)
	p, _ = Parse(request(Request, "02:00:00:00:00:01", "192.168.1.100", nil))
	if out, _ := s.Handle(p, now); out == nil {
		t.Fatal("le renouvellement doit réussir malgré le DECLINE d'un tiers")
	}
	// REQUEST/RELEASE à MAC aléatoires : la table reste bornée.
	for i := 0; i < 500; i++ {
		mac := net.HardwareAddr{0x02, 1, 0, 0, byte(i >> 8), byte(i)}.String()
		s.Handle(must(Parse(request(Request, mac, "0.0.0.0", map[byte][]byte{optRequested: ip4("192.168.1.102")}))), now)
		s.Handle(must(Parse(request(Release, mac, "192.168.1.102", nil))), now)
	}
	if n := len(s.leases); n > 2*3+1 {
		t.Fatalf("table des baux non bornée : %d", n)
	}
	// Relais : ignoré.
	b := request(Discover, "02:00:00:00:00:05", "0.0.0.0", nil)
	copy(b[24:28], ip4("203.0.113.9"))
	if out, _ := s.Handle(must(Parse(b)), now); out != nil {
		t.Fatal("message relayé : aucune réponse attendue")
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
}

func must(p *Packet, err error) *Packet {
	if err != nil {
		panic(err)
	}
	return p
}
