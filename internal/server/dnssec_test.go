package server

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/dnssec"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
	"github.com/rempart-dns/rempart/internal/zones"
)

// signedUpstream : résolveur en amont qui sert une zone signée « test. »,
// éventuellement falsifiée.
type signedUpstream struct {
	z      *zones.Zone
	forged atomic.Bool
	sawCD  atomic.Bool
}

func (u *signedUpstream) Exchange(_ context.Context, q *dns.Msg) (*dns.Msg, string, error) {
	if q.CheckingDisabled {
		u.sawCD.Store(true)
	}
	r := u.z.Answer(q, true)
	r.Authoritative = false
	r.AuthenticatedData = true // un amont menteur prétend avoir validé
	if u.forged.Load() && q.Question[0].Qtype == dns.TypeA {
		for _, rr := range r.Answer {
			if a, ok := rr.(*dns.A); ok {
				a.A = net.IPv4(6, 6, 6, 6)
			}
		}
	}
	return r, "amont", nil
}

func dnssecServer(t *testing.T) (*Server, *signedUpstream) {
	s := newTestServer(t)
	z, err := zones.Build(testutil.Keystore(t), state.Zone{Name: "test.", DNSSEC: true, Algorithm: "ECDSAP256", Records: []string{"www IN A 192.0.2.1"}})
	if err != nil {
		t.Fatal(err)
	}
	up := &signedUpstream{z: z}
	v, err := dnssec.New(up, z.DS())
	if err != nil {
		t.Fatal(err)
	}
	s.Upstreams, s.Validator = up, v
	return s, up
}

func askFlags(s *Server, name string, do, ad, cd bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.SetEdns0(1232, do)
	m.AuthenticatedData, m.CheckingDisabled = ad, cd
	return s.Handle(context.Background(), m, netip.MustParseAddr("127.0.0.1"), "udp")
}

func TestLocalValidation(t *testing.T) {
	s, up := dnssecServer(t)
	r := askFlags(s, "www.test.", true, false, false)
	if r.Rcode != dns.RcodeSuccess || !r.AuthenticatedData || len(r.Answer) != 2 {
		t.Fatalf("réponse validée attendue (AD, A + RRSIG) : %v", r)
	}
	if !up.sawCD.Load() {
		t.Fatal("la validation doit être demandée sans la déléguer (CD en amont)")
	}
	// Client sans DO ni AD : ni signatures ni bit AD (RFC 6840 §5.8), depuis le cache.
	r = askFlags(s, "www.test.", false, false, false)
	if r.AuthenticatedData || len(r.Answer) != 1 {
		t.Fatalf("client sans DO : %v", r)
	}
	if r = askFlags(s, "www.test.", false, true, false); !r.AuthenticatedData {
		t.Fatal("client AD : bit AD attendu")
	}
	// Domaine inexistant : NXDOMAIN validé.
	if r = askFlags(s, "nx.test.", true, false, false); r.Rcode != dns.RcodeNameError || !r.AuthenticatedData {
		t.Fatalf("NXDOMAIN validé attendu : %v", r)
	}
	// Hors de l'ancre (domaine non signé) : servi sans AD malgré l'amont.
	if r = askFlags(s, "normal.example.", true, false, false); r.AuthenticatedData {
		t.Fatal("bit AD de l'amont recopié sans validation")
	}
}

func TestBogusRefused(t *testing.T) {
	s, up := dnssecServer(t)
	up.forged.Store(true)
	// Un client CD reçoit la réponse brute, sans AD, et elle n'est pas mise en cache.
	if r := askFlags(s, "www.test.", true, false, true); r.Rcode != dns.RcodeSuccess || r.AuthenticatedData {
		t.Fatalf("client CD : %v", r)
	}
	r := askFlags(s, "www.test.", true, false, false)
	if r.Rcode != dns.RcodeServerFailure {
		t.Fatalf("réponse falsifiée servie : %v", r)
	}
	var ede *dns.EDNS0_EDE
	for _, o := range r.IsEdns0().Option {
		if e, ok := o.(*dns.EDNS0_EDE); ok {
			ede = e
		}
	}
	if ede == nil || ede.InfoCode != dns.ExtendedErrorCodeDNSBogus {
		t.Fatalf("erreur étendue DNSSEC Bogus absente : %v", r)
	}
	// Validation coupée : la réponse passe (validation laissée à l'amont).
	st := s.Settings().Settings
	st.DNSSECValidationOff = true
	s.SetSettings(state.State{Settings: st})
	if r := askFlags(s, "www.test.", true, false, false); r.Rcode != dns.RcodeSuccess {
		t.Fatalf("validation coupée : %v", r)
	}
}
