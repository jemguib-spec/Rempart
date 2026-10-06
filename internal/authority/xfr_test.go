package authority_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/authority"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/tsig"
)

// Un pair qui connaît une autre clé de Rempart (éditeur RPZ, client de
// mises à jour) ne peut pas signer la réponse destinée à un autre primaire.
func TestTransferRejectsOtherKey(t *testing.T) {
	want, _ := tsig.NewKey("xfr-a.test", "hmac-sha256")
	other, _ := tsig.NewKey("rpz-b.test", "hmac-sha256")
	prov := tsig.NewProvider()
	prov.Set([]state.TSIGKey{want, other})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		soa, _ := dns.NewRR("z.test. 300 IN SOA ns.z.test. h.z.test. 7 3600 600 86400 300")
		a, _ := dns.NewRR("evil.z.test. 300 IN A 6.6.6.6")
		if r.Question[0].Qtype == dns.TypeSOA {
			m.Answer = []dns.RR{soa}
		} else {
			m.Answer = []dns.RR{soa, a, soa}
		}
		m.SetTsig(other.Name, other.Algorithm, 300, time.Now().Unix()) // mauvaise clé
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{Listener: ln, Handler: h, TsigProvider: prov}
	go srv.ActivateAndServe()
	defer srv.Shutdown()
	time.Sleep(100 * time.Millisecond)
	addr := ln.Addr().String()
	if _, err := authority.QuerySOA(addr, "z.test.", want); err == nil {
		t.Fatal("SOA signé par une autre clé accepté")
	}
	if _, err := authority.Transfer(context.Background(), addr, "z.test.", want); err == nil {
		t.Fatal("AXFR signé par une autre clé accepté")
	}
}
