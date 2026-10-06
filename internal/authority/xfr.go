package authority

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/tsig"
)

// MaxTransferRRs borne un transfert reçu : une zone ou un flux RPZ plus
// gros (ou un primaire hostile) épuiserait la mémoire.
const MaxTransferRRs = 2_000_000

// counting compte les messages dont la signature TSIG a été vérifiée.
type counting struct {
	*tsig.Single
	n int
}

func (c *counting) Verify(msg []byte, t *dns.TSIG) error {
	err := c.Single.Verify(msg, t)
	if err == nil {
		c.n++
	}
	return err
}

// WithPort ajoute le port 53 à une adresse qui n'en a pas.
func WithPort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "53")
}

// Transfer récupère une zone par AXFR signé TSIG. Chaque message reçu doit
// porter une signature valide, et de la clé de la requête : un message non
// signé, ou signé d'une autre clé, fait échouer le transfert.
func Transfer(ctx context.Context, addr, zone string, key state.TSIGKey) ([]dns.RR, error) {
	cp := &counting{Single: tsig.NewSingle(key)}
	t := &dns.Transfer{TsigProvider: cp, DialTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 10 * time.Second}
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(zone))
	m.SetTsig(key.Name, key.Algorithm, 300, time.Now().Unix())
	ch, err := t.In(m, WithPort(addr))
	if err != nil {
		return nil, err
	}
	// Le contexte coupe aussi un pair qui enverrait un message toutes les
	// 29 secondes (le délai de lecture ne borne qu'un message).
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			if t.Conn != nil {
				_ = t.Conn.Close()
			}
		case <-done:
		}
	}()
	var rrs []dns.RR
	msgs := 0
	var ferr error
	for env := range ch {
		msgs++
		if env.Error != nil && ferr == nil {
			ferr = env.Error
		}
		if ferr == nil {
			rrs = append(rrs, env.RR...)
			if len(rrs) > MaxTransferRRs {
				ferr = errors.New("transfert trop volumineux")
			}
		}
		if ctx.Err() != nil && ferr == nil {
			ferr = ctx.Err()
		}
	}
	if ferr != nil {
		return nil, ferr
	}
	if cp.n != msgs {
		return nil, fmt.Errorf("transfert refusé : %d message(s) sur %d sans signature TSIG valide", msgs-cp.n, msgs)
	}
	return rrs, nil
}

// QuerySOA interroge le SOA d'une zone chez son primaire (réponse signée).
func QuerySOA(addr, zone string, key state.TSIGKey) (*dns.SOA, error) {
	c := &dns.Client{Net: "tcp", Timeout: 5 * time.Second, TsigProvider: tsig.NewSingle(key)}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	m.SetTsig(key.Name, key.Algorithm, 300, time.Now().Unix())
	r, _, err := c.Exchange(m, WithPort(addr))
	if err != nil {
		return nil, err
	}
	if ts := r.IsTsig(); ts == nil || tsig.CanonicalName(ts.Hdr.Name) != key.Name {
		return nil, errors.New("réponse SOA non signée par la clé attendue")
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("SOA : %s", dns.RcodeToString[r.Rcode])
	}
	for _, rr := range r.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa, nil
		}
	}
	return nil, errors.New("pas de SOA dans la réponse")
}

// SendNotify envoie un NOTIFY signé (RFC 1996), avec trois essais.
func SendNotify(addr, zone string, serial uint32, key state.TSIGKey) error {
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second, TsigProvider: tsig.NewSingle(key)}
	var err error
	for i := 0; i < 3; i++ {
		m := new(dns.Msg)
		m.SetNotify(dns.Fqdn(zone))
		m.Answer = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET}, Ns: ".", Mbox: ".", Serial: serial}}
		m.SetTsig(key.Name, key.Algorithm, 300, time.Now().Unix())
		var r *dns.Msg
		if r, _, err = c.Exchange(m, WithPort(addr)); err == nil {
			if r.Rcode != dns.RcodeSuccess {
				return fmt.Errorf("NOTIFY refusé : %s", dns.RcodeToString[r.Rcode])
			}
			return nil
		}
		time.Sleep(time.Duration(i+1) * time.Second)
	}
	return err
}
