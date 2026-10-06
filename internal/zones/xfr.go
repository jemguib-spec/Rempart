package zones

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Serial renvoie le numéro de série en service.
func (z *Zone) Serial() uint32 { return z.soa.Serial }

// SOA renvoie une copie de l'enregistrement SOA.
func (z *Zone) SOA() *dns.SOA { return dns.Copy(z.soa).(*dns.SOA) }

// AXFR renvoie la zone complète dans l'ordre d'un transfert (RFC 5936) :
// SOA, ses signatures, tous les autres enregistrements et leurs signatures
// en ordre canonique, puis le SOA à nouveau.
func (z *Zone) AXFR() []dns.RR {
	out := []dns.RR{dns.Copy(z.soa)}
	for _, s := range z.sigs[z.Origin][dns.TypeSOA] {
		out = append(out, dns.Copy(s))
	}
	for _, name := range z.names {
		for t, rrs := range z.nodes[name] {
			if name == z.Origin && t == dns.TypeSOA {
				continue
			}
			for _, rr := range rrs {
				out = append(out, dns.Copy(rr))
			}
			for _, s := range z.sigs[name][t] {
				out = append(out, dns.Copy(s))
			}
		}
	}
	if z.n3 != nil {
		for _, o := range z.n3.owners {
			out = append(out, dns.Copy(z.n3.recs[o]))
			for _, s := range z.sigs[o][dns.TypeNSEC3] {
				out = append(out, dns.Copy(s))
			}
		}
	}
	return append(out, dns.Copy(z.soa))
}

// FromTransfer construit une zone secondaire à partir d'un AXFR reçu. Les
// enregistrements hors de la zone sont refusés ; les signatures sont gardées
// telles quelles (la zone reste signée par le primaire).
func FromTransfer(origin string, rrs []dns.RR) (*Zone, error) {
	origin = strings.ToLower(dns.Fqdn(origin))
	if len(rrs) < 2 {
		return nil, errors.New("transfert vide")
	}
	soa, ok := rrs[0].(*dns.SOA)
	if !ok || strings.ToLower(soa.Hdr.Name) != origin {
		return nil, errors.New("le transfert ne commence pas par le SOA de la zone")
	}
	z := &Zone{Origin: origin, nodes: map[string]rrsets{}, sigs: map[string]rrsets{}, soa: soa}
	var expires uint32
	for i, rr := range rrs {
		h := rr.Header()
		h.Name = strings.ToLower(h.Name)
		if !dns.IsSubDomain(origin, h.Name) {
			return nil, fmt.Errorf("enregistrement hors zone : %s", h.Name)
		}
		if h.Rrtype == dns.TypeSOA && i > 0 {
			continue // SOA de fin de transfert
		}
		if sig, ok := rr.(*dns.RRSIG); ok {
			if z.sigs[h.Name] == nil {
				z.sigs[h.Name] = rrsets{}
			}
			z.sigs[h.Name][sig.TypeCovered] = append(z.sigs[h.Name][sig.TypeCovered], sig)
			if expires == 0 || sig.Expiration < expires {
				expires = sig.Expiration
			}
			continue
		}
		if z.nodes[h.Name] == nil {
			z.nodes[h.Name] = rrsets{}
		}
		z.nodes[h.Name][h.Rrtype] = append(z.nodes[h.Name][h.Rrtype], rr)
		z.MaxTTL = max(z.MaxTTL, time.Duration(h.Ttl)*time.Second)
	}
	z.DNSSEC = len(z.nodes[origin][dns.TypeDNSKEY]) > 0
	if expires > 0 {
		z.Expires = time.Unix(int64(expires), 0).UTC()
	}
	z.SignedAt = time.Now().UTC()
	z.fromTransferNSEC3()
	z.sortNames()
	return z, nil
}

// SerialNewer compare deux numéros de série selon RFC 1982.
func SerialNewer(a, b uint32) bool { return a != b && int32(a-b) > 0 }

// NextSerial renvoie le numéro de série d'une zone modifiée : l'heure Unix,
// ou le précédent plus un si deux modifications tombent dans la même seconde
// (sinon les secondaires manqueraient la seconde).
func NextSerial(prev uint32) uint32 {
	now := uint32(time.Now().Unix())
	if SerialNewer(now, prev) {
		return now
	}
	return prev + 1
}

// All renvoie les zones primaires chargées.
func (m *Manager) All() []*Zone {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Zone, 0, len(m.z))
	for _, z := range m.z {
		out = append(out, z)
	}
	return out
}
