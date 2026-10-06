// Package rpz applique des zones de politique de réponse (Response Policy
// Zones, format de BIND et de Knot Resolver) reçues des éditeurs de flux de
// menaces, par AXFR signé TSIG ou par HTTPS.
//
// Déclencheurs pris en charge, dans l'ordre de priorité d'une même zone :
// adresse du client (rpz-client-ip), QNAME (nom exact et « *. » pour les
// sous-domaines), adresse de réponse (rpz-ip), nom des serveurs de noms du
// domaine (rpz-nsdname) et leurs adresses (rpz-nsip). Les serveurs de noms
// sont trouvés par des requêtes NS aux résolveurs en amont, Rempart ne
// faisant pas de résolution itérative.
package rpz

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// Action d'une règle.
type Action int

const (
	NXDomain Action = iota // CNAME .
	NoData                 // CNAME *.
	Passthru               // CNAME rpz-passthru.
	Drop                   // CNAME rpz-drop.
	TCPOnly                // CNAME rpz-tcp-only.
	Rewrite                // CNAME vers un autre nom
	Local                  // données locales (A, AAAA, TXT…)
)

var actionNames = map[Action]string{NXDomain: "NXDOMAIN", NoData: "NODATA", Passthru: "PASSTHRU", Drop: "DROP", TCPOnly: "TCP-ONLY", Rewrite: "CNAME", Local: "données locales"}

func (a Action) String() string { return actionNames[a] }

// Rule : action associée à un déclencheur.
type Rule struct {
	Trigger string
	Action  Action
	Target  string   // Rewrite : nom cible ; « *. » en tête = préfixé du nom demandé
	Local   []dns.RR // Local : enregistrements (propriétaire remplacé à l'usage)
}

// Policy : une zone RPZ compilée, immuable.
type Policy struct {
	Feed    string
	exact   map[string]*Rule
	wild    map[string]*Rule // « *.example.com » → clé « example.com. »
	ipBits  []int            // longueurs de préfixe présentes, de la plus longue à la plus courte
	ips     map[netip.Prefix]*Rule
	client  ipSet // rpz-client-ip
	nsip    ipSet // rpz-nsip
	nsExact map[string]*Rule
	nsWild  map[string]*Rule
	Rules   int
	Skipped int // déclencheurs non pris en charge ou mal formés
}

// Parse compile les enregistrements d'une zone RPZ.
func Parse(feed, zone string, rrs []dns.RR) (*Policy, error) {
	zone = strings.ToLower(dns.Fqdn(zone))
	p := &Policy{Feed: feed, exact: map[string]*Rule{}, wild: map[string]*Rule{}, ips: map[netip.Prefix]*Rule{},
		client: ipSet{m: map[netip.Prefix]*Rule{}}, nsip: ipSet{m: map[netip.Prefix]*Rule{}}, nsExact: map[string]*Rule{}, nsWild: map[string]*Rule{}}
	rules := map[string]*Rule{}
	for _, rr := range rrs {
		h := rr.Header()
		owner := strings.ToLower(h.Name)
		if owner == zone || !dns.IsSubDomain(zone, owner) {
			continue // SOA, NS de la zone, ou hors zone
		}
		if h.Rrtype == dns.TypeRRSIG || h.Rrtype == dns.TypeNSEC || h.Rrtype == dns.TypeDNSKEY {
			continue
		}
		trig := strings.TrimSuffix(owner, "."+zone)
		r := rules[trig]
		if r == nil {
			r = &Rule{Trigger: trig, Action: Local}
			rules[trig] = r
		}
		if c, ok := rr.(*dns.CNAME); ok {
			switch t := strings.ToLower(c.Target); t {
			case ".":
				r.Action = NXDomain
			case "*.":
				r.Action = NoData
			case "rpz-passthru.":
				r.Action = Passthru
			case "rpz-drop.":
				r.Action = Drop
			case "rpz-tcp-only.":
				r.Action = TCPOnly
			default:
				r.Action, r.Target = Rewrite, t
			}
			continue
		}
		if r.Action == Local {
			r.Local = append(r.Local, rr)
		}
	}
	for trig, r := range rules {
		switch {
		case strings.HasSuffix(trig, ".rpz-ip"):
			pfx, err := parseIPTrigger(strings.TrimSuffix(trig, ".rpz-ip"))
			if err != nil {
				p.Skipped++
				continue
			}
			p.ips[pfx] = r
		case strings.HasSuffix(trig, ".rpz-client-ip"), strings.HasSuffix(trig, ".rpz-nsip"):
			set, suffix := &p.client, ".rpz-client-ip"
			if strings.HasSuffix(trig, ".rpz-nsip") {
				set, suffix = &p.nsip, ".rpz-nsip"
			}
			pfx, err := parseIPTrigger(strings.TrimSuffix(trig, suffix))
			if err != nil {
				p.Skipped++
				continue
			}
			set.add(pfx, r)
		case strings.HasSuffix(trig, ".rpz-nsdname"):
			n := strings.TrimSuffix(trig, ".rpz-nsdname")
			if strings.HasPrefix(n, "*.") {
				p.nsWild[dns.Fqdn(n[2:])] = r
			} else {
				p.nsExact[dns.Fqdn(n)] = r
			}
		case strings.HasPrefix(trig, "*."):
			p.wild[dns.Fqdn(trig[2:])] = r
		default:
			p.exact[dns.Fqdn(trig)] = r
		}
		p.Rules++
	}
	seen := map[int]bool{}
	for pfx := range p.ips {
		if !seen[pfx.Bits()] {
			seen[pfx.Bits()] = true
			p.ipBits = append(p.ipBits, pfx.Bits())
		}
	}
	sortDesc(p.ipBits)
	return p, nil
}

func sortDesc(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] > a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// parseIPTrigger : « 24.0.2.0.192 » → 192.0.2.0/24 ; IPv6 : groupes de 16
// bits inversés, « zz » pour la suite de zéros (« 64.zz.db8.2001 » →
// 2001:db8::/64).
func parseIPTrigger(s string) (netip.Prefix, error) {
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return netip.Prefix{}, fmt.Errorf("déclencheur IP mal formé")
	}
	bits, err := strconv.Atoi(labels[0])
	if err != nil {
		return netip.Prefix{}, err
	}
	parts := labels[1:]
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	var text string
	if len(parts) == 4 && !slicesContains(parts, "zz") {
		text = strings.Join(parts, ".")
	} else {
		for i, g := range parts {
			if g == "zz" {
				parts[i] = ""
			}
		}
		text = strings.Join(parts, ":")
		if strings.HasPrefix(text, ":") {
			text = ":" + text
		}
		if strings.HasSuffix(text, ":") {
			text += ":"
		}
	}
	a, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, err
	}
	pfx, err := a.Prefix(bits)
	if err != nil || pfx.Addr() != a {
		return netip.Prefix{}, fmt.Errorf("préfixe invalide %s/%d", a, bits)
	}
	return pfx, nil
}

func slicesContains(a []string, v string) bool {
	for _, x := range a {
		if x == v {
			return true
		}
	}
	return false
}

// MatchName cherche un déclencheur QNAME : nom exact, puis le joker du
// parent le plus proche.
func (p *Policy) MatchName(qname string) *Rule {
	if r := p.exact[qname]; r != nil {
		return r
	}
	for name := qname; ; {
		i := strings.IndexByte(name, '.')
		if i < 0 || i == len(name)-1 {
			return nil
		}
		name = name[i+1:]
		if r := p.wild[name]; r != nil {
			return r
		}
	}
}

// MatchIP cherche le préfixe le plus long contenant ip.
func (p *Policy) MatchIP(ip netip.Addr) *Rule {
	for _, b := range p.ipBits {
		if b > ip.BitLen() {
			continue
		}
		pfx, err := ip.Prefix(b)
		if err != nil {
			continue
		}
		if r := p.ips[pfx]; r != nil {
			return r
		}
	}
	return nil
}

// ipSet : préfixes d'adresses, recherche du plus long préfixe.
type ipSet struct {
	bits []int
	m    map[netip.Prefix]*Rule
}

func (s *ipSet) add(p netip.Prefix, r *Rule) {
	if _, ok := s.m[p]; !ok {
		found := false
		for _, b := range s.bits {
			found = found || b == p.Bits()
		}
		if !found {
			s.bits = append(s.bits, p.Bits())
			sortDesc(s.bits)
		}
	}
	s.m[p] = r
}

func (s *ipSet) match(ip netip.Addr) *Rule {
	ip = ip.Unmap()
	for _, b := range s.bits {
		if b > ip.BitLen() {
			continue
		}
		if pfx, err := ip.Prefix(b); err == nil {
			if r := s.m[pfx]; r != nil {
				return r
			}
		}
	}
	return nil
}

// MatchClient : déclencheur rpz-client-ip.
func (p *Policy) MatchClient(ip netip.Addr) *Rule { return p.client.match(ip) }

// HasNS indique si la zone contient des déclencheurs sur serveurs de noms.
func (p *Policy) HasNS() bool { return len(p.nsExact)+len(p.nsWild)+len(p.nsip.m) > 0 }

// MatchNSName : déclencheur rpz-nsdname (nom exact ou joker).
func (p *Policy) MatchNSName(ns string) *Rule {
	ns = strings.ToLower(dns.Fqdn(ns))
	if r := p.nsExact[ns]; r != nil {
		return r
	}
	for name := ns; ; {
		i := strings.IndexByte(name, '.')
		if i < 0 || i == len(name)-1 {
			return nil
		}
		name = name[i+1:]
		if r := p.nsWild[name]; r != nil {
			return r
		}
	}
}

// MatchNSIP : déclencheur rpz-nsip.
func (p *Policy) MatchNSIP(ip netip.Addr) *Rule { return p.nsip.match(ip) }
