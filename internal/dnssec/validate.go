// validate.go - validation d'une réponse complète (réponse positive, chaîne
// de CNAME/DNAME, joker, réponse négative).

package dnssec

import (
	"context"
	"strings"

	"github.com/miekg/dns"
)

// Validate valide une réponse obtenue (bits DO et CD) pour la question q.
// Les TTL des RRsets validés sont bornés par leurs signatures. reason
// explique un échec.
func (v *Validator) Validate(ctx context.Context, q dns.Question, r *dns.Msg) (st Status, reason string) {
	defer func() {
		switch st {
		case Secure:
			v.Counts.Secure.Add(1)
		case Insecure:
			v.Counts.Insecure.Add(1)
		case Bogus:
			v.Counts.Bogus.Add(1)
		}
	}()
	if r == nil || (r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError) {
		return Indeterminate, ""
	}
	qname := strings.ToLower(dns.Fqdn(q.Name))
	if v.NTA != nil && v.NTA(qname) {
		return Insecure, ""
	}
	st = Secure
	worse := func(s Status, why string) {
		switch {
		case s == Bogus && st != Bogus:
			st, reason = Bogus, why
		case s == Insecure && st == Secure:
			st, reason = Insecure, why
		}
	}

	// RRsets de la section réponse.
	type key struct {
		name string
		t    uint16
	}
	var order []key
	sets := map[key][]dns.RR{}
	sigs := map[key][]*dns.RRSIG{}
	for _, rr := range r.Answer {
		h := rr.Header()
		k := key{strings.ToLower(h.Name), h.Rrtype}
		if s, ok := rr.(*dns.RRSIG); ok {
			k.t = s.TypeCovered
			sigs[k] = append(sigs[k], s)
			continue
		}
		if _, ok := sets[k]; !ok {
			order = append(order, k)
		}
		sets[k] = append(sets[k], rr)
	}
	// DNAME validés : leurs CNAME synthétisés ne sont pas signés (RFC 6672).
	dnames := map[string]string{}
	var wildcards []struct {
		owner  string
		labels uint8
		zi     *zoneInfo
	}
	for _, k := range order {
		set := sets[k]
		if k.t == dns.TypeCNAME && len(sigs[k]) == 0 {
			if synthesized(k.name, set, dnames) {
				continue
			}
		}
		s, zi, why := v.rrset(ctx, k.name, set, sigs[k])
		if s == Bogus {
			worse(Bogus, why)
			continue
		}
		if s == Insecure {
			worse(Insecure, why)
			continue
		}
		if k.t == dns.TypeDNAME {
			d := set[0].(*dns.DNAME)
			dnames[k.name] = strings.ToLower(d.Target)
		}
		if sg := sigs[k]; len(sg) > 0 && int(sg[0].Labels) < dns.CountLabel(k.name) && !strings.HasPrefix(k.name, "*.") {
			wildcards = append(wildcards, struct {
				owner  string
				labels uint8
				zi     *zoneInfo
			}{k.name, sg[0].Labels, zi})
		}
	}
	if st == Bogus {
		return st, reason
	}
	// Réponses synthétisées depuis un joker : il faut prouver l'absence du
	// nom exact.
	for _, w := range wildcards {
		p, err := v.authority(r, w.zi)
		if err != nil {
			return Bogus, "joker " + w.owner + " : " + err.Error()
		}
		if s := p.wildcard(w.owner, w.labels); s == Bogus {
			return Bogus, "joker " + w.owner + " sans preuve de non-existence"
		} else if s == Insecure {
			worse(Insecure, "joker sous NSEC3 opt-out")
		}
	}

	// Fin de la chaîne de CNAME : le nom dont on attend la réponse.
	sname := qname
	for i := 0; i < 16; i++ {
		next := ""
		for _, rr := range r.Answer {
			if c, ok := rr.(*dns.CNAME); ok && strings.EqualFold(c.Hdr.Name, sname) && q.Qtype != dns.TypeCNAME {
				next = strings.ToLower(c.Target)
			}
		}
		if next == "" {
			break
		}
		sname = next
	}
	final := false
	for k := range sets {
		if k.name == sname && (k.t == q.Qtype || q.Qtype == dns.TypeANY) {
			final = true
		}
	}
	if final && r.Rcode == dns.RcodeSuccess {
		return st, reason
	}

	// Réponse négative pour sname : preuve signée par sa zone.
	zone := ""
	for _, rr := range r.Ns {
		if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == dns.TypeSOA {
			zone = strings.ToLower(s.SignerName)
		}
	}
	if zone == "" {
		for _, rr := range r.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				zone = strings.ToLower(soa.Hdr.Name)
			}
		}
	}
	if zone == "" || !dns.IsSubDomain(zone, sname) {
		// Aucune zone annoncée : il faut que sname soit sous une délégation
		// non signée.
		zi := v.chain(ctx, sname)
		if zi.status == Secure {
			return Bogus, "réponse négative sans preuve pour " + sname
		}
		worse(zi.status, zi.reason)
		return st, reason
	}
	zi := v.chain(ctx, zone)
	switch {
	case zi.status == Bogus:
		return Bogus, zi.reason
	case zi.status != Secure:
		worse(Insecure, zi.reason)
		return st, reason
	case zi.zone != zone:
		return Bogus, zone + " n'est pas une zone signée"
	}
	p, err := v.authority(r, zi)
	if err != nil {
		return Bogus, "réponse négative pour " + sname + " : " + err.Error()
	}
	var s Status
	if r.Rcode == dns.RcodeNameError {
		s = p.nxdomain(sname)
	} else {
		s = p.nodata(sname, q.Qtype)
	}
	if s == Bogus {
		return Bogus, "preuve de non-existence invalide pour " + sname
	}
	worse(s, "preuve NSEC3 opt-out")
	return st, reason
}

// rrset valide un RRset de la réponse.
func (v *Validator) rrset(ctx context.Context, owner string, set []dns.RR, sigs []*dns.RRSIG) (Status, *zoneInfo, string) {
	if len(sigs) == 0 {
		zi := v.chain(ctx, owner)
		switch zi.status {
		case Secure:
			return Bogus, nil, owner + " : signature absente dans une zone signée (" + zi.zone + ")"
		case Bogus:
			return Bogus, nil, zi.reason
		}
		return Insecure, nil, zi.reason
	}
	signer := strings.ToLower(dns.Fqdn(sigs[0].SignerName))
	if !dns.IsSubDomain(signer, owner) {
		return Bogus, nil, owner + " : signataire " + signer + " hors de la zone"
	}
	zi := v.chain(ctx, signer)
	switch {
	case zi.status == Bogus:
		return Bogus, nil, zi.reason
	case zi.status != Secure:
		return Insecure, nil, zi.reason
	case zi.zone != signer:
		return Bogus, nil, signer + " n'est pas l'apex d'une zone signée"
	}
	s, err := v.verify(set, sigs, signer, zi.keys)
	if err != nil {
		return Bogus, nil, owner + "/" + dns.TypeToString[set[0].Header().Rrtype] + " : " + err.Error()
	}
	v.capTTL(set, s)
	return Secure, zi, ""
}

// synthesized : CNAME non signé déduit d'un DNAME validé (RFC 6672 §5.3.1).
func synthesized(owner string, set []dns.RR, dnames map[string]string) bool {
	c, ok := set[0].(*dns.CNAME)
	if !ok || len(set) != 1 {
		return false
	}
	for d, target := range dnames {
		if dns.IsSubDomain(d, owner) && owner != d {
			want := strings.TrimSuffix(owner, d) + target
			if strings.EqualFold(c.Target, want) {
				return true
			}
		}
	}
	return false
}
