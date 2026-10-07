// denial.go - preuves de non-existence (RFC 4035 §5.4, RFC 5155 §8).

package dnssec

import (
	"errors"
	"strings"

	"github.com/miekg/dns"
)

// proof : enregistrements NSEC ou NSEC3 validés de la section d'autorité.
type proof struct {
	zone  string
	nsec  []*dns.NSEC
	nsec3 []*dns.NSEC3
	all   []dns.RR
}

// authority vérifie les NSEC, NSEC3 et SOA de la section d'autorité avec les
// clés de la zone zi et renvoie les preuves.
func (v *Validator) authority(r *dns.Msg, zi *zoneInfo) (*proof, error) {
	type key struct {
		name string
		t    uint16
	}
	sets := map[key][]dns.RR{}
	sigs := map[key][]*dns.RRSIG{}
	for _, rr := range r.Ns {
		h := rr.Header()
		k := key{strings.ToLower(h.Name), h.Rrtype}
		if s, ok := rr.(*dns.RRSIG); ok {
			k.t = s.TypeCovered
			sigs[k] = append(sigs[k], s)
			continue
		}
		switch h.Rrtype {
		case dns.TypeNSEC, dns.TypeNSEC3, dns.TypeSOA:
			sets[k] = append(sets[k], rr)
		}
	}
	p := &proof{zone: zi.zone}
	for k, set := range sets {
		if k.t == dns.TypeSOA && !strings.EqualFold(k.name, zi.zone) {
			continue // SOA d'une autre zone : ignoré
		}
		s, err := v.verify(set, sigs[k], zi.zone, zi.keys)
		if err != nil {
			return nil, errors.New(k.name + "/" + dns.TypeToString[k.t] + " : " + err.Error())
		}
		// Un NSEC ou un NSEC3 n'est jamais synthétisé depuis un joker. Le
		// NSEC dont le propriétaire est le joker lui-même (« *.zone ») n'est
		// pas une expansion : le label « * » n'est pas compté dans le champ
		// Labels de sa signature (RFC 4034 §3.1.3).
		want := dns.CountLabel(k.name)
		if strings.HasPrefix(k.name, "*.") {
			want--
		}
		if k.t != dns.TypeSOA && int(s.Labels) != want {
			return nil, errors.New(k.name + " : preuve signée comme un joker")
		}
		v.capTTL(set, s)
		p.all = append(p.all, set...)
		for _, rr := range set {
			switch n := rr.(type) {
			case *dns.NSEC:
				p.nsec = append(p.nsec, n)
			case *dns.NSEC3:
				p.nsec3 = append(p.nsec3, n)
			}
		}
	}
	if len(p.nsec) == 0 && len(p.nsec3) == 0 {
		return nil, errors.New("aucun NSEC ni NSEC3")
	}
	return p, nil
}

// denyResult : conclusion d'une preuve d'absence de DS.
type denyResult int

const (
	denyNone           denyResult = iota // pas de preuve
	denyNotCut                           // pas de délégation : même zone
	denyInsecure                         // délégation sans DS (ou opt-out)
	denyInsecureParams                   // NSEC3 trop coûteux : non sécurisé
)

func hasType(bm []uint16, t uint16) bool {
	for _, x := range bm {
		if x == t {
			return true
		}
	}
	return false
}

// denyDS interprète la preuve qu'un nom n'a pas de DS.
func (p *proof) denyDS(name string) denyResult {
	for _, n := range p.nsec {
		if equal(n.Hdr.Name, name) {
			switch {
			case hasType(n.TypeBitMap, dns.TypeDS):
				return denyNone
			case hasType(n.TypeBitMap, dns.TypeNS) && !hasType(n.TypeBitMap, dns.TypeSOA):
				return denyInsecure
			}
			return denyNotCut
		}
	}
	for _, n := range p.nsec {
		if covers(n, name) {
			return denyNotCut // le nom n'existe pas, ou est un nom intermédiaire vide
		}
	}
	if len(p.nsec3) == 0 {
		return denyNone
	}
	if p.highIterations() {
		return denyInsecureParams
	}
	for _, n := range p.nsec3 {
		if n.Match(name) {
			switch {
			case hasType(n.TypeBitMap, dns.TypeDS):
				return denyNone
			case hasType(n.TypeBitMap, dns.TypeNS) && !hasType(n.TypeBitMap, dns.TypeSOA):
				return denyInsecure
			}
			return denyNotCut
		}
	}
	// Pas de NSEC3 pour le nom : il faut la preuve de l'encloser le plus
	// proche ; une couverture opt-out laisse place à une délégation non signée.
	ce, nc, ok := p.closestEncloser3(name)
	if !ok {
		return denyNone
	}
	_ = ce
	if c := p.cover3(nc); c != nil {
		if c.Flags&1 == 1 {
			return denyInsecure
		}
		return denyNotCut
	}
	return denyNone
}

func (p *proof) highIterations() bool {
	for _, n := range p.nsec3 {
		if n.Iterations > MaxNSEC3Iterations || n.Hash != dns.SHA1 {
			return true
		}
	}
	return false
}

func (p *proof) match3(name string) *dns.NSEC3 {
	for _, n := range p.nsec3 {
		if n.Match(name) {
			return n
		}
	}
	return nil
}

func (p *proof) cover3(name string) *dns.NSEC3 {
	for _, n := range p.nsec3 {
		if n.Cover(name) {
			return n
		}
	}
	return nil
}

// closestEncloser3 : plus proche ancêtre de name prouvé existant par un
// NSEC3 (RFC 5155 §8.3), et le nom suivant sur le chemin de name.
func (p *proof) closestEncloser3(name string) (ce, nc string, ok bool) {
	nc = name
	for cur := name; ; {
		i := strings.IndexByte(cur, '.')
		if i < 0 || i+1 >= len(cur) {
			return "", "", false
		}
		parent := cur[i+1:]
		if !dns.IsSubDomain(p.zone, parent) {
			return "", "", false
		}
		if p.match3(parent) != nil {
			return parent, cur, true
		}
		cur = parent
		nc = cur
	}
}

// nxdomain : preuve que name n'existe pas, joker compris.
func (p *proof) nxdomain(name string) Status {
	if len(p.nsec) > 0 {
		var cov *dns.NSEC
		for _, n := range p.nsec {
			if covers(n, name) {
				cov = n
				break
			}
		}
		if cov == nil {
			return Bogus
		}
		ce := longer(commonAncestor(name, cov.Hdr.Name), commonAncestor(name, cov.NextDomain))
		if !dns.IsSubDomain(p.zone, ce) {
			ce = p.zone
		}
		wc := "*." + ce
		for _, n := range p.nsec {
			if equal(n.Hdr.Name, wc) {
				return Bogus // le joker existe : la réponse aurait dû être synthétisée
			}
			if covers(n, wc) {
				return Secure
			}
		}
		return Bogus
	}
	if p.highIterations() {
		return Insecure
	}
	ce, nc, ok := p.closestEncloser3(name)
	if !ok {
		return Bogus
	}
	c := p.cover3(nc)
	if c == nil {
		return Bogus
	}
	if c.Flags&1 == 1 {
		return Insecure // opt-out : une délégation non signée peut exister
	}
	if p.cover3("*."+ce) == nil {
		return Bogus
	}
	return Secure
}

// nodata : preuve que name existe sans le type t (ni CNAME).
func (p *proof) nodata(name string, t uint16) Status {
	if len(p.nsec) > 0 {
		for _, n := range p.nsec {
			if equal(n.Hdr.Name, name) {
				if hasType(n.TypeBitMap, t) || hasType(n.TypeBitMap, dns.TypeCNAME) {
					return Bogus
				}
				// Pour un DS, le NSEC doit venir du parent (pas de SOA).
				if t == dns.TypeDS && hasType(n.TypeBitMap, dns.TypeSOA) && !equal(name, ".") {
					return Bogus
				}
				return Secure
			}
		}
		for _, n := range p.nsec {
			// Nom intermédiaire vide : un NSEC le couvre et le nom suivant en
			// descend (RFC 4035 §5.4).
			if covers(n, name) && dns.IsSubDomain(name, n.NextDomain) && !equal(name, n.NextDomain) {
				return Secure
			}
		}
		// Joker sans le type demandé.
		for _, n := range p.nsec {
			if covers(n, name) {
				ce := longer(commonAncestor(name, n.Hdr.Name), commonAncestor(name, n.NextDomain))
				for _, w := range p.nsec {
					if equal(w.Hdr.Name, "*."+ce) && !hasType(w.TypeBitMap, t) && !hasType(w.TypeBitMap, dns.TypeCNAME) {
						return Secure
					}
				}
			}
		}
		return Bogus
	}
	if p.highIterations() {
		return Insecure
	}
	if n := p.match3(name); n != nil {
		if hasType(n.TypeBitMap, t) || hasType(n.TypeBitMap, dns.TypeCNAME) {
			return Bogus
		}
		return Secure
	}
	ce, nc, ok := p.closestEncloser3(name)
	if !ok {
		return Bogus
	}
	c := p.cover3(nc)
	if c == nil {
		return Bogus
	}
	if t == dns.TypeDS && c.Flags&1 == 1 {
		return Insecure
	}
	if w := p.match3("*." + ce); w != nil && !hasType(w.TypeBitMap, t) && !hasType(w.TypeBitMap, dns.TypeCNAME) {
		return Secure
	}
	if c.Flags&1 == 1 {
		return Insecure
	}
	return Bogus
}

// wildcard : preuve qu'une réponse synthétisée depuis un joker n'avait pas
// de correspondance exacte (RFC 4035 §5.3.4, RFC 5155 §8.8).
func (p *proof) wildcard(owner string, labels uint8) Status {
	l := dns.SplitDomainName(owner)
	if int(labels) >= len(l) {
		return Bogus
	}
	// Nom suivant : un label de plus que la source du joker.
	nc := dns.Fqdn(strings.Join(l[len(l)-int(labels)-1:], "."))
	for _, n := range p.nsec {
		if covers(n, owner) {
			return Secure
		}
	}
	if len(p.nsec3) > 0 {
		if p.highIterations() {
			return Insecure
		}
		if c := p.cover3(nc); c != nil {
			if c.Flags&1 == 1 {
				return Insecure
			}
			return Secure
		}
	}
	return Bogus
}

func equal(a, b string) bool { return strings.EqualFold(dns.Fqdn(a), dns.Fqdn(b)) }

// covers : name est strictement entre le propriétaire du NSEC et le nom
// suivant, en ordre canonique (le dernier NSEC boucle vers l'apex).
func covers(n *dns.NSEC, name string) bool {
	o, nx := n.Hdr.Name, n.NextDomain
	if !dns.IsSubDomain(zoneOfNSEC(n), name) {
		return false
	}
	if compare(o, nx) < 0 {
		return compare(o, name) < 0 && compare(name, nx) < 0
	}
	// Dernier NSEC de la zone : tout ce qui suit le propriétaire.
	return compare(o, name) < 0 || compare(name, nx) < 0
}

// zoneOfNSEC : approximation de l'apex pour le dernier NSEC, dont le nom
// suivant est l'apex ; sinon la racine (le contrôle de zone est fait par la
// signature).
func zoneOfNSEC(n *dns.NSEC) string {
	if compare(n.Hdr.Name, n.NextDomain) >= 0 {
		return n.NextDomain
	}
	return "."
}

func commonAncestor(a, b string) string {
	la := dns.SplitDomainName(strings.ToLower(a))
	lb := dns.SplitDomainName(strings.ToLower(b))
	var out []string
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0 && la[i] == lb[j]; i, j = i-1, j-1 {
		out = append([]string{la[i]}, out...)
	}
	if len(out) == 0 {
		return "."
	}
	return dns.Fqdn(strings.Join(out, "."))
}

func longer(a, b string) string {
	if dns.CountLabel(a) >= dns.CountLabel(b) {
		return a
	}
	return b
}

// compare : ordre canonique des noms (RFC 4034 §6.1).
func compare(a, b string) int {
	la := dns.SplitDomainName(strings.ToLower(a))
	lb := dns.SplitDomainName(strings.ToLower(b))
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		x, y := unescape(la[i]), unescape(lb[j])
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(la) < len(lb):
		return -1
	case len(la) > len(lb):
		return 1
	}
	return 0
}

func unescape(l string) string {
	if !strings.Contains(l, "\\") {
		return l
	}
	var b []byte
	for i := 0; i < len(l); i++ {
		if l[i] == '\\' && i+1 < len(l) {
			if i+3 < len(l) && isDigit(l[i+1]) && isDigit(l[i+2]) && isDigit(l[i+3]) {
				b = append(b, (l[i+1]-'0')*100+(l[i+2]-'0')*10+(l[i+3]-'0'))
				i += 3
				continue
			}
			i++
		}
		b = append(b, l[i])
	}
	return string(b)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
