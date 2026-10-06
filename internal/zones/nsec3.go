// nsec3.go - preuves de non-existence hachées (RFC 5155), paramètres de la
// RFC 9276 : SHA-1, aucune itération supplémentaire, sans sel, sans opt-out.

package zones

import (
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// nsec3Chain : enregistrements NSEC3 d'une zone. Leurs propriétaires (noms
// hachés) ne sont pas des noms de la zone : ils sont rangés à part, pour
// qu'une requête sur l'un d'eux reçoive une réponse NXDOMAIN ordinaire.
type nsec3Chain struct {
	hash   uint8
	iter   uint16
	salt   string   // hexadécimal, "" si aucun
	owners []string // propriétaires complets, en ordre (base32hex préserve l'ordre)
	recs   map[string]*dns.NSEC3
}

// hashOwner renvoie le propriétaire NSEC3 correspondant à name.
func (c *nsec3Chain) hashOwner(name, origin string) string {
	h := dns.HashName(name, c.hash, c.iter, c.salt)
	if h == "" {
		return ""
	}
	return strings.ToLower(h) + "." + origin
}

func (c *nsec3Chain) label(owner string) string {
	if i := strings.IndexByte(owner, '.'); i > 0 {
		return owner[:i]
	}
	return owner
}

// match renvoie le propriétaire NSEC3 de name s'il existe.
func (c *nsec3Chain) match(name, origin string) (string, bool) {
	o := c.hashOwner(name, origin)
	_, ok := c.recs[o]
	return o, ok
}

// cover renvoie le propriétaire NSEC3 dont l'intervalle couvre le haché de
// name (le plus grand propriétaire inférieur, en boucle).
func (c *nsec3Chain) cover(name, origin string) string {
	h := c.label(c.hashOwner(name, origin))
	i := sort.Search(len(c.owners), func(i int) bool { return c.label(c.owners[i]) >= h })
	if i == 0 {
		return c.owners[len(c.owners)-1]
	}
	return c.owners[i-1]
}

// buildNSEC3 calcule la chaîne NSEC3 d'une zone signée. Chaque nom de la
// zone et chaque nom intermédiaire vide (RFC 5155 §7.1) reçoit un NSEC3.
func (z *Zone) buildNSEC3(ttl uint32) error {
	c := &nsec3Chain{hash: dns.SHA1, recs: map[string]*dns.NSEC3{}}
	// NSEC3PARAM à l'apex : il doit figurer dans le bitmap de l'apex et être
	// signé comme les autres enregistrements.
	z.nodes[z.Origin][dns.TypeNSEC3PARAM] = []dns.RR{&dns.NSEC3PARAM{
		Hdr:  dns.RR_Header{Name: z.Origin, Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET, Ttl: 0},
		Hash: c.hash, Flags: 0, Iterations: c.iter, SaltLength: 0, Salt: ""}}

	all := map[string]bool{}
	for name := range z.nodes {
		all[name] = true
		// Ancêtres jusqu'à l'apex : noms intermédiaires vides.
		for n := name; n != z.Origin; {
			i := strings.IndexByte(n, '.')
			if i < 0 || i == len(n)-1 {
				break
			}
			n = n[i+1:]
			if !dns.IsSubDomain(z.Origin, n) {
				break
			}
			all[n] = true
		}
	}
	byOwner := map[string]string{}
	for name := range all {
		o := c.hashOwner(name, z.Origin)
		if o == "" {
			return fmt.Errorf("NSEC3 : hachage impossible de %s", name)
		}
		if prev, dup := byOwner[o]; dup {
			return fmt.Errorf("NSEC3 : collision de hachage entre %s et %s", prev, name)
		}
		byOwner[o] = name
		c.owners = append(c.owners, o)
	}
	sort.Slice(c.owners, func(i, j int) bool { return c.label(c.owners[i]) < c.label(c.owners[j]) })
	for i, o := range c.owners {
		name := byOwner[o]
		var types []uint16
		if set := z.nodes[name]; len(set) > 0 {
			types = append(types, dns.TypeRRSIG)
			for t := range set {
				types = append(types, t)
			}
		}
		sort.Slice(types, func(a, b int) bool { return types[a] < types[b] })
		next := c.owners[(i+1)%len(c.owners)]
		c.recs[o] = &dns.NSEC3{
			Hdr:  dns.RR_Header{Name: o, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: ttl},
			Hash: c.hash, Flags: 0, Iterations: c.iter, SaltLength: 0, Salt: "",
			HashLength: 20, NextDomain: strings.ToUpper(c.label(next)), TypeBitMap: types}
	}
	z.n3 = c
	return nil
}

// fromTransferNSEC3 range à part les NSEC3 d'une zone reçue par transfert.
func (z *Zone) fromTransferNSEC3() {
	c := &nsec3Chain{recs: map[string]*dns.NSEC3{}}
	found := false
	for name, set := range z.nodes {
		rrs := set[dns.TypeNSEC3]
		if len(rrs) == 0 {
			continue
		}
		n3, ok := rrs[0].(*dns.NSEC3)
		if !ok {
			continue
		}
		if !found {
			c.hash, c.iter, c.salt = n3.Hash, n3.Iterations, n3.Salt
			found = true
		}
		c.recs[name] = n3
		c.owners = append(c.owners, name)
		delete(set, dns.TypeNSEC3)
		if len(set) == 0 {
			delete(z.nodes, name)
		}
	}
	if !found {
		return
	}
	if p, ok := firstRR[*dns.NSEC3PARAM](z.nodes[z.Origin][dns.TypeNSEC3PARAM]); ok {
		c.hash, c.iter, c.salt = p.Hash, p.Iterations, p.Salt
	}
	if c.salt == "-" {
		c.salt = ""
	}
	sort.Slice(c.owners, func(i, j int) bool { return c.label(c.owners[i]) < c.label(c.owners[j]) })
	z.n3 = c
}

func firstRR[T dns.RR](rrs []dns.RR) (T, bool) {
	var zero T
	if len(rrs) == 0 {
		return zero, false
	}
	t, ok := rrs[0].(T)
	return t, ok
}

// appendNSEC3 ajoute l'enregistrement NSEC3 de propriétaire o et ses
// signatures, une seule fois par réponse.
func (z *Zone) appendNSEC3(dst *[]dns.RR, o string, done map[string]bool) {
	if done[o] {
		return
	}
	r, ok := z.n3.recs[o]
	if !ok {
		return
	}
	done[o] = true
	*dst = append(*dst, dns.Copy(r))
	for _, s := range z.sigs[o][dns.TypeNSEC3] {
		*dst = append(*dst, dns.Copy(s))
	}
}

// denyNoData : le nom existe (ou est un nom intermédiaire vide) sans le type
// demandé (RFC 5155 §7.2.3).
func (z *Zone) denyNoData(dst *[]dns.RR, qname string) {
	done := map[string]bool{}
	if o, ok := z.n3.match(qname, z.Origin); ok {
		z.appendNSEC3(dst, o, done)
	}
}

// denyName : preuve de l'encloser le plus proche (RFC 5155 §7.2.1 et 7.2.2) :
// NSEC3 de l'encloser, NSEC3 couvrant le nom suivant, NSEC3 couvrant le
// joker sous l'encloser.
func (z *Zone) denyName(dst *[]dns.RR, qname string) {
	done := map[string]bool{}
	ce := z.closestEncloser(qname)
	if o, ok := z.n3.match(ce, z.Origin); ok {
		z.appendNSEC3(dst, o, done)
	}
	z.appendNSEC3(dst, z.n3.cover(nextCloser(qname, ce), z.Origin), done)
	z.appendNSEC3(dst, z.n3.cover("*."+ce, z.Origin), done)
}

// nextCloser : le nom qui a un label de plus que l'encloser le plus proche,
// sur le chemin de qname.
func nextCloser(qname, ce string) string {
	labels := dns.SplitDomainName(qname)
	n := dns.CountLabel(ce)
	if len(labels) <= n {
		return qname
	}
	return dns.Fqdn(strings.Join(labels[len(labels)-n-1:], "."))
}
