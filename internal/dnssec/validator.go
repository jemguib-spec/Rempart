// Package dnssec valide localement les réponses DNSSEC (RFC 4033, 4034,
// 4035, 5155, 6840) obtenues des résolveurs en amont.
//
// Rempart ne fait pas de résolution itérative : il interroge ses résolveurs
// en amont avec les bits DO et CD (sans leur déléguer la validation), puis
// reconstruit lui-même la chaîne de confiance depuis l'ancre de la racine,
// zone par zone (DS chez le parent, DNSKEY de l'enfant), et vérifie les
// signatures et les preuves de non-existence (NSEC, NSEC3). Un résolveur en
// amont compromis, ou un intermédiaire, ne peut donc plus faire accepter une
// réponse falsifiée pour un domaine signé.
package dnssec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Status : résultat d'une validation (RFC 4033 §5).
type Status int

const (
	// Indeterminate : la réponse n'a pas été validée (erreur du serveur, CD).
	Indeterminate Status = iota
	// Insecure : domaine non signé, ou sous une délégation non signée.
	Insecure
	// Secure : chaîne de confiance complète depuis l'ancre.
	Secure
	// Bogus : signature invalide, absente ou preuve manquante.
	Bogus
)

func (s Status) String() string {
	switch s {
	case Insecure:
		return "insecure"
	case Secure:
		return "secure"
	case Bogus:
		return "bogus"
	}
	return "indeterminate"
}

// RootAnchors : DS des clés de la racine. KSK-2017 (20326) et KSK-2024
// (38696) ; la racine ne signe plus qu'avec KSK-2024 à partir du
// 11 octobre 2026, les deux restent acceptées.
var RootAnchors = []string{
	". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
	". IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
}

// Exchanger interroge les résolveurs en amont.
type Exchanger interface {
	Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, string, error)
}

// MaxNSEC3Iterations : au-delà, une preuve NSEC3 est traitée comme non
// sécurisée (RFC 9276 §3.2) : son coût de vérification servirait d'attaque.
const MaxNSEC3Iterations = 100

const (
	maxCacheTTL   = time.Hour
	minCacheTTL   = 30 * time.Second
	bogusCacheTTL = 15 * time.Second
	maxLabels     = 24
	maxEntries    = 50000
)

// Validator : voir le commentaire du paquet. Sûr en accès concurrent.
type Validator struct {
	Up Exchanger
	// anchors : DS de confiance par zone (la racine, et éventuellement des
	// zones internes signées que la racine ne désigne pas).
	anchors map[string][]*dns.DS
	// NTA (ancres négatives, RFC 7646) : domaines jamais validés, par
	// exemple ceux transférés vers un serveur interne (Active Directory).
	NTA func(name string) bool
	Now func() time.Time

	mu     sync.Mutex
	zones  map[string]*zoneInfo
	flight map[string]*call

	Counts struct{ Secure, Insecure, Bogus atomic.Uint64 }
}

// New crée un validateur ancré sur les DS donnés (format présentation) ;
// sans DS, les ancres de la racine.
func New(up Exchanger, anchors []string) (*Validator, error) {
	if len(anchors) == 0 {
		anchors = RootAnchors
	}
	v := &Validator{Up: up}
	for _, a := range anchors {
		rr, err := dns.NewRR(a)
		if err != nil {
			return nil, fmt.Errorf("ancre de confiance %q : %w", a, err)
		}
		ds, ok := rr.(*dns.DS)
		if !ok {
			return nil, fmt.Errorf("ancre de confiance %q : enregistrement DS attendu", a)
		}
		if v.anchors == nil {
			v.anchors = map[string][]*dns.DS{}
		}
		z := strings.ToLower(dns.Fqdn(ds.Hdr.Name))
		v.anchors[z] = append(v.anchors[z], ds)
	}
	return v, nil
}

// zoneInfo : état de sécurité d'un nom, et la zone signée qui le contient.
type zoneInfo struct {
	status  Status
	zone    string // apex de la zone signée la plus proche (status Secure)
	keys    []*dns.DNSKEY
	reason  string
	expires time.Time
}

type call struct {
	done chan struct{}
	info *zoneInfo
}

func (v *Validator) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Flush oublie la chaîne de confiance mise en cache.
func (v *Validator) Flush() {
	v.mu.Lock()
	v.zones = nil
	v.mu.Unlock()
}

func (v *Validator) query(ctx context.Context, name string, t uint16) (*dns.Msg, error) {
	q := new(dns.Msg)
	q.Id = dns.Id()
	q.RecursionDesired = true
	q.CheckingDisabled = true
	q.SetQuestion(name, t)
	q.SetEdns0(1232, true)
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	r, _, err := v.Up.Exchange(ctx, q)
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("%s/%s : %s", name, dns.TypeToString[t], dns.RcodeToString[r.Rcode])
	}
	return r, nil
}

// chain renvoie l'état de sécurité de name en descendant depuis la racine,
// un label à la fois ; les résultats sont mis en cache par nom.
func (v *Validator) chain(ctx context.Context, name string) *zoneInfo {
	name = strings.ToLower(dns.Fqdn(name))
	if v.NTA != nil && name != "." && v.NTA(name) {
		return &zoneInfo{status: Insecure, reason: "ancre négative (domaine transféré)"}
	}
	if dns.CountLabel(name) > maxLabels {
		return &zoneInfo{status: Bogus, reason: "nom trop long"}
	}
	now := v.now()
	v.mu.Lock()
	if v.zones == nil {
		v.zones = map[string]*zoneInfo{}
		v.flight = map[string]*call{}
	}
	if zi, ok := v.zones[name]; ok && now.Before(zi.expires) {
		v.mu.Unlock()
		return zi
	}
	if c, ok := v.flight[name]; ok {
		v.mu.Unlock()
		select {
		case <-c.done:
			return c.info
		case <-ctx.Done():
			return &zoneInfo{status: Bogus, reason: "délai dépassé"}
		}
	}
	c := &call{done: make(chan struct{})}
	v.flight[name] = c
	v.mu.Unlock()

	var zi *zoneInfo
	if ds := v.anchors[name]; len(ds) > 0 {
		zi = v.anchor(ctx, name, ds)
	} else if name == "." {
		zi = &zoneInfo{status: Insecure, reason: "aucune ancre de confiance"}
	} else {
		parent := "."
		if i := strings.IndexByte(name, '.'); i >= 0 && i+1 < len(name) {
			parent = name[i+1:]
		}
		p := v.chain(ctx, parent)
		if p.status != Secure {
			zi = &zoneInfo{status: p.status, reason: p.reason, expires: p.expires}
		} else {
			zi = v.step(ctx, p, name)
		}
	}
	if zi.expires.IsZero() {
		ttl := minCacheTTL
		if zi.status == Bogus {
			ttl = bogusCacheTTL
		}
		zi.expires = now.Add(ttl)
	}
	v.mu.Lock()
	if len(v.zones) >= maxEntries {
		for k, e := range v.zones {
			if now.After(e.expires) || len(v.zones) >= maxEntries {
				delete(v.zones, k)
			}
		}
	}
	v.zones[name] = zi
	delete(v.flight, name)
	v.mu.Unlock()
	c.info = zi
	close(c.done)
	return zi
}

func expiry(now time.Time, rrs ...dns.RR) time.Time {
	ttl := maxCacheTTL
	for _, rr := range rrs {
		ttl = min(ttl, time.Duration(rr.Header().Ttl)*time.Second)
	}
	return now.Add(max(ttl, minCacheTTL))
}

// anchor valide le DNSKEY d'une zone ancrée (la racine) avec ses DS.
func (v *Validator) anchor(ctx context.Context, zone string, ds []*dns.DS) *zoneInfo {
	r, err := v.query(ctx, zone, dns.TypeDNSKEY)
	if err != nil {
		return &zoneInfo{status: Bogus, reason: "DNSKEY de " + zone + " injoignable : " + err.Error()}
	}
	keys, err := v.validateDNSKEY(r, zone, ds)
	if err != nil {
		return &zoneInfo{status: Bogus, reason: zone + " (ancre) : " + err.Error()}
	}
	return &zoneInfo{status: Secure, zone: zone, keys: keys, expires: expiry(v.now(), keysRR(keys)...)}
}

func keysRR(keys []*dns.DNSKEY) []dns.RR {
	out := make([]dns.RR, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	return out
}

// supportedAlg : algorithmes que la vérification sait traiter.
func supportedAlg(a uint8) bool {
	switch a {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512, dns.ECDSAP256SHA256, dns.ECDSAP384SHA384, dns.ED25519:
		return true
	}
	return false
}

func supportedDigest(d uint8) bool {
	return d == dns.SHA1 || d == dns.SHA256 || d == dns.SHA384
}

// validateDNSKEY vérifie qu'un DNSKEY reçu est signé par une clé qui
// correspond à l'un des DS (RFC 4035 §5.2) et renvoie les clés de zone.
func (v *Validator) validateDNSKEY(r *dns.Msg, zone string, ds []*dns.DS) ([]*dns.DNSKEY, error) {
	set, sigs := rrsetOf(r.Answer, zone, dns.TypeDNSKEY)
	if len(set) == 0 {
		return nil, errors.New("DNSKEY absent")
	}
	var keys []*dns.DNSKEY
	for _, rr := range set {
		k := rr.(*dns.DNSKEY)
		if k.Flags&dns.ZONE != 0 && k.Flags&dns.REVOKE == 0 && k.Protocol == 3 {
			keys = append(keys, k)
		}
	}
	now := v.now()
	for _, d := range ds {
		for _, k := range keys {
			if k.KeyTag() != d.KeyTag || k.Algorithm != d.Algorithm {
				continue
			}
			kd := k.ToDS(d.DigestType)
			if kd == nil || !strings.EqualFold(kd.Digest, d.Digest) {
				continue
			}
			for _, s := range sigs {
				if s.KeyTag == k.KeyTag() && s.Algorithm == k.Algorithm && s.ValidityPeriod(now) && s.Verify(k, set) == nil {
					return keys, nil
				}
			}
		}
	}
	return nil, errors.New("aucune signature du DNSKEY par une clé désignée par le DS")
}

// rrsetOf extrait un RRset et ses signatures d'une section.
func rrsetOf(sec []dns.RR, name string, t uint16) ([]dns.RR, []*dns.RRSIG) {
	var set []dns.RR
	var sigs []*dns.RRSIG
	for _, rr := range sec {
		h := rr.Header()
		if !strings.EqualFold(h.Name, name) {
			continue
		}
		if s, ok := rr.(*dns.RRSIG); ok {
			if s.TypeCovered == t {
				sigs = append(sigs, s)
			}
			continue
		}
		if h.Rrtype == t {
			set = append(set, rr)
		}
	}
	return set, sigs
}

// verify vérifie un RRset avec les clés d'une zone ; il renvoie la signature
// retenue.
func (v *Validator) verify(set []dns.RR, sigs []*dns.RRSIG, zone string, keys []*dns.DNSKEY) (*dns.RRSIG, error) {
	if len(sigs) == 0 {
		return nil, errors.New("signature absente")
	}
	now := v.now()
	var last error = errors.New("aucune clé ne correspond")
	for _, s := range sigs {
		if !strings.EqualFold(s.SignerName, zone) {
			last = fmt.Errorf("signataire %s inattendu (zone %s)", s.SignerName, zone)
			continue
		}
		if !s.ValidityPeriod(now) {
			last = errors.New("signature expirée ou pas encore valide")
			continue
		}
		// Labels ne peut pas dépasser le nombre de labels du propriétaire.
		if int(s.Labels) > dns.CountLabel(set[0].Header().Name) {
			last = errors.New("champ Labels de la signature incohérent")
			continue
		}
		for _, k := range keys {
			if k.KeyTag() == s.KeyTag && k.Algorithm == s.Algorithm {
				if err := s.Verify(k, set); err == nil {
					return s, nil
				} else {
					last = err
				}
			}
		}
	}
	return nil, last
}

// capTTL borne le TTL d'un RRset validé au TTL d'origine signé et à
// l'expiration de la signature (RFC 4035 §5.3.3).
func (v *Validator) capTTL(set []dns.RR, s *dns.RRSIG) {
	left := int64(s.Expiration) - v.now().Unix()
	for _, rr := range set {
		h := rr.Header()
		h.Ttl = min(h.Ttl, s.OrigTtl)
		if left >= 0 && int64(h.Ttl) > left {
			h.Ttl = uint32(left)
		}
	}
}

// step : passage de la zone signée p à son descendant direct child.
func (v *Validator) step(ctx context.Context, p *zoneInfo, child string) *zoneInfo {
	now := v.now()
	same := func(exp time.Time) *zoneInfo {
		return &zoneInfo{status: Secure, zone: p.zone, keys: p.keys, expires: minTime(exp, p.expires)}
	}
	r, err := v.query(ctx, child, dns.TypeDS)
	if err != nil {
		return &zoneInfo{status: Bogus, reason: "DS de " + child + " injoignable : " + err.Error()}
	}
	if set, sigs := rrsetOf(r.Answer, child, dns.TypeDS); len(set) > 0 {
		if _, err := v.verify(set, sigs, p.zone, p.keys); err != nil {
			return &zoneInfo{status: Bogus, reason: "DS de " + child + " : " + err.Error()}
		}
		var ds []*dns.DS
		for _, rr := range set {
			d := rr.(*dns.DS)
			if supportedAlg(d.Algorithm) && supportedDigest(d.DigestType) {
				ds = append(ds, d)
			}
		}
		if len(ds) == 0 {
			// RFC 4035 §5.2 : algorithmes inconnus, zone traitée comme non signée.
			return &zoneInfo{status: Insecure, reason: child + " : algorithme DNSSEC non pris en charge", expires: expiry(now, set...)}
		}
		kr, err := v.query(ctx, child, dns.TypeDNSKEY)
		if err != nil {
			return &zoneInfo{status: Bogus, reason: "DNSKEY de " + child + " injoignable : " + err.Error()}
		}
		keys, err := v.validateDNSKEY(kr, child, ds)
		if err != nil {
			return &zoneInfo{status: Bogus, reason: child + " : " + err.Error()}
		}
		return &zoneInfo{status: Secure, zone: child, keys: keys, expires: expiry(now, append(set, keysRR(keys)...)...)}
	}
	// Pas de DS : preuve signée par la zone parente.
	proof, err := v.authority(r, p)
	if err != nil {
		return &zoneInfo{status: Bogus, reason: "absence de DS pour " + child + " : " + err.Error()}
	}
	exp := expiry(now, proof.all...)
	switch d := proof.denyDS(child); d {
	case denyNotCut:
		return same(exp)
	case denyInsecure:
		return &zoneInfo{status: Insecure, reason: child + " : délégation non signée", expires: exp}
	case denyNone:
		return &zoneInfo{status: Bogus, reason: "absence de DS pour " + child + " non prouvée"}
	case denyInsecureParams:
		return &zoneInfo{status: Insecure, reason: child + " : NSEC3 avec trop d'itérations", expires: exp}
	}
	return &zoneInfo{status: Bogus, reason: "réponse DS incohérente pour " + child}
}

func minTime(a, b time.Time) time.Time {
	if b.IsZero() || (!a.IsZero() && a.Before(b)) {
		return a
	}
	return b
}
