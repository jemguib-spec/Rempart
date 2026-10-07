// Package zones serves local authoritative zones (maison.lan, corp.example…)
// and signs them with DNSSEC. Signing keys come from the keystore, so with an
// HSM the private keys never leave the hardware: Rempart only asks the HSM
// to sign each RRset when the zone is (re)loaded, never per query.
package zones

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"encoding/base64"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/state"
)

const (
	sigValidity   = 14 * 24 * time.Hour
	resignBefore  = 7 * 24 * time.Hour
	sigBackdating = time.Hour
)

type rrsets map[uint16][]dns.RR

// Zone is an immutable, fully signed zone.
type Zone struct {
	Origin    string
	DNSSEC    bool
	Algorithm keystore.Algorithm
	nodes     map[string]rrsets // owner -> type -> RRs
	sigs      map[string]rrsets // owner -> covered type -> RRSIGs
	names     []string          // owners in canonical order
	soa       *dns.SOA
	// KSK et ZSK sont les clés actives ; Keys décrit toutes les clés publiées
	// (pendant une rotation, plusieurs clés d'un même rôle coexistent).
	KSK, ZSK  *dns.DNSKEY
	Keys      []KeyView
	SignedAt  time.Time
	Expires   time.Time
	MaxTTL    time.Duration // plus grand TTL de la zone (délais de rotation)
	Records   []string
	signCalls int
	n3        *nsec3Chain // chaîne NSEC3 (nil : NSEC ou zone non signée)
	prev      *Zone       // version précédente, pendant la signature seulement
	reused    int         // signatures reprises de la version précédente
}

// KeyView décrit une clé publiée dans le DNSKEY de la zone.
type KeyView struct {
	Label     string    `json:"label"`
	Role      string    `json:"role"`
	State     string    `json:"state"`
	Tag       uint16    `json:"tag"`
	Algorithm string    `json:"algorithm"`
	Imported  bool      `json:"imported,omitempty"`
	Created   time.Time `json:"created"`
	Changed   time.Time `json:"changed"`
	DNSKEY    string    `json:"dnskey"`
	DS        string    `json:"ds,omitempty"` // KSK uniquement
	key       *dns.DNSKEY
}

// Manager holds the active zones.
type Manager struct {
	ks  keystore.Keystore
	log *slog.Logger
	mu  sync.RWMutex
	z   map[string]*Zone
	sec map[string]*Zone // zones secondaires (copiées d'un primaire)

	// OnLoad est appelé après chaque chargement des zones primaires (NOTIFY
	// vers les secondaires).
	OnLoad func([]*Zone)

	chMu       sync.Mutex
	challenges map[string][]string // fqdn → valeurs TXT des défis ACME dns-01

	histMu sync.Mutex
	hist   map[string][]delta // origine → différences successives (IXFR)
}

func NewManager(ks keystore.Keystore, log *slog.Logger) *Manager {
	return &Manager{ks: ks, log: log, z: map[string]*Zone{}, sec: map[string]*Zone{}, challenges: map[string][]string{}}
}

// SetChallenge publie (add) ou retire un TXT de défi ACME dns-01 dans la
// zone locale qui contient fqdn, puis re-signe les zones.
func (m *Manager) SetChallenge(zs []state.Zone, fqdn, value string, add bool) error {
	fqdn = strings.ToLower(dns.Fqdn(fqdn))
	found := false
	for _, sz := range zs {
		if dns.IsSubDomain(strings.ToLower(dns.Fqdn(sz.Name)), fqdn) {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("aucune zone locale ne contient %s : créez la zone ou utilisez le défi http-01", strings.TrimSuffix(fqdn, "."))
	}
	m.chMu.Lock()
	vals := m.challenges[fqdn]
	if add {
		vals = append(vals, value)
	} else {
		for i, v := range vals {
			if v == value {
				vals = append(vals[:i], vals[i+1:]...)
				break
			}
		}
	}
	if len(vals) == 0 {
		delete(m.challenges, fqdn)
	} else {
		m.challenges[fqdn] = vals
	}
	m.chMu.Unlock()
	return m.Load(zs)
}

// withChallenges ajoute aux enregistrements d'une zone les TXT de défi en cours.
func (m *Manager) withChallenges(sz state.Zone) state.Zone {
	m.chMu.Lock()
	defer m.chMu.Unlock()
	origin := strings.ToLower(dns.Fqdn(sz.Name))
	var extra []string
	for name, vals := range m.challenges {
		if !dns.IsSubDomain(origin, name) {
			continue
		}
		for _, v := range vals {
			extra = append(extra, fmt.Sprintf("%s 60 IN TXT %q", name, v))
		}
	}
	if len(extra) > 0 {
		sz.Records = append(append([]string{}, sz.Records...), extra...)
	}
	return sz
}

// KeyLabel is the keystore label of a zone key ("ksk" or "zsk").
func KeyLabel(origin, role string) string {
	return "zone-" + strings.TrimSuffix(strings.ToLower(origin), ".") + "-" + role
}

// Load (re)builds and signs every zone. On error the previous zones stay active.
func (m *Manager) Load(zs []state.Zone) error { return m.load(zs, false) }

// Resign re-signe toutes les zones sans reprendre aucune signature.
func (m *Manager) Resign(zs []state.Zone) error { return m.load(zs, true) }

func (m *Manager) load(zs []state.Zone, fresh bool) error {
	next := map[string]*Zone{}
	m.mu.RLock()
	cur := m.z
	m.mu.RUnlock()
	for _, sz := range zs {
		var prev *Zone
		if !fresh {
			prev = cur[strings.ToLower(dns.Fqdn(sz.Name))]
		}
		z, err := BuildFrom(m.ks, m.withChallenges(sz), prev)
		if err != nil {
			return fmt.Errorf("zone %s: %w", sz.Name, err)
		}
		next[z.Origin] = z
		if old := cur[z.Origin]; old != nil {
			m.record(old, z)
		}
		if z.DNSSEC {
			m.log.Info("zone signée DNSSEC", "zone", z.Origin, "rrsets", z.signCalls, "ksk", z.KSK.KeyTag(), "zsk", z.ZSK.KeyTag(), "expire", z.Expires.Format(time.DateOnly))
		}
	}
	m.mu.Lock()
	m.z = next
	for origin := range m.hist {
		if next[origin] == nil {
			delete(m.hist, origin)
		}
	}
	m.mu.Unlock()
	if m.OnLoad != nil {
		all := make([]*Zone, 0, len(next))
		for _, z := range next {
			all = append(all, z)
		}
		m.OnLoad(all)
	}
	return nil
}

// SetSecondary installe (ou retire, z nil) une zone secondaire. Une zone
// primaire du même nom reste prioritaire.
func (m *Manager) SetSecondary(origin string, z *Zone) {
	origin = strings.ToLower(dns.Fqdn(origin))
	m.mu.Lock()
	if z == nil {
		delete(m.sec, origin)
	} else {
		m.sec[origin] = z
	}
	m.mu.Unlock()
}

// Secondary renvoie une zone secondaire.
func (m *Manager) Secondary(origin string) *Zone {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sec[strings.ToLower(dns.Fqdn(origin))]
}

// Find returns the most specific zone containing qname.
func (m *Manager) Find(qname string) *Zone {
	qname = strings.ToLower(dns.Fqdn(qname))
	m.mu.RLock()
	defer m.mu.RUnlock()
	var best *Zone
	for _, set := range []map[string]*Zone{m.z, m.sec} {
		for origin, z := range set {
			if dns.IsSubDomain(origin, qname) && (best == nil || len(origin) > len(best.Origin)) {
				best = z
			}
		}
	}
	return best
}

// Get returns a zone by name.
func (m *Manager) Get(name string) *Zone {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.z[strings.ToLower(dns.Fqdn(name))]
}

// NeedsResign reports whether any zone signature expires soon.
func (m *Manager) NeedsResign() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, z := range m.z {
		if z.DNSSEC && time.Until(z.Expires) < resignBefore {
			return true
		}
	}
	return false
}

// ParseRecords parses zone-file lines relative to origin.
func ParseRecords(origin string, lines []string) ([]dns.RR, error) {
	zp := dns.NewZoneParser(strings.NewReader(strings.Join(lines, "\n")), origin, "")
	zp.SetDefaultTTL(300)
	var out []dns.RR
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		h := rr.Header()
		h.Name = strings.ToLower(h.Name)
		if !dns.IsSubDomain(origin, h.Name) {
			return nil, fmt.Errorf("%s est hors de la zone %s", h.Name, origin)
		}
		switch h.Rrtype {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeDNSKEY, dns.TypeNSEC3PARAM, dns.TypeCDS, dns.TypeCDNSKEY:
			return nil, fmt.Errorf("les enregistrements %s sont gérés automatiquement", dns.TypeToString[h.Rrtype])
		}
		out = append(out, rr)
	}
	if err := zp.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Build parses and signs a zone.
func Build(ks keystore.Keystore, sz state.Zone) (*Zone, error) { return BuildFrom(ks, sz, nil) }

// BuildFrom parses and signs a zone, reusing the signatures of prev (the
// version in service) for RRsets that did not change and whose signatures
// are not close to expiry: an update then only re-signs what changed, and an
// IXFR to the secondaries only carries the difference.
func BuildFrom(ks keystore.Keystore, sz state.Zone, prev *Zone) (*Zone, error) {
	origin := strings.ToLower(dns.Fqdn(sz.Name))
	if _, ok := dns.IsDomainName(origin); !ok || origin == "." {
		return nil, fmt.Errorf("nom de zone invalide")
	}
	rrs, err := ParseRecords(origin, sz.Records)
	if err != nil {
		return nil, err
	}
	dyn, err := ParseRecords(origin, sz.Dynamic)
	if err != nil {
		return nil, fmt.Errorf("enregistrements dynamiques : %w", err)
	}
	rrs = append(rrs, dyn...)
	z := &Zone{Origin: origin, DNSSEC: sz.DNSSEC, nodes: map[string]rrsets{}, sigs: map[string]rrsets{}, Records: sz.Records}
	if prev != nil && prev.Origin == origin && prev.DNSSEC {
		z.prev = prev
		defer func() { z.prev = nil }()
	}
	add := func(rr dns.RR) {
		h := rr.Header()
		if z.nodes[h.Name] == nil {
			z.nodes[h.Name] = rrsets{}
		}
		for _, ex := range z.nodes[h.Name][h.Rrtype] {
			if dns.IsDuplicate(ex, rr) {
				return
			}
		}
		z.nodes[h.Name][h.Rrtype] = append(z.nodes[h.Name][h.Rrtype], rr)
	}
	for _, rr := range rrs {
		add(rr)
	}
	// SOA and NS are generated when absent.
	if soas := z.nodes[origin][dns.TypeSOA]; len(soas) > 0 {
		z.soa = soas[0].(*dns.SOA)
		z.nodes[origin][dns.TypeSOA] = soas[:1]
		// Le numéro de série suit aussi les mises à jour dynamiques et les
		// enregistrements faits depuis l'interface (sz.Serial), sinon les
		// secondaires ne verraient pas les changements.
		z.soa.Serial = max(z.soa.Serial, sz.Serial)
	} else {
		serial := sz.Serial
		if serial == 0 {
			serial = uint32(time.Now().Unix())
		}
		z.soa = &dns.SOA{Hdr: dns.RR_Header{Name: origin, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns: "ns1." + origin, Mbox: "hostmaster." + origin, Serial: serial,
			Refresh: 3600, Retry: 900, Expire: 1209600, Minttl: 300}
		add(z.soa)
	}
	if len(z.nodes[origin][dns.TypeNS]) == 0 {
		add(&dns.NS{Hdr: dns.RR_Header{Name: origin, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns1." + origin})
	}
	// CNAME must be alone at a name (RFC 1034 §3.6.2).
	for name, set := range z.nodes {
		if len(set[dns.TypeCNAME]) > 0 && len(set) > 1 {
			return nil, fmt.Errorf("%s : un CNAME ne peut pas coexister avec d'autres enregistrements", name)
		}
	}
	for _, set := range z.nodes {
		for _, rrs := range set {
			for _, rr := range rrs {
				z.MaxTTL = max(z.MaxTTL, time.Duration(rr.Header().Ttl)*time.Second)
			}
		}
	}
	if sz.DNSSEC {
		if err := z.sign(ks, sz); err != nil {
			return nil, err
		}
	} else {
		z.sortNames()
	}
	return z, nil
}

func (z *Zone) sortNames() {
	z.names = z.names[:0]
	for n := range z.nodes {
		z.names = append(z.names, n)
	}
	sort.Slice(z.names, func(i, j int) bool { return canonicalLess(z.names[i], z.names[j]) })
}

func dnssecAlg(a keystore.Algorithm) uint8 {
	switch a {
	case keystore.ECDSAP384:
		return dns.ECDSAP384SHA384
	case keystore.Ed25519:
		return dns.ED25519
	}
	return dns.ECDSAP256SHA256
}

// DNSKEYFromSigner builds the DNSKEY record of a public key.
func DNSKEYFromSigner(origin string, s crypto.Signer, flags uint16) (*dns.DNSKEY, error) {
	alg, err := keystore.AlgorithmOf(s.Public())
	if err != nil {
		return nil, err
	}
	var raw []byte
	switch p := s.Public().(type) {
	case *ecdsa.PublicKey:
		size := (p.Curve.Params().BitSize + 7) / 8
		raw = append(pad(p.X, size), pad(p.Y, size)...)
	case ed25519.PublicKey:
		raw = p
	}
	return &dns.DNSKEY{Hdr: dns.RR_Header{Name: origin, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: flags, Protocol: 3, Algorithm: dnssecAlg(alg), PublicKey: base64.StdEncoding.EncodeToString(raw)}, nil
}

func pad(i *big.Int, n int) []byte {
	b := i.Bytes()
	if len(b) >= n {
		return b
	}
	return append(make([]byte, n-len(b)), b...)
}

// EffectiveKeys renvoie les clés d'une zone ; une zone créée avant la gestion
// des rotations n'en liste aucune et utilise les labels historiques.
func EffectiveKeys(sz state.Zone) []state.ZoneKey {
	if len(sz.Keys) > 0 {
		return sz.Keys
	}
	origin := strings.ToLower(dns.Fqdn(sz.Name))
	return []state.ZoneKey{
		{Label: KeyLabel(origin, "ksk"), Role: "ksk", State: StateActive},
		{Label: KeyLabel(origin, "zsk"), Role: "zsk", State: StateActive},
	}
}

// KeyAlgorithm renvoie l'algorithme d'une clé (celui de la zone par défaut).
func KeyAlgorithm(sz state.Zone, k state.ZoneKey) string {
	if k.Algorithm != "" {
		return k.Algorithm
	}
	return sz.Algorithm
}

// publishedState : la clé figure dans le DNSKEY servi.
func publishedState(st string) bool {
	return st != StatePresign && st != StatePostsign
}

// signsZone : la ZSK signe les enregistrements de la zone.
func signsZone(st string) bool {
	return st == StateActive || st == StatePresign || st == StatePostsign
}

func (z *Zone) sign(ks keystore.Keystore, sz state.Zone) error {
	zoneAlg, err := keystore.ParseAlgorithm(sz.Algorithm)
	if err != nil {
		return err
	}
	type entry struct {
		meta   state.ZoneKey
		signer crypto.Signer
		key    *dns.DNSKEY
	}
	var ksks, zsks, zoneSigners []entry
	zskByAlg := map[keystore.Algorithm]bool{}
	for _, k := range EffectiveKeys(sz) {
		alg, err := keystore.ParseAlgorithm(KeyAlgorithm(sz, k))
		if err != nil {
			return err
		}
		// Seule une clé qui vient d'être ajoutée (rotation) peut être générée
		// ici. Une clé active ou retirée absente du keystore est une erreur :
		// la régénérer en silence casserait la chaîne de confiance (DS).
		create := k.State == StatePublished || k.State == StatePresign || len(sz.Keys) == 0
		signer, err := ks.Signer(k.Label, alg, create)
		if err != nil {
			return fmt.Errorf("%s %s: %w", strings.ToUpper(k.Role), k.Label, err)
		}
		a, err := keystore.AlgorithmOf(signer.Public())
		if err != nil {
			return err
		}
		if a != alg {
			return fmt.Errorf("la clé %s est en %s alors qu'elle devrait être en %s", k.Label, a, alg)
		}
		flags := uint16(256)
		if k.Role == "ksk" {
			flags = 257
		}
		dk, err := DNSKEYFromSigner(z.Origin, signer, flags)
		if err != nil {
			return err
		}
		e := entry{k, signer, dk}
		if k.Role == "ksk" {
			ksks = append(ksks, e)
			if k.State == StateActive && alg == zoneAlg && z.KSK == nil {
				z.KSK = dk
			}
			continue
		}
		zsks = append(zsks, e)
		if signsZone(k.State) {
			// Une seule ZSK signe par algorithme ; deux algorithmes signent
			// ensemble pendant une rotation d'algorithme.
			if zskByAlg[alg] {
				return fmt.Errorf("plusieurs ZSK actives en %s : état de rotation incohérent", alg)
			}
			zskByAlg[alg] = true
			zoneSigners = append(zoneSigners, e)
			if k.State == StateActive && alg == zoneAlg {
				z.ZSK = dk
			}
		}
	}
	if len(ksks) == 0 || len(zoneSigners) == 0 {
		return errors.New("il faut au moins une KSK et une ZSK active pour signer la zone")
	}
	if z.KSK == nil { // KSK pas encore active (première KSK en attente de DS)
		z.KSK = ksks[0].key
	}
	if z.ZSK == nil {
		z.ZSK = zoneSigners[0].key
	}
	z.Algorithm = zoneAlg

	var dnskeys, cds, cdnskey []dns.RR
	for _, e := range append(append([]entry{}, ksks...), zsks...) {
		if publishedState(e.meta.State) {
			dnskeys = append(dnskeys, e.key)
		}
		v := KeyView{Label: e.meta.Label, Role: e.meta.Role, State: e.meta.State, Tag: e.key.KeyTag(), Imported: e.meta.Imported,
			Algorithm: KeyAlgorithm(sz, e.meta), Created: e.meta.Created, Changed: e.meta.Changed, DNSKEY: e.key.String(), key: e.key}
		if e.meta.Role == "ksk" {
			v.DS = e.key.ToDS(dns.SHA256).String()
			// CDS/CDNSKEY (RFC 7344) annoncent les KSK qui doivent figurer
			// dans le DS du parent : celles prêtes ou actives.
			if sz.Policy.PublishCDS && (e.meta.State == StateReady || e.meta.State == StateActive) {
				ds := e.key.ToDS(dns.SHA256)
				c := &dns.CDS{DS: *ds}
				c.Hdr = dns.RR_Header{Name: z.Origin, Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: e.key.Hdr.Ttl}
				cds = append(cds, c)
				ck := &dns.CDNSKEY{DNSKEY: *e.key}
				ck.Hdr = dns.RR_Header{Name: z.Origin, Rrtype: dns.TypeCDNSKEY, Class: dns.ClassINET, Ttl: e.key.Hdr.Ttl}
				cdnskey = append(cdnskey, ck)
			}
		}
		z.Keys = append(z.Keys, v)
	}
	z.nodes[z.Origin][dns.TypeDNSKEY] = dnskeys
	if len(cds) > 0 {
		z.nodes[z.Origin][dns.TypeCDS] = cds
		z.nodes[z.Origin][dns.TypeCDNSKEY] = cdnskey
	}

	// Chaque signature change la zone : le numéro de série avance pour que
	// les secondaires récupèrent les nouvelles RRSIG avant expiration.
	z.soa.Serial = max(z.soa.Serial, uint32(time.Now().Unix()))

	// Preuves de non-existence : NSEC (RFC 4034 §4) ou NSEC3 (RFC 5155).
	// TTL : min(TTL du SOA, MINIMUM) (RFC 9077).
	nsecTTL := min(z.soa.Hdr.Ttl, z.soa.Minttl)
	if sz.Policy.NSEC3 {
		if err := z.buildNSEC3(nsecTTL); err != nil {
			return err
		}
		z.sortNames()
	} else {
		z.sortNames()
		for i, name := range z.names {
			types := []uint16{dns.TypeRRSIG, dns.TypeNSEC}
			for t := range z.nodes[name] {
				types = append(types, t)
			}
			sort.Slice(types, func(a, b int) bool { return types[a] < types[b] })
			next := z.names[(i+1)%len(z.names)]
			z.nodes[name][dns.TypeNSEC] = []dns.RR{&dns.NSEC{
				Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: nsecTTL},
				NextDomain: next, TypeBitMap: types}}
		}
	}

	now := time.Now().UTC()
	z.SignedAt = now
	z.Expires = now.Add(sigValidity)
	sign := func(name string, t uint16, rrs []dns.RR, e entry) error {
		if z.sigs[name] == nil {
			z.sigs[name] = rrsets{}
		}
		if old := z.reusable(name, t, rrs, e.key, now); old != nil {
			z.sigs[name][t] = append(z.sigs[name][t], old)
			z.reused++
			return nil
		}
		sig := &dns.RRSIG{
			Hdr:        dns.RR_Header{Ttl: rrs[0].Header().Ttl},
			Algorithm:  e.key.Algorithm,
			KeyTag:     e.key.KeyTag(),
			SignerName: z.Origin,
			Inception:  uint32(now.Add(-sigBackdating).Unix()),
			Expiration: uint32(z.Expires.Unix()),
		}
		if err := sig.Sign(e.signer, rrs); err != nil {
			return fmt.Errorf("signature %s/%s: %w", name, dns.TypeToString[t], err)
		}
		if err := sig.Verify(e.key, rrs); err != nil {
			return fmt.Errorf("auto-vérification de la signature %s/%s: %w", name, dns.TypeToString[t], err)
		}
		z.sigs[name][t] = append(z.sigs[name][t], sig)
		z.signCalls++
		return nil
	}
	for name, set := range z.nodes {
		z.sigs[name] = rrsets{}
		for t, rrs := range set {
			// DNSKEY, CDS et CDNSKEY sont signés par chaque KSK (double
			// signature pour la rotation de KSK) ; le reste de la zone par la
			// ZSK active de chaque algorithme.
			if t == dns.TypeDNSKEY || t == dns.TypeCDS || t == dns.TypeCDNSKEY {
				for _, e := range ksks {
					if err := sign(name, t, rrs, e); err != nil {
						return err
					}
				}
				continue
			}
			for _, e := range zoneSigners {
				if err := sign(name, t, rrs, e); err != nil {
					return err
				}
			}
		}
	}
	if z.n3 != nil {
		for _, o := range z.n3.owners {
			for _, e := range zoneSigners {
				if err := sign(o, dns.TypeNSEC3, []dns.RR{z.n3.recs[o]}, e); err != nil {
					return err
				}
			}
		}
	}
	// Expiration : la plus proche des signatures (reprises comprises).
	for _, set := range z.sigs {
		for _, sigs := range set {
			for _, rr := range sigs {
				if exp := time.Unix(int64(rr.(*dns.RRSIG).Expiration), 0).UTC(); exp.Before(z.Expires) {
					z.Expires = exp
				}
			}
		}
	}
	return nil
}

// reusable renvoie la signature de la version précédente pour un RRset
// identique (mêmes données, mêmes TTL), faite par la même clé, et loin de
// son expiration.
func (z *Zone) reusable(name string, t uint16, rrs []dns.RR, key *dns.DNSKEY, now time.Time) dns.RR {
	p := z.prev
	if p == nil {
		return nil
	}
	var old []dns.RR
	if t == dns.TypeNSEC3 {
		if p.n3 == nil {
			return nil
		}
		if r, ok := p.n3.recs[name]; ok {
			old = []dns.RR{r}
		}
	} else {
		old = p.nodes[name][t]
	}
	if !sameRRset(old, rrs) {
		return nil
	}
	for _, rr := range p.sigs[name][t] {
		s := rr.(*dns.RRSIG)
		if s.KeyTag != key.KeyTag() || s.Algorithm != key.Algorithm || !strings.EqualFold(s.SignerName, z.Origin) {
			continue
		}
		if time.Unix(int64(s.Expiration), 0).Sub(now) <= resignBefore || int64(s.Inception) > now.Unix() {
			continue
		}
		return dns.Copy(s)
	}
	return nil
}

func sameRRset(a, b []dns.RR) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	for _, x := range a {
		found := false
		for _, y := range b {
			if x.Header().Ttl == y.Header().Ttl && dns.IsDuplicate(x, y) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// DS returns the DS records to publish in the parent zone (or to configure
// as a trust anchor on validating resolvers): one per KSK that is ready or
// active.
func (z *Zone) DS() []string {
	out := []string{}
	for _, k := range z.Keys {
		if k.Role == "ksk" && (k.State == StateReady || k.State == StateActive) {
			out = append(out, k.DS)
		}
	}
	return out
}

// Answer builds an authoritative response. do is the client's DNSSEC OK bit.
func (z *Zone) Answer(req *dns.Msg, do bool) *dns.Msg {
	q := req.Question[0]
	qname := strings.ToLower(q.Name)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	withSig := do && z.DNSSEC

	appendSet := func(dst *[]dns.RR, name string, t uint16) bool {
		rrs := z.nodes[name][t]
		if len(rrs) == 0 {
			return false
		}
		for _, rr := range rrs {
			*dst = append(*dst, dns.Copy(rr))
		}
		if withSig {
			for _, s := range z.sigs[name][t] {
				*dst = append(*dst, dns.Copy(s))
			}
		}
		return true
	}
	addSOA := func() {
		soa := dns.Copy(z.soa).(*dns.SOA)
		soa.Hdr.Ttl = min(soa.Hdr.Ttl, soa.Minttl)
		resp.Ns = append(resp.Ns, soa)
		if withSig {
			for _, s := range z.sigs[z.Origin][dns.TypeSOA] {
				sig := dns.Copy(s)
				sig.Header().Ttl = soa.Hdr.Ttl
				resp.Ns = append(resp.Ns, sig)
			}
		}
	}

	if node, ok := z.nodes[qname]; ok {
		if appendSet(&resp.Answer, qname, q.Qtype) {
			return resp
		}
		if len(node[dns.TypeCNAME]) > 0 {
			appendSet(&resp.Answer, qname, dns.TypeCNAME)
			target := strings.ToLower(node[dns.TypeCNAME][0].(*dns.CNAME).Target)
			if dns.IsSubDomain(z.Origin, target) {
				appendSet(&resp.Answer, target, q.Qtype)
			}
			return resp
		}
		// NODATA: the name exists but not this type.
		addSOA()
		if withSig {
			if z.n3 != nil {
				z.denyNoData(&resp.Ns, qname)
			} else {
				appendSet(&resp.Ns, qname, dns.TypeNSEC)
			}
		}
		return resp
	}

	// Empty non-terminal (e.g. "b.zone." when only "a.b.zone." exists): NODATA.
	for _, n := range z.names {
		if strings.HasSuffix(n, "."+qname) {
			addSOA()
			if withSig {
				if z.n3 != nil {
					z.denyNoData(&resp.Ns, qname)
				} else {
					appendSet(&resp.Ns, z.covering(qname), dns.TypeNSEC)
				}
			}
			return resp
		}
	}

	// Joker (RFC 4592) : le nom n'existe pas, mais « *.<encloser le plus
	// proche> » existe. Réponse synthétisée au nom demandé ; les RRSIG du
	// joker sont reprises telles quelles (leur champ Labels permet au
	// validateur de reconstruire le joker), avec la preuve que le nom exact
	// n'existe pas (RFC 4035 §3.1.3.3, RFC 5155 §7.2.6).
	ce := z.closestEncloser(qname)
	wc := "*." + ce
	if wnode, ok := z.nodes[wc]; ok {
		synth := func(dst *[]dns.RR, t uint16) bool {
			if len(wnode[t]) == 0 {
				return false
			}
			for _, rr := range wnode[t] {
				c := dns.Copy(rr)
				c.Header().Name = q.Name
				*dst = append(*dst, c)
			}
			if withSig {
				for _, s := range z.sigs[wc][t] {
					c := dns.Copy(s)
					c.Header().Name = q.Name
					*dst = append(*dst, c)
				}
			}
			return true
		}
		proveNoExact := func() {
			if !withSig {
				return
			}
			if z.n3 != nil {
				z.appendNSEC3(&resp.Ns, z.n3.cover(nextCloser(qname, ce), z.Origin), map[string]bool{})
			} else {
				appendSet(&resp.Ns, z.covering(qname), dns.TypeNSEC)
			}
		}
		if synth(&resp.Answer, q.Qtype) {
			proveNoExact()
			return resp
		}
		if synth(&resp.Answer, dns.TypeCNAME) {
			target := strings.ToLower(wnode[dns.TypeCNAME][0].(*dns.CNAME).Target)
			if dns.IsSubDomain(z.Origin, target) {
				appendSet(&resp.Answer, target, q.Qtype)
			}
			proveNoExact()
			return resp
		}
		// NODATA par le joker (RFC 4035 §3.1.3.4, RFC 5155 §7.2.5).
		addSOA()
		if withSig {
			if z.n3 != nil {
				done := map[string]bool{}
				if o, ok := z.n3.match(ce, z.Origin); ok {
					z.appendNSEC3(&resp.Ns, o, done)
				}
				z.appendNSEC3(&resp.Ns, z.n3.cover(nextCloser(qname, ce), z.Origin), done)
				if o, ok := z.n3.match(wc, z.Origin); ok {
					z.appendNSEC3(&resp.Ns, o, done)
				}
			} else {
				c := z.covering(qname)
				appendSet(&resp.Ns, c, dns.TypeNSEC)
				if c != wc {
					appendSet(&resp.Ns, wc, dns.TypeNSEC)
				}
			}
		}
		return resp
	}

	resp.Rcode = dns.RcodeNameError
	addSOA()
	if withSig && z.n3 != nil {
		z.denyName(&resp.Ns, qname)
	} else if withSig {
		c1 := z.covering(qname)
		appendSet(&resp.Ns, c1, dns.TypeNSEC)
		if c2 := z.covering("*." + z.closestEncloser(qname)); c2 != c1 {
			appendSet(&resp.Ns, c2, dns.TypeNSEC)
		}
	}
	return resp
}

func (z *Zone) exists(name string) bool {
	if _, ok := z.nodes[name]; ok {
		return true
	}
	for _, n := range z.names {
		if strings.HasSuffix(n, "."+name) {
			return true
		}
	}
	return false
}

func (z *Zone) closestEncloser(qname string) string {
	name := qname
	for name != z.Origin {
		i := strings.IndexByte(name, '.')
		if i < 0 || i == len(name)-1 {
			break
		}
		name = name[i+1:]
		if z.exists(name) {
			return name
		}
	}
	return z.Origin
}

// covering returns the owner whose NSEC covers name (the greatest owner
// canonically lower than name).
func (z *Zone) covering(name string) string {
	i := sort.Search(len(z.names), func(i int) bool { return !canonicalLess(z.names[i], name) })
	if i == 0 {
		return z.names[len(z.names)-1]
	}
	return z.names[i-1]
}

// canonicalLess implements RFC 4034 §6.1 canonical name ordering.
func canonicalLess(a, b string) bool {
	la := dns.SplitDomainName(strings.ToLower(a))
	lb := dns.SplitDomainName(strings.ToLower(b))
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if x, y := unescape(la[i]), unescape(lb[j]); x != y {
			return x < y
		}
	}
	return len(la) < len(lb)
}

// unescape decodes presentation-format escapes (\DDD and \X) in a label.
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
