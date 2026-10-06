// Package policy décide, pour chaque requête, quelle politique s'applique au
// client (groupe d'appareils) et ce que cette politique impose : règles
// propres au groupe, services bloqués, plages horaires, SafeSearch.
//
// La politique compilée est immuable et remplacée atomiquement à chaque
// modification de l'état : la décision ne prend aucun verrou.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/rempart-dns/rempart/internal/blocker"
	"github.com/rempart-dns/rempart/internal/filter"
	"github.com/rempart-dns/rempart/internal/state"
)

// Group est la forme compilée d'un state.Group.
type Group struct {
	ID, Name    string
	Blocking    bool
	PausedUntil time.Time
	ListsKey    string // clé du matcher de listes (blocker.SetKey)
	CatsKey     string // listes de catégories, appliquées même en pause ("" : aucune)
	SafeSearch  bool
	YouTube     string

	rules     *filter.Matcher   // règles propres au groupe
	services  map[string]string // domaine → nom du service, en permanence
	schedules []schedule
}

type schedule struct {
	name       string
	days       [7]bool
	start, end int // minutes depuis minuit
	services   map[string]string
	blockAll   bool
}

// Verdict d'une vérification propre au groupe.
type Verdict struct {
	Allowed bool // exception du groupe : rien d'autre ne bloque
	Blocked bool
	Rule    string
	Source  string
}

// Policy : groupes compilés et index d'identification des clients.
type Policy struct {
	Loc      *time.Location
	byIP     map[netip.Addr]*Group
	prefixes []prefixGroup // du plus spécifique au plus large
	byMAC    map[string]*Group
	byDevice map[string]*Group // id d'appareil → groupe
	tokens   map[string]string // SHA-256 du jeton → id d'appareil
	names    map[string]string // id d'appareil → nom
}

type prefixGroup struct {
	p netip.Prefix
	g *Group
}

// Compile construit la politique à partir de l'état et refuse toute entrée
// invalide (validation avant enregistrement).
func Compile(st state.State) (*Policy, error) {
	p, errs := build(st, true)
	if len(errs) > 0 {
		return nil, errs[0]
	}
	return p, nil
}

// Build construit la politique en service en écartant les seules entrées
// invalides (par exemple un service retiré du catalogue par une mise à
// jour) : jamais de politique nulle, et les jetons révoqués le sont toujours.
func Build(st state.State) (*Policy, []error) { return build(st, false) }

func build(st state.State, strict bool) (*Policy, []error) {
	var errs []error
	loc := time.Local
	if st.Settings.TimeZone != "" {
		l, err := time.LoadLocation(st.Settings.TimeZone)
		if err != nil {
			errs = append(errs, fmt.Errorf("fuseau horaire %q inconnu", st.Settings.TimeZone))
		} else {
			loc = l
		}
	}
	p := &Policy{Loc: loc, byIP: map[netip.Addr]*Group{}, byMAC: map[string]*Group{},
		byDevice: map[string]*Group{}, tokens: map[string]string{}, names: map[string]string{}}
	for _, d := range st.Devices {
		p.tokens[d.TokenHash] = d.ID
		p.names[d.ID] = d.Name
	}
	for _, sg := range st.Groups {
		g, gerrs := compileGroup(st, sg)
		for _, e := range gerrs {
			errs = append(errs, fmt.Errorf("groupe %s : %w", sg.Name, e))
		}
		for _, c := range sg.Clients {
			kind, v, err := ParseClient(c)
			if err != nil {
				errs = append(errs, fmt.Errorf("groupe %s : %w", sg.Name, err))
				continue
			}
			switch kind {
			case "ip":
				p.byIP[netip.MustParseAddr(v)] = g
			case "cidr":
				p.prefixes = append(p.prefixes, prefixGroup{netip.MustParsePrefix(v), g})
			case "mac":
				p.byMAC[v] = g
			case "device":
				p.byDevice[v] = g
			}
		}
	}
	slices.SortStableFunc(p.prefixes, func(a, b prefixGroup) int { return b.p.Bits() - a.p.Bits() })
	if strict && len(errs) > 0 {
		return nil, errs
	}
	return p, errs
}

// ParseClient valide et normalise un identifiant de client : renvoie son type
// (ip, cidr, mac, device) et sa forme canonique.
func ParseClient(c string) (kind, value string, err error) {
	c = strings.TrimSpace(c)
	if id, ok := strings.CutPrefix(c, "device:"); ok {
		if id == "" || len(id) > 32 || strings.Trim(id, "0123456789abcdef") != "" {
			return "", "", fmt.Errorf("identifiant d'appareil invalide %q", c)
		}
		return "device", id, nil
	}
	if a, err := netip.ParseAddr(c); err == nil {
		return "ip", a.Unmap().String(), nil
	}
	if pr, err := netip.ParsePrefix(c); err == nil {
		return "cidr", pr.Masked().String(), nil
	}
	if hw, err := net.ParseMAC(c); err == nil && len(hw) == 6 {
		return "mac", hw.String(), nil
	}
	return "", "", fmt.Errorf("client %q : adresse IP, préfixe CIDR, adresse MAC ou device:<id> attendu", c)
}

func compileGroup(st state.State, sg state.Group) (*Group, []error) {
	var errs []error
	ids, rules, cats := blocker.GroupLists(st, sg)
	g := &Group{ID: sg.ID, Name: sg.Name, Blocking: sg.Blocking, PausedUntil: sg.PausedUntil,
		ListsKey: blocker.SetKey(ids, rules), SafeSearch: sg.SafeSearch, YouTube: sg.YouTube}
	if len(cats) > 0 {
		g.CatsKey = blocker.SetKey(cats, false)
	}
	b := filter.NewBuilder()
	src := b.AddSource(filter.Source{ID: "group-" + sg.ID, Name: "Règles du groupe " + sg.Name})
	for _, r := range sg.Rules {
		if r.Allow {
			b.Allow(r.Domain, src)
		} else {
			b.Block(r.Domain, src)
		}
	}
	g.rules = b.Build()
	var err error
	if g.services, err = serviceDomains(sg.Services); err != nil {
		errs = append(errs, err)
	}
	for _, s := range sg.Schedules {
		cs, err := compileSchedule(s)
		if err != nil {
			errs = append(errs, err)
			if cs.blockAll || len(cs.services) > 0 {
				g.schedules = append(g.schedules, cs) // service inconnu : le reste de la plage s'applique
			}
			continue
		}
		g.schedules = append(g.schedules, cs)
	}
	return g, errs
}

// serviceDomains renvoie les domaines des services connus, et une erreur
// pour le premier service inconnu.
func serviceDomains(ids []string) (map[string]string, error) {
	out := map[string]string{}
	var err error
	for _, id := range ids {
		s, ok := ServiceByID(id)
		if !ok {
			if err == nil {
				err = fmt.Errorf("service inconnu %q", id)
			}
			continue
		}
		for _, d := range s.Domains {
			out[d] = s.Name
		}
	}
	return out, err
}

// ParseClock lit une heure HH:MM et renvoie les minutes depuis minuit.
func ParseClock(s string) (int, error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, fmt.Errorf("heure invalide %q (HH:MM attendu)", s)
	}
	return t.Hour()*60 + t.Minute(), nil
}

func compileSchedule(s state.Schedule) (schedule, error) {
	cs := schedule{name: s.Name, blockAll: s.BlockAll}
	var err error
	if cs.start, err = ParseClock(s.Start); err != nil {
		return cs, err
	}
	if cs.end, err = ParseClock(s.End); err != nil {
		return cs, err
	}
	if len(s.Days) == 0 {
		return cs, fmt.Errorf("plage %q : aucun jour choisi", s.Name)
	}
	for _, d := range s.Days {
		if d < 0 || d > 6 {
			return cs, fmt.Errorf("plage %q : jour invalide %d", s.Name, d)
		}
		cs.days[d] = true
	}
	if !s.BlockAll && len(s.Services) == 0 {
		return cs, fmt.Errorf("plage %q : choisissez des services ou la coupure complète", s.Name)
	}
	cs.services, err = serviceDomains(s.Services)
	return cs, err
}

// active : la plage couvre-t-elle l'instant t (heure locale) ? Une plage qui
// passe minuit appartient au jour de son début ; début = fin couvre 24 h.
func (s schedule) active(t time.Time) bool {
	m := t.Hour()*60 + t.Minute()
	today := int(t.Weekday())
	yesterday := (today + 6) % 7
	switch {
	case s.start < s.end:
		return s.days[today] && m >= s.start && m < s.end
	case s.start > s.end:
		return (s.days[today] && m >= s.start) || (s.days[yesterday] && m < s.end)
	default:
		return (s.days[today] && m >= s.start) || (s.days[yesterday] && m < s.start)
	}
}

// Identify renvoie le groupe du client, ou nil (politique générale). Ordre :
// appareil identifié par jeton, IP exacte, adresse MAC, préfixe le plus long.
func (p *Policy) Identify(ip netip.Addr, device, mac string) *Group {
	if device != "" {
		if g := p.byDevice[device]; g != nil {
			return g
		}
	}
	if g := p.byIP[ip]; g != nil {
		return g
	}
	if mac != "" {
		if g := p.byMAC[mac]; g != nil {
			return g
		}
	}
	for _, pg := range p.prefixes {
		if pg.p.Contains(ip) {
			return pg.g
		}
	}
	return nil
}

// UsesMAC : au moins un groupe identifie ses clients par adresse MAC.
func (p *Policy) UsesMAC() bool { return len(p.byMAC) > 0 }

// Device renvoie l'appareil dont le jeton est présenté, ou "".
func (p *Policy) Device(token string) string {
	if token == "" {
		return ""
	}
	return p.tokens[HashToken(token)]
}

// DeviceName renvoie le nom d'un appareil.
func (p *Policy) DeviceName(id string) string { return p.names[id] }

// HashToken : empreinte conservée d'un jeton d'appareil.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// FilteringActive : filtrage publicitaire du groupe (listes, règles,
// services permanents), suspendu par la pause du groupe.
func (g *Group) FilteringActive(now time.Time) bool {
	return g.Blocking && now.After(g.PausedUntil)
}

// Check applique ce qui est propre au groupe pour name (FQDN), à l'instant
// now en heure locale. filtering indique si le filtrage publicitaire est
// actif ; les plages horaires s'appliquent dans tous les cas.
func (g *Group) Check(name string, now time.Time, filtering bool) Verdict {
	n := strings.TrimSuffix(name, ".")
	if res := g.rules.Match(n); res.Allowed {
		return Verdict{Allowed: true, Rule: res.Rule, Source: res.Source}
	} else if res.Blocked && filtering {
		return Verdict{Blocked: true, Rule: res.Rule, Source: res.Source}
	}
	for _, s := range g.schedules {
		if !s.active(now) {
			continue
		}
		if s.blockAll {
			return Verdict{Blocked: true, Rule: "coupure " + clock(s.start) + "–" + clock(s.end), Source: "plage horaire « " + s.name + " »"}
		}
		if d, svc, ok := lookup(s.services, n); ok {
			return Verdict{Blocked: true, Rule: d + " (" + svc + ")", Source: "plage horaire « " + s.name + " »"}
		}
	}
	if filtering {
		if d, svc, ok := lookup(g.services, n); ok {
			return Verdict{Blocked: true, Rule: d + " (" + svc + ")", Source: "services bloqués, groupe " + g.Name}
		}
	}
	return Verdict{}
}

func clock(m int) string { return fmt.Sprintf("%02d:%02d", m/60, m%60) }

// lookup parcourt les suffixes de name (sans point final).
func lookup(set map[string]string, name string) (string, string, bool) {
	if len(set) == 0 {
		return "", "", false
	}
	for {
		if v, ok := set[name]; ok {
			return name, v, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return "", "", false
		}
		name = name[i+1:]
	}
}
