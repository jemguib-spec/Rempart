// suggest.go - suggestions locales de blocage à partir des noms résolus.
// Mémoire seule, aucune information sur les clients, effacé à la désactivation.
// Rempart ; alimenté par server.Handle.

// Package suggest propose des domaines à bloquer à partir de ce que Rempart
// observe localement. Rien ne quitte le serveur et rien n'est écrit sur le
// disque : les observations restent en mémoire, sans aucune information sur
// les appareils, et sont effacées dès que la fonction est désactivée.
//
// Quatre indices sont combinés :
//   - CNAME vers une infrastructure de traçage connue (« cloaking ») ;
//   - sous-domaines voisins déjà bloqués par vos listes ;
//   - libellé typique de la publicité ou de la télémétrie ;
//   - nom de domaine aléatoire et inexistant (génération algorithmique de
//     domaines, signe possible d'un logiciel malveillant).
package suggest

import (
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rempart-dns/rempart/internal/filter"
)

const maxObserved = 20000

// Suggestion est un domaine proposé au blocage.
type Suggestion struct {
	Domain   string    `json:"domain"`
	Kind     string    `json:"kind"` // cname | voisins | libellé | aléatoire
	Reason   string    `json:"reason"`
	Score    float64   `json:"score"` // 0..1 : confiance de l'indice
	Count    uint64    `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

type obs struct {
	count, nx uint64
	cname     string
	last      time.Time
}

// Observer accumule les observations en mémoire.
type Observer struct {
	active  atomic.Bool // lecture sans verrou sur le chemin DNS
	mu      sync.Mutex
	on      bool
	seen    map[string]*obs            // nom résolu → observations
	blocked map[string]map[string]bool // parent → sous-domaines bloqués vus
}

func New() *Observer {
	return &Observer{seen: map[string]*obs{}, blocked: map[string]map[string]bool{}}
}

// Enable active ou désactive l'observation ; la désactivation efface tout.
func (o *Observer) Enable(on bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.on = on
	o.active.Store(on)
	if !on {
		o.seen = map[string]*obs{}
		o.blocked = map[string]map[string]bool{}
	}
}

// Enabled indique si l'observation est active.
func (o *Observer) Enabled() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.on
}

// Resolved enregistre une réponse non bloquée. cname est la première cible
// CNAME de la réponse, s'il y en a une.
func (o *Observer) Resolved(name string, nxdomain bool, cname string) {
	if !o.active.Load() {
		return
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.on || name == "" {
		return
	}
	e := o.seen[name]
	if e == nil {
		if len(o.seen) >= maxObserved {
			o.evict()
		}
		e = &obs{}
		o.seen[name] = e
	}
	e.count++
	if nxdomain {
		e.nx++
	}
	if cname != "" {
		e.cname = strings.TrimSuffix(strings.ToLower(cname), ".")
	}
	e.last = time.Now()
}

// Blocked enregistre un nom bloqué, pour l'indice des voisins.
func (o *Observer) Blocked(name string) {
	if !o.active.Load() {
		return
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	parent := parentOf(name)
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.on || parent == "" {
		return
	}
	set := o.blocked[parent]
	if set == nil {
		if len(o.blocked) >= maxObserved {
			o.blocked = map[string]map[string]bool{}
		}
		set = map[string]bool{}
		o.blocked[parent] = set
	}
	if len(set) < 64 {
		set[name] = true
	}
}

// evict retire la moitié la moins vue (appelé verrou tenu).
func (o *Observer) evict() {
	type kv struct {
		k string
		n uint64
	}
	all := make([]kv, 0, len(o.seen))
	for k, v := range o.seen {
		all = append(all, kv{k, v.count})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].n < all[j].n })
	for _, e := range all[:len(all)/2] {
		delete(o.seen, e.k)
	}
}

// Analyze renvoie les suggestions, de la plus probable à la moins probable.
// Les domaines déjà bloqués ou autorisés, et ceux ignorés, sont exclus.
func (o *Observer) Analyze(m *filter.Matcher, dismissed []string, limit int) []Suggestion {
	skip := map[string]bool{}
	for _, d := range dismissed {
		skip[d] = true
	}
	o.mu.Lock()
	type snap struct {
		name string
		obs
	}
	items := make([]snap, 0, len(o.seen))
	for k, v := range o.seen {
		items = append(items, snap{k, *v})
	}
	siblings := map[string]int{}
	for p, set := range o.blocked {
		siblings[p] = len(set)
	}
	o.mu.Unlock()

	best := map[string]Suggestion{}
	add := func(s Suggestion) {
		if skip[s.Domain] {
			return
		}
		if r := m.Match(s.Domain); r.Blocked || r.Allowed {
			return
		}
		if cur, ok := best[s.Domain]; ok && cur.Score >= s.Score {
			cur.Count += s.Count
			best[s.Domain] = cur
			return
		}
		best[s.Domain] = s
	}
	for _, it := range items {
		if it.cname != "" {
			if t := trackerCNAME(it.cname); t != "" {
				add(Suggestion{Domain: t, Kind: "cname", Score: 0.9, Count: it.count, LastSeen: it.last,
					Reason: it.name + " est un alias (CNAME) vers " + it.cname + ", une infrastructure de traçage connue"})
			}
		}
		if p := parentOf(it.name); p != "" && siblings[p] >= 3 {
			add(Suggestion{Domain: it.name, Kind: "voisins", Score: 0.55 + math.Min(0.3, float64(siblings[p])/40), Count: it.count, LastSeen: it.last,
				Reason: plural(siblings[p], "sous-domaine voisin de "+p+" déjà bloqué", "sous-domaines voisins de "+p+" déjà bloqués")})
		}
		if lbl := adLabel(it.name); lbl != "" {
			add(Suggestion{Domain: it.name, Kind: "libellé", Score: 0.6, Count: it.count, LastSeen: it.last,
				Reason: "le libellé « " + lbl + " » est typique de la publicité, de la mesure d'audience ou de la télémétrie"})
		}
		if it.nx > 0 && it.nx*2 >= it.count {
			if sld := randomSLD(it.name); sld != "" {
				add(Suggestion{Domain: registrable(it.name), Kind: "aléatoire", Score: 0.5, Count: it.count, LastSeen: it.last,
					Reason: "nom aléatoire (" + sld + ") qui n'existe pas : motif des logiciels malveillants qui cherchent leur serveur de commande"})
			}
		}
	}
	out := make([]Suggestion, 0, len(best))
	for _, s := range best {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		wi := out[i].Score * math.Log2(2+float64(out[i].Count))
		wj := out[j].Score * math.Log2(2+float64(out[j].Count))
		if wi != wj {
			return wi > wj
		}
		return out[i].Domain < out[j].Domain
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// parentOf retire le premier libellé, sauf s'il ne reste qu'un domaine
// enregistrable (on ne regroupe pas les sous-domaines de « com »).
func parentOf(name string) string {
	i := strings.IndexByte(name, '.')
	if i < 0 {
		return ""
	}
	if registrable(name) == name {
		return ""
	}
	return name[i+1:]
}

// Suffixes publics à deux niveaux les plus courants ; sans la Public Suffix
// List complète, c'est une approximation suffisante pour regrouper des noms.
var twoLevel = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "com.au": true, "net.au": true, "org.au": true,
	"co.jp": true, "ne.jp": true, "co.nz": true, "com.br": true, "com.cn": true, "com.tr": true, "co.in": true,
	"gouv.fr": true, "asso.fr": true, "com.fr": true, "co.za": true, "com.mx": true, "com.ar": true,
}

func registrable(name string) string {
	labels := strings.Split(name, ".")
	n := 2
	if len(labels) >= 3 && twoLevel[strings.Join(labels[len(labels)-2:], ".")] {
		n = 3
	}
	if len(labels) <= n {
		return name
	}
	return strings.Join(labels[len(labels)-n:], ".")
}

// Infrastructures de traçage utilisées derrière un CNAME du site visité
// (« CNAME cloaking ») : mesure d'audience et attribution publicitaire.
var cnameTrackers = []string{
	"eulerian.net", "at-o.net", "keyade.com", "omtrdc.net", "2o7.net", "wizaly.com",
	"commander1.com", "dnsdelegation.io", "storetail.io", "tagcommander.com",
}

func trackerCNAME(target string) string {
	for _, t := range cnameTrackers {
		if target == t || strings.HasSuffix(target, "."+t) {
			return t
		}
	}
	return ""
}

var adWords = map[string]bool{
	"ad": true, "ads": true, "adserver": true, "adservice": true, "adserving": true, "adsrv": true, "advert": true,
	"adverts": true, "advertising": true, "analytics": true, "telemetry": true, "tracking": true, "tracker": true,
	"track": true, "pixel": true, "beacon": true, "beacons": true, "metrics": true, "doubleclick": true,
	"adsystem": true, "adtech": true, "affiliate": true, "affiliates": true, "banner": true, "banners": true,
}

// adLabel renvoie le libellé publicitaire trouvé dans la partie hôte du nom
// (jamais dans le domaine enregistrable lui-même : « track.com » est un site).
func adLabel(name string) string {
	reg := registrable(name)
	host := strings.TrimSuffix(strings.TrimSuffix(name, reg), ".")
	if host == "" {
		return ""
	}
	for _, l := range strings.Split(host, ".") {
		base := strings.TrimRight(l, "0123456789")
		for _, part := range strings.FieldsFunc(base, func(r rune) bool { return r == '-' || r == '_' }) {
			if adWords[part] {
				return part
			}
		}
	}
	return ""
}

// randomSLD renvoie le libellé enregistrable s'il ressemble à une chaîne
// tirée au hasard : long, forte entropie, mélange de chiffres et de lettres
// ou peu de voyelles.
func randomSLD(name string) string {
	reg := registrable(name)
	lbl := strings.SplitN(reg, ".", 2)[0]
	if len(lbl) < 12 {
		return ""
	}
	if entropy(lbl) < 3.5 {
		return ""
	}
	vowels, digits := 0, 0
	for _, c := range lbl {
		switch {
		case strings.ContainsRune("aeiouy", c):
			vowels++
		case c >= '0' && c <= '9':
			digits++
		}
	}
	if float64(vowels)/float64(len(lbl)) > 0.3 && digits == 0 {
		return "" // probablement des mots accolés
	}
	return lbl
}

func entropy(s string) float64 {
	freq := map[rune]float64{}
	for _, c := range s {
		freq[c]++
	}
	h := 0.0
	n := float64(len(s))
	for _, f := range freq {
		p := f / n
		h -= p * math.Log2(p)
	}
	return h
}
