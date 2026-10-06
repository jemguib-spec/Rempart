package querylog

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	bucketWidth = 10 * time.Minute
	bucketCount = 144 // 24 h
	minuteCount = 60  // dernière heure, minute par minute
	hourCount   = 168 // 7 jours, heure par heure
	maxTopKeys  = 20000
	// maxLabels borne les compteurs par étiquette (type, code de réponse,
	// transport, motif, groupe) : un client hostile ne doit pas pouvoir
	// faire grossir la mémoire en inventant des valeurs.
	maxLabels = 64
	otherKey  = "autre"
)

// latencyBounds : bornes supérieures (ms) des tranches de l'histogramme de
// durée de traitement ; la dernière tranche est « au-delà ».
var latencyBounds = []float64{1, 5, 20, 50, 100, 250, 1000}

type bucket struct {
	start     int64
	queries   uint64
	blocked   uint64
	cached    uint64
	local     uint64
	failed    uint64 // erreurs et refus
	rewritten uint64
}

// slot : tranche courte (minute) ou longue (heure), sans le détail.
type slot struct {
	start   int64
	queries uint64
	blocked uint64
}

// Stats are kept in memory only: nothing here is written to disk.
//
// Deux familles de compteurs :
//   - anonymes (séries temporelles, types, codes de réponse, transports,
//     motifs de blocage, latences) : gardés dans tous les modes, y compris
//     « aucun journal », car ils ne portent ni domaine ni appareil ;
//   - nominatifs (domaines, clients, groupes) : seulement si le mode le permet.
type Stats struct {
	Total, Blocked, Cached, Local, Errors, Refused, Rewritten atomic.Uint64

	mu         sync.Mutex
	buckets    [bucketCount]bucket
	minutes    [minuteCount]slot
	hours      [hourCount]slot
	topBlocked map[string]uint64
	topDomains map[string]uint64
	topClients map[string]uint64

	qtypes  map[string]uint64
	rcodes  map[string]uint64
	protos  map[string]uint64
	reasons map[string]uint64 // motif (source) des blocages, sans le groupe
	groups  map[string]*groupCount

	latency    [8]uint64 // len(latencyBounds)+1
	latSum     float64
	latN       uint64
	upSum      float64 // requêtes résolues en amont (hors cache)
	upN        uint64
	peakMinute uint64
	peakAt     int64

	started time.Time
}

type groupCount struct{ queries, blocked uint64 }

func NewStats() *Stats {
	return &Stats{topBlocked: map[string]uint64{}, topDomains: map[string]uint64{}, topClients: map[string]uint64{},
		qtypes: map[string]uint64{}, rcodes: map[string]uint64{}, protos: map[string]uint64{}, reasons: map[string]uint64{},
		groups: map[string]*groupCount{}, started: time.Now()}
}

func bump(m map[string]uint64, k string) {
	if k == "" {
		return
	}
	if _, ok := m[k]; !ok && len(m) >= maxTopKeys {
		// Drop the least frequent half to bound memory.
		type kv struct {
			k string
			v uint64
		}
		all := make([]kv, 0, len(m))
		for k, v := range m {
			all = append(all, kv{k, v})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].v < all[j].v })
		for _, e := range all[:len(all)/2] {
			delete(m, e.k)
		}
	}
	m[k]++
}

// bumpLabel compte une étiquette dans un ensemble borné : au-delà de
// maxLabels valeurs distinctes, les nouvelles vont dans « autre ».
func bumpLabel(m map[string]uint64, k string) {
	if k == "" {
		k = otherKey
	}
	if _, ok := m[k]; !ok && len(m) >= maxLabels-1 {
		k = otherKey
	}
	m[k]++
}

// reasonOf réduit la source d'un blocage à son motif : le nom du groupe,
// déjà compté à part quand le mode le permet, est retiré.
func reasonOf(src string) string {
	if i := strings.Index(src, ", groupe "); i >= 0 {
		src = src[:i]
	}
	if strings.HasPrefix(src, "services bloqués") {
		return "services bloqués"
	}
	if strings.HasPrefix(src, "plage horaire") {
		return "plages horaires"
	}
	if len(src) > 80 {
		src = src[:80]
	}
	return src
}

func latencySlot(ms float64) int {
	for i, b := range latencyBounds {
		if ms <= b {
			return i
		}
	}
	return len(latencyBounds)
}

func ring[T any](a []T, width time.Duration, now time.Time) (*T, int64) {
	start := now.Truncate(width).Unix()
	idx := (start / int64(width.Seconds())) % int64(len(a))
	return &a[idx], start
}

// add records one query. domain/client are empty when the privacy mode
// forbids keeping them; group is kept only when keepGroup is set.
func (s *Stats) add(e Entry, blockedDomain, domain, client string, keepGroup bool) {
	s.Total.Add(1)
	switch e.Status {
	case StatusBlocked:
		s.Blocked.Add(1)
	case StatusCached:
		s.Cached.Add(1)
	case StatusLocal:
		s.Local.Add(1)
	case StatusError:
		s.Errors.Add(1)
	case StatusRefused:
		s.Refused.Add(1)
	case StatusRewritten:
		s.Rewritten.Add(1)
	}
	now := time.Now()
	blocked := e.Status == StatusBlocked
	s.mu.Lock()
	defer s.mu.Unlock()

	b, start := ring(s.buckets[:], bucketWidth, now)
	if b.start != start {
		*b = bucket{start: start}
	}
	b.queries++
	switch e.Status {
	case StatusBlocked:
		b.blocked++
	case StatusCached:
		b.cached++
	case StatusLocal:
		b.local++
	case StatusError, StatusRefused:
		b.failed++
	case StatusRewritten:
		b.rewritten++
	}
	for _, r := range []struct {
		a []slot
		w time.Duration
	}{{s.minutes[:], time.Minute}, {s.hours[:], time.Hour}} {
		sl, st := ring(r.a, r.w, now)
		if sl.start != st {
			*sl = slot{start: st}
		}
		sl.queries++
		if blocked {
			sl.blocked++
		}
		if r.w == time.Minute && sl.queries > s.peakMinute {
			s.peakMinute, s.peakAt = sl.queries, st
		}
	}

	if e.Type != "" {
		bumpLabel(s.qtypes, e.Type)
	}
	if e.Rcode != "" {
		bumpLabel(s.rcodes, e.Rcode)
	}
	if e.Proto != "" {
		bumpLabel(s.protos, e.Proto)
	}
	if blocked {
		bumpLabel(s.reasons, reasonOf(e.Source))
		bump(s.topBlocked, blockedDomain)
	}
	if e.Status != StatusRefused && e.Millis >= 0 {
		s.latency[latencySlot(e.Millis)]++
		s.latSum += e.Millis
		s.latN++
		if e.Status == StatusAllowed && e.Upstream != "" {
			s.upSum += e.Millis
			s.upN++
		}
	}
	if keepGroup && e.Status != StatusRefused {
		g := s.groups[e.Group]
		if g == nil {
			if len(s.groups) >= maxLabels {
				g = s.groups[otherKey]
				if g == nil {
					g = &groupCount{}
					s.groups[otherKey] = g
				}
			} else {
				g = &groupCount{}
				s.groups[e.Group] = g
			}
		}
		g.queries++
		if blocked {
			g.blocked++
		}
	}
	bump(s.topDomains, domain)
	bump(s.topClients, client)
}

// Point is one bucket of the time series.
type Point struct {
	T         int64  `json:"t"`
	Queries   uint64 `json:"q"`
	Blocked   uint64 `json:"b"`
	Cached    uint64 `json:"c"`
	Local     uint64 `json:"l"`
	Failed    uint64 `json:"f"`
	Rewritten uint64 `json:"r"`
}

// Slot : point d'une série courte (minute) ou longue (heure).
type Slot struct {
	T       int64  `json:"t"`
	Queries uint64 `json:"q"`
	Blocked uint64 `json:"b"`
}

// Top is a ranked counter.
type Top struct {
	Key   string `json:"key"`
	Count uint64 `json:"count"`
}

// GroupStat : activité d'un groupe d'appareils (nom vide : politique générale).
type GroupStat struct {
	Name    string `json:"name"`
	Queries uint64 `json:"q"`
	Blocked uint64 `json:"b"`
}

// Latency : histogramme des durées de traitement.
type Latency struct {
	Bounds   []float64 `json:"bounds_ms"`
	Counts   []uint64  `json:"counts"`
	AvgMs    float64   `json:"avg_ms"`
	UpAvgMs  float64   `json:"upstream_avg_ms"`
	Measured uint64    `json:"measured"`
}

// Snapshot is the JSON returned to the dashboard.
type Snapshot struct {
	Total      uint64      `json:"total"`
	Blocked    uint64      `json:"blocked"`
	Cached     uint64      `json:"cached"`
	Local      uint64      `json:"local"`
	Errors     uint64      `json:"errors"`
	Refused    uint64      `json:"refused"`
	Rewritten  uint64      `json:"rewritten"`
	Since      int64       `json:"since"`
	Series     []Point     `json:"series"`
	LastHour   []Slot      `json:"last_hour"`
	Week       []Slot      `json:"week"`
	PeakMinute uint64      `json:"peak_minute"`
	PeakAt     int64       `json:"peak_at,omitempty"`
	QTypes     []Top       `json:"qtypes"`
	Rcodes     []Top       `json:"rcodes"`
	Protocols  []Top       `json:"protocols"`
	Reasons    []Top       `json:"block_reasons"`
	Groups     []GroupStat `json:"groups"`
	Latency    Latency     `json:"latency"`
	TopBlocked []Top       `json:"top_blocked"`
	TopDomains []Top       `json:"top_domains"`
	TopClients []Top       `json:"top_clients"`
}

func topN(m map[string]uint64, n int) []Top {
	out := make([]Top, 0, len(m))
	for k, v := range m {
		out = append(out, Top{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func series[T any](a []T, width time.Duration, now time.Time, get func(*T) (int64, Slot)) []Slot {
	out := make([]Slot, 0, len(a))
	end := now.Truncate(width)
	for i := len(a) - 1; i >= 0; i-- {
		start := end.Add(-time.Duration(i) * width).Unix()
		idx := (start / int64(width.Seconds())) % int64(len(a))
		p := Slot{T: start}
		if st, v := get(&a[idx]); st == start {
			p.Queries, p.Blocked = v.Queries, v.Blocked
		}
		out = append(out, p)
	}
	return out
}

func (s *Stats) Snapshot() Snapshot {
	snap := Snapshot{Total: s.Total.Load(), Blocked: s.Blocked.Load(), Cached: s.Cached.Load(),
		Local: s.Local.Load(), Errors: s.Errors.Load(), Refused: s.Refused.Load(), Rewritten: s.Rewritten.Load(),
		Since: s.started.Unix()}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	end := now.Truncate(bucketWidth)
	for i := bucketCount - 1; i >= 0; i-- {
		start := end.Add(-time.Duration(i) * bucketWidth).Unix()
		idx := (start / int64(bucketWidth.Seconds())) % bucketCount
		p := Point{T: start}
		if b := s.buckets[idx]; b.start == start {
			p.Queries, p.Blocked, p.Cached, p.Local, p.Failed, p.Rewritten = b.queries, b.blocked, b.cached, b.local, b.failed, b.rewritten
		}
		snap.Series = append(snap.Series, p)
	}
	get := func(x *slot) (int64, Slot) { return x.start, Slot{Queries: x.queries, Blocked: x.blocked} }
	snap.LastHour = series(s.minutes[:], time.Minute, now, get)
	snap.Week = series(s.hours[:], time.Hour, now, get)
	snap.PeakMinute, snap.PeakAt = s.peakMinute, s.peakAt

	snap.QTypes = topN(s.qtypes, 12)
	snap.Rcodes = topN(s.rcodes, 12)
	snap.Protocols = topN(s.protos, 12)
	snap.Reasons = topN(s.reasons, 12)
	snap.Groups = make([]GroupStat, 0, len(s.groups))
	for k, g := range s.groups {
		snap.Groups = append(snap.Groups, GroupStat{Name: k, Queries: g.queries, Blocked: g.blocked})
	}
	sort.Slice(snap.Groups, func(i, j int) bool {
		if snap.Groups[i].Queries != snap.Groups[j].Queries {
			return snap.Groups[i].Queries > snap.Groups[j].Queries
		}
		return snap.Groups[i].Name < snap.Groups[j].Name
	})
	snap.Latency = Latency{Bounds: latencyBounds, Counts: append([]uint64(nil), s.latency[:]...), Measured: s.latN}
	if s.latN > 0 {
		snap.Latency.AvgMs = s.latSum / float64(s.latN)
	}
	if s.upN > 0 {
		snap.Latency.UpAvgMs = s.upSum / float64(s.upN)
	}

	snap.TopBlocked = topN(s.topBlocked, 10)
	snap.TopDomains = topN(s.topDomains, 10)
	snap.TopClients = topN(s.topClients, 10)
	return snap
}

// forget erases per-domain and per-client counters (used when the privacy
// mode becomes stricter). groups : activité par groupe d'appareils.
func (s *Stats) forget(domains, clients, groups bool) {
	s.mu.Lock()
	if domains {
		s.topDomains = map[string]uint64{}
	}
	if clients {
		s.topClients = map[string]uint64{}
	}
	if groups {
		s.groups = map[string]*groupCount{}
	}
	s.mu.Unlock()
}

// forgetBlocked efface les domaines bloqués (mode « aucun journal »).
func (s *Stats) forgetBlocked() {
	s.mu.Lock()
	s.topBlocked = map[string]uint64{}
	s.mu.Unlock()
}
