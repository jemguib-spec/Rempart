// Package cache is a sharded DNS response cache. Responses are stored packed
// (wire format) to keep memory low and to hand out independent copies.
//
// Two mechanisms keep answers fast when records have short TTLs (CDN of
// streaming services, often 20 to 60 s):
//   - prefetch: an entry asked for again in the last 10 % of its life is
//     refreshed in the background, so the next client never waits;
//   - serve-stale (RFC 8767): an expired entry is kept for StaleWindow and
//     handed out, with a short TTL, when the upstreams fail or are slow.
package cache

import (
	"hash/maphash"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const shards = 64

const (
	// StaleWindow : durée de conservation d'une réponse expirée (RFC 8767 §5
	// conseille 1 à 3 jours).
	StaleWindow = 24 * time.Hour
	// StaleTTL : TTL d'une réponse périmée servie (RFC 8767 §4 : 30 s).
	StaleTTL = 30
	// prefetchMinTTL : en dessous, une entrée n'est pas rafraîchie d'avance.
	prefetchMinTTL = 10 * time.Second
)

type entry struct {
	wire       []byte
	stored     time.Time
	expires    time.Time
	refreshing bool // un rafraîchissement anticipé est en cours
}

type shard struct {
	mu sync.RWMutex
	m  map[string]entry
}

type Cache struct {
	sh          [shards]shard
	seed        maphash.Seed
	maxPerShard int
	minTTL      uint32
	maxTTL      uint32
	hits, miss  atomic.Uint64
	stale       atomic.Uint64
	prefetches  atomic.Uint64
}

func New(maxEntries int, minTTL, maxTTL time.Duration) *Cache {
	c := &Cache{seed: maphash.MakeSeed(), maxPerShard: max(maxEntries/shards, 16),
		minTTL: uint32(minTTL.Seconds()), maxTTL: uint32(maxTTL.Seconds())}
	for i := range c.sh {
		c.sh[i].m = map[string]entry{}
	}
	return c
}

// Key builds the cache key for a question. The DO bit is part of the key so
// that clients asking for DNSSEC records get them.
func Key(q dns.Question, do bool) string {
	var b strings.Builder
	b.Grow(len(q.Name) + 8)
	b.WriteString(strings.ToLower(q.Name))
	b.WriteByte(byte(q.Qtype >> 8))
	b.WriteByte(byte(q.Qtype))
	b.WriteByte(byte(q.Qclass))
	if do {
		b.WriteByte(1)
	} else {
		b.WriteByte(0)
	}
	return b.String()
}

func (c *Cache) shard(key string) *shard {
	return &c.sh[maphash.String(c.seed, key)%shards]
}

// Get returns a copy of the cached response with TTLs decremented.
func (c *Cache) Get(key string) (*dns.Msg, bool) {
	s := c.shard(key)
	s.mu.RLock()
	e, ok := s.m[key]
	s.mu.RUnlock()
	now := time.Now()
	if !ok || now.After(e.expires) {
		c.miss.Add(1)
		return nil, false
	}
	m := new(dns.Msg)
	if err := m.Unpack(e.wire); err != nil {
		c.miss.Add(1)
		return nil, false
	}
	elapsed := uint32(now.Sub(e.stored).Seconds())
	setTTL(m, func(t uint32) uint32 {
		if t > elapsed {
			return t - elapsed
		}
		return 1
	})
	c.hits.Add(1)
	return m, true
}

func setTTL(m *dns.Msg, f func(uint32) uint32) {
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			h.Ttl = f(h.Ttl)
		}
	}
}

// GetStale returns an expired response kept for StaleWindow, every TTL set
// to StaleTTL (RFC 8767). Use it only when no fresh answer can be had.
func (c *Cache) GetStale(key string) (*dns.Msg, bool) {
	s := c.shard(key)
	s.mu.RLock()
	e, ok := s.m[key]
	s.mu.RUnlock()
	now := time.Now()
	if !ok || !now.After(e.expires) || now.After(e.expires.Add(StaleWindow)) {
		return nil, false
	}
	m := new(dns.Msg)
	if err := m.Unpack(e.wire); err != nil {
		return nil, false
	}
	setTTL(m, func(uint32) uint32 { return StaleTTL })
	c.stale.Add(1)
	return m, true
}

// ClaimPrefetch reports whether the fresh entry for key is in the last 10 %
// of its life and nobody is refreshing it yet; if so the caller must refresh
// it (Set clears the claim).
func (c *Cache) ClaimPrefetch(key string) bool {
	s := c.shard(key)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[key]
	if !ok || e.refreshing || now.After(e.expires) {
		return false
	}
	life := e.expires.Sub(e.stored)
	if life < prefetchMinTTL || e.expires.Sub(now) > life/10 {
		return false
	}
	e.refreshing = true
	s.m[key] = e
	c.prefetches.Add(1)
	return true
}

// Set stores a response when it is cacheable.
func (c *Cache) Set(key string, m *dns.Msg) {
	if m == nil || m.Truncated || (m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError) {
		return
	}
	ttl, ok := minTTL(m)
	if !ok {
		return
	}
	if ttl < c.minTTL {
		ttl = c.minTTL
	}
	if c.maxTTL > 0 && ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	if ttl == 0 {
		return
	}
	wire, err := m.Pack()
	if err != nil {
		return
	}
	now := time.Now()
	s := c.shard(key)
	s.mu.Lock()
	if _, exists := s.m[key]; !exists && len(s.m) >= c.maxPerShard {
		// Random eviction (Go map order is random), preferring an entry
		// already past its stale window among the first few looked at.
		victim, n := "", 0
		for k, e := range s.m {
			if victim == "" || now.After(e.expires.Add(StaleWindow)) {
				victim = k
			}
			if n++; n >= 8 || now.After(s.m[victim].expires.Add(StaleWindow)) {
				break
			}
		}
		delete(s.m, victim)
	}
	s.m[key] = entry{wire: wire, stored: now, expires: now.Add(time.Duration(ttl) * time.Second)}
	s.mu.Unlock()
}

func minTTL(m *dns.Msg) (uint32, bool) {
	var ttl uint32
	found := false
	consider := func(t uint32) {
		if !found || t < ttl {
			ttl, found = t, true
		}
	}
	for _, rr := range m.Answer {
		consider(rr.Header().Ttl)
	}
	if len(m.Answer) == 0 {
		// Negative caching (RFC 2308): min(SOA TTL, SOA MINIMUM).
		for _, rr := range m.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				consider(min(soa.Hdr.Ttl, soa.Minttl))
			}
		}
	}
	return ttl, found
}

// Flush empties the cache.
func (c *Cache) Flush() {
	for i := range c.sh {
		c.sh[i].mu.Lock()
		c.sh[i].m = map[string]entry{}
		c.sh[i].mu.Unlock()
	}
}

// StaleStats returns how many stale answers were served and how many
// entries were refreshed ahead of expiry.
func (c *Cache) StaleStats() (stale, prefetches uint64) {
	return c.stale.Load(), c.prefetches.Load()
}

// Stats returns entries, hits and misses.
func (c *Cache) Stats() (entries int, hits, misses uint64) {
	for i := range c.sh {
		c.sh[i].mu.RLock()
		entries += len(c.sh[i].m)
		c.sh[i].mu.RUnlock()
	}
	return entries, c.hits.Load(), c.miss.Load()
}
