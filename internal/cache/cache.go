// Package cache is a sharded DNS response cache. Responses are stored packed
// (wire format) to keep memory low and to hand out independent copies.
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

type entry struct {
	wire    []byte
	stored  time.Time
	expires time.Time
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
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			if h.Ttl > elapsed {
				h.Ttl -= elapsed
			} else {
				h.Ttl = 1
			}
		}
	}
	c.hits.Add(1)
	return m, true
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
	if len(s.m) >= c.maxPerShard {
		for k := range s.m { // Go map iteration order is random: cheap random eviction
			delete(s.m, k)
			break
		}
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

// Stats returns entries, hits and misses.
func (c *Cache) Stats() (entries int, hits, misses uint64) {
	for i := range c.sh {
		c.sh[i].mu.RLock()
		entries += len(c.sh[i].m)
		c.sh[i].mu.RUnlock()
	}
	return entries, c.hits.Load(), c.miss.Load()
}
