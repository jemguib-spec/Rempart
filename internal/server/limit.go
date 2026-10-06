package server

import (
	"net/netip"
	"sync"
	"time"
)

// Limiter is a per-client token bucket.
type Limiter struct {
	qps, burst float64
	mu         sync.Mutex
	b          map[netip.Addr]*tokens
}

type tokens struct {
	n    float64
	last time.Time
}

func NewLimiter(qps, burst float64) *Limiter {
	l := &Limiter{qps: qps, burst: burst, b: map[netip.Addr]*tokens{}}
	go func() {
		for range time.Tick(time.Minute) {
			l.mu.Lock()
			for k, t := range l.b {
				if time.Since(t.last) > 2*time.Minute {
					delete(l.b, k)
				}
			}
			l.mu.Unlock()
		}
	}()
	return l
}

func (l *Limiter) Allow(ip netip.Addr) bool {
	if l == nil || l.qps <= 0 {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	t, ok := l.b[ip]
	if !ok {
		t = &tokens{n: l.burst, last: now}
		l.b[ip] = t
	}
	t.n = min(l.burst, t.n+now.Sub(t.last).Seconds()*l.qps)
	t.last = now
	if t.n < 1 {
		return false
	}
	t.n--
	return true
}
