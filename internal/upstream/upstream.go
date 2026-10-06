// Package upstream forwards queries to recursive resolvers over plain DNS,
// DNS-over-TLS (RFC 7858) or DNS-over-HTTPS (RFC 8484). Encrypted queries
// are padded (RFC 8467) so that their size does not reveal the name asked.
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Upstream is one resolver.
type Upstream interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
	String() string
	Encrypted() bool
}

// Options shared by all upstreams.
type Options struct {
	Bootstrap []string // plain DNS servers used to resolve upstream hostnames
	Timeout   time.Duration
	RootCAs   *x509.CertPool // nil = system roots (set it for an internal PKI)
}

func (o Options) resolver() *net.Resolver {
	if len(o.Bootstrap) == 0 {
		return net.DefaultResolver
	}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		var last error
		for _, b := range o.Bootstrap {
			c, err := d.DialContext(ctx, network, withPort(b, "53"))
			if err == nil {
				return c, nil
			}
			last = err
		}
		return nil, last
	}}
}

func withPort(hostport, port string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(strings.Trim(hostport, "[]"), port)
}

// Parse builds an upstream from a spec:
//
//	9.9.9.9 | udp://9.9.9.9:53 | tcp://9.9.9.9
//	tls://dns.quad9.net | tls://9.9.9.9:853#dns.quad9.net
//	https://dns.quad9.net/dns-query | https://dns.quad9.net/dns-query#9.9.9.9
func Parse(spec string, o Options) (Upstream, error) {
	if o.Timeout == 0 {
		o.Timeout = 4 * time.Second
	}
	spec = strings.TrimSpace(spec)
	pin := ""
	if i := strings.LastIndexByte(spec, '#'); i > 0 {
		spec, pin = spec[:i], spec[i+1:]
	}
	switch {
	case strings.HasPrefix(spec, "https://"):
		return newDoH(spec, pin, o)
	case strings.HasPrefix(spec, "tls://"):
		host := strings.TrimPrefix(spec, "tls://")
		addr := withPort(host, "853")
		sni := pin
		if sni == "" {
			sni, _, _ = net.SplitHostPort(addr)
		}
		return &dot{addr: addr, sni: sni, o: o, res: o.resolver()}, nil
	case strings.HasPrefix(spec, "tcp://"):
		return &plain{addr: withPort(strings.TrimPrefix(spec, "tcp://"), "53"), tcpOnly: true, o: o}, nil
	default:
		addr := withPort(strings.TrimPrefix(spec, "udp://"), "53")
		if h, _, _ := net.SplitHostPort(addr); net.ParseIP(h) == nil {
			return nil, fmt.Errorf("upstream %q : une adresse IP est requise pour le DNS en clair", spec)
		}
		return &plain{addr: addr, o: o}, nil
	}
}

// ---- plain DNS ----

type plain struct {
	addr    string
	tcpOnly bool
	o       Options
}

func (p *plain) String() string {
	if p.tcpOnly {
		return "tcp://" + p.addr
	}
	return "udp://" + p.addr
}
func (p *plain) Encrypted() bool { return false }

func (p *plain) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	if !p.tcpOnly {
		c := &dns.Client{Net: "udp", Timeout: p.o.Timeout, UDPSize: 1232}
		r, _, err := c.ExchangeContext(ctx, m, p.addr)
		if err == nil && !r.Truncated {
			return r, nil
		}
		if err != nil {
			return nil, err
		}
	}
	c := &dns.Client{Net: "tcp", Timeout: p.o.Timeout}
	r, _, err := c.ExchangeContext(ctx, m, p.addr)
	return r, err
}

// ---- DNS over TLS with connection reuse ----

type dot struct {
	addr string
	sni  string
	o    Options
	res  *net.Resolver

	mu   sync.Mutex
	idle []*dns.Conn
}

func (d *dot) String() string  { return "tls://" + d.addr + "#" + d.sni }
func (d *dot) Encrypted() bool { return true }

func (d *dot) dial(ctx context.Context) (*dns.Conn, error) {
	host, port, _ := net.SplitHostPort(d.addr)
	ips := []string{host}
	if net.ParseIP(host) == nil {
		var err error
		if ips, err = d.res.LookupHost(ctx, host); err != nil {
			return nil, err
		}
	}
	dialer := &net.Dialer{Timeout: d.o.Timeout}
	var last error
	for _, ip := range ips {
		raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
		if err != nil {
			last = err
			continue
		}
		tc := tls.Client(raw, &tls.Config{ServerName: d.sni, MinVersion: tls.VersionTLS12, RootCAs: d.o.RootCAs})
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			last = err
			continue
		}
		return &dns.Conn{Conn: tc}, nil
	}
	return nil, last
}

func (d *dot) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	q := pad(m)
	for attempt := 0; attempt < 2; attempt++ {
		var conn *dns.Conn
		reused := false
		d.mu.Lock()
		if n := len(d.idle); n > 0 {
			conn, d.idle = d.idle[n-1], d.idle[:n-1]
			reused = true
		}
		d.mu.Unlock()
		if conn == nil {
			var err error
			if conn, err = d.dial(ctx); err != nil {
				return nil, err
			}
		}
		deadline := time.Now().Add(d.o.Timeout)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		_ = conn.SetDeadline(deadline)
		c := &dns.Client{Net: "tcp-tls", Timeout: d.o.Timeout}
		r, _, err := c.ExchangeWithConnContext(ctx, q, conn)
		if err != nil {
			conn.Close()
			if reused {
				continue // the server probably closed an idle connection
			}
			return nil, err
		}
		d.mu.Lock()
		if len(d.idle) < 8 {
			d.idle = append(d.idle, conn)
		} else {
			conn.Close()
		}
		d.mu.Unlock()
		return r, nil
	}
	return nil, errors.New("échec DoT")
}

// ---- DNS over HTTPS ----

type doh struct {
	url    string
	client *http.Client
}

func newDoH(spec, pin string, o Options) (*doh, error) {
	u, err := url.Parse(spec)
	if err != nil {
		return nil, err
	}
	res := o.resolver()
	dialer := &net.Dialer{Timeout: o.Timeout}
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname(), RootCAs: o.RootCAs},
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
		Proxy:               nil, // never send DNS through an HTTP proxy implicitly
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, _ := net.SplitHostPort(addr)
			ips := []string{host}
			if pin != "" {
				ips = []string{pin}
			} else if net.ParseIP(host) == nil {
				if ips, err = res.LookupHost(ctx, host); err != nil {
					return nil, err
				}
			}
			var last error
			for _, ip := range ips {
				c, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		},
	}
	return &doh{url: spec, client: &http.Client{Transport: tr, Timeout: o.Timeout}}, nil
}

func (d *doh) String() string  { return d.url }
func (d *doh) Encrypted() bool { return true }

func (d *doh) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	q := pad(m)
	id := q.Id
	q.Id = 0 // RFC 8484 §4.1: use ID 0 for HTTP cache friendliness
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, err
	}
	r.Id = id
	return r, nil
}

// pad returns a copy of m padded to a multiple of 128 bytes (RFC 8467).
func pad(m *dns.Msg) *dns.Msg {
	q := m.Copy()
	opt := q.IsEdns0()
	if opt == nil {
		q.SetEdns0(1232, false)
		opt = q.IsEdns0()
	}
	kept := opt.Option[:0]
	for _, o := range opt.Option {
		if o.Option() != dns.EDNS0PADDING {
			kept = append(kept, o)
		}
	}
	opt.Option = kept
	n := q.Len() + 4 // option code + length
	padLen := (128 - n%128) % 128
	opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, padLen)})
	return q
}

// ---- group ----

// Stat is exposed in the web interface.
type Stat struct {
	Name      string  `json:"name"`
	Domain    string  `json:"domain,omitempty"` // transfert conditionnel
	Encrypted bool    `json:"encrypted"`
	Queries   uint64  `json:"queries"`
	Errors    uint64  `json:"errors"`
	AvgMs     float64 `json:"avg_ms"`
}

type member struct {
	u       Upstream
	queries atomic.Uint64
	errors  atomic.Uint64
	totalUs atomic.Uint64
}

// Group races two random upstreams and falls back on the others.
type Group struct {
	members []*member
}

func NewGroup(us []Upstream) (*Group, error) {
	if len(us) == 0 {
		return nil, errors.New("aucun upstream configuré")
	}
	g := &Group{}
	for _, u := range us {
		g.members = append(g.members, &member{u: u})
	}
	return g, nil
}

type answer struct {
	r   *dns.Msg
	m   *member
	err error
}

func (g *Group) call(ctx context.Context, mb *member, q *dns.Msg, out chan<- answer) {
	start := time.Now()
	r, err := mb.u.Exchange(ctx, q)
	mb.queries.Add(1)
	if err != nil {
		mb.errors.Add(1)
	} else {
		mb.totalUs.Add(uint64(time.Since(start).Microseconds()))
	}
	out <- answer{r, mb, err}
}

// Exchange returns the first successful answer and the upstream name.
func (g *Group) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, string, error) {
	order := rand.Perm(len(g.members))
	first := order[:min(2, len(order))]
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	out := make(chan answer, len(order))
	for _, i := range first {
		go g.call(ctx, g.members[i], q, out)
	}
	var last error
	for range first {
		a := <-out
		if a.err == nil && a.r != nil && a.r.Rcode != dns.RcodeServerFailure {
			return a.r, a.m.u.String(), nil
		}
		last = a.err
	}
	for _, i := range order[len(first):] {
		go g.call(ctx, g.members[i], q, out)
		a := <-out
		if a.err == nil && a.r != nil {
			return a.r, a.m.u.String(), nil
		}
		last = a.err
	}
	if last == nil {
		last = errors.New("SERVFAIL de tous les upstreams")
	}
	return nil, "", last
}

func (g *Group) Stats() []Stat {
	out := make([]Stat, 0, len(g.members))
	for _, m := range g.members {
		q, e := m.queries.Load(), m.errors.Load()
		s := Stat{Name: m.u.String(), Encrypted: m.u.Encrypted(), Queries: q, Errors: e}
		if ok := q - e; ok > 0 {
			s.AvgMs = float64(m.totalUs.Load()) / float64(ok) / 1000
		}
		out = append(out, s)
	}
	return out
}
