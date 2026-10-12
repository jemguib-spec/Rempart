// solver.go - défi dns-01 chez un fournisseur public : suivi d'une
// délégation CNAME de _acme-challenge, puis attente que chaque serveur
// faisant autorité de la zone serve le TXT avant de demander la validation.

package acmedns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Solver relie un Provider au client ACME.
type Solver struct {
	P         Provider
	Resolvers []string      // résolveurs récursifs en clair (ip ou ip:port) ; défaut 9.9.9.9, 1.1.1.1
	Timeout   time.Duration // attente maximale de la propagation (défaut 4 min)
	Interval  time.Duration // entre deux vérifications (défaut 5 s)
	Fallback  time.Duration // délai fixe si aucun serveur ne répond (DNS sortant filtré ; défaut 90 s)
	Progress  func(string)

	exchange func(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error)
	mu       sync.Mutex
	targets  map[string]string // nom demandé → nom publié (après CNAME)
}

func (s *Solver) say(msg string) {
	if s.Progress != nil {
		s.Progress(msg)
	}
}

func (s *Solver) resolvers() []string {
	r := s.Resolvers
	if len(r) == 0 {
		r = []string{"9.9.9.9", "1.1.1.1"}
	}
	out := make([]string, 0, len(r))
	for _, a := range r {
		if _, _, err := net.SplitHostPort(a); err != nil {
			a = net.JoinHostPort(a, "53")
		}
		out = append(out, a)
	}
	return out
}

func defaultExchange(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
	c := &dns.Client{Timeout: 4 * time.Second}
	r, _, err := c.ExchangeContext(ctx, m, addr)
	if err == nil && r.Truncated {
		c.Net = "tcp"
		r, _, err = c.ExchangeContext(ctx, m, addr)
	}
	return r, err
}

func (s *Solver) ex(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
	if s.exchange != nil {
		return s.exchange(ctx, m, addr)
	}
	return defaultExchange(ctx, m, addr)
}

// recursive interroge les résolveurs récursifs jusqu'à une réponse exploitable.
func (s *Solver) recursive(ctx context.Context, name string, qt uint16) (*dns.Msg, error) {
	var last error = errors.New("aucun résolveur")
	for _, a := range s.resolvers() {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qt)
		m.RecursionDesired = true
		r, err := s.ex(ctx, m, a)
		if err != nil {
			last = err
			continue
		}
		if r.Rcode == dns.RcodeSuccess || r.Rcode == dns.RcodeNameError {
			return r, nil
		}
		last = fmt.Errorf("%s : %s", a, dns.RcodeToString[r.Rcode])
	}
	return nil, last
}

// target suit les CNAME de _acme-challenge (l'AC les suit aussi) : la clé
// d'API peut ainsi n'avoir de droits que sur une petite zone dédiée.
func (s *Solver) target(ctx context.Context, fqdn string) string {
	name := dns.Fqdn(strings.ToLower(fqdn))
	for range 8 {
		r, err := s.recursive(ctx, name, dns.TypeCNAME)
		if err != nil {
			return name
		}
		next := ""
		for _, rr := range r.Answer {
			if c, ok := rr.(*dns.CNAME); ok && strings.EqualFold(c.Hdr.Name, name) {
				next = strings.ToLower(c.Target)
			}
		}
		if next == "" || next == name {
			return name
		}
		name = next
	}
	return name
}

// Present publie le TXT, au bout de la délégation CNAME s'il y en a une.
func (s *Solver) Present(ctx context.Context, fqdn, value string) error {
	t := s.target(ctx, fqdn)
	s.mu.Lock()
	if s.targets == nil {
		s.targets = map[string]string{}
	}
	s.targets[dns.Fqdn(strings.ToLower(fqdn))] = t
	s.mu.Unlock()
	if t != dns.Fqdn(strings.ToLower(fqdn)) {
		s.say(fmt.Sprintf("%s est délégué par CNAME à %s", strings.TrimSuffix(fqdn, "."), strings.TrimSuffix(t, ".")))
	}
	return s.P.Present(ctx, t, value)
}

func (s *Solver) published(fqdn string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.targets[dns.Fqdn(strings.ToLower(fqdn))]; ok {
		return t
	}
	return dns.Fqdn(strings.ToLower(fqdn))
}

// CleanUp retire le TXT publié.
func (s *Solver) CleanUp(ctx context.Context, fqdn, value string) error {
	return s.P.CleanUp(ctx, s.published(fqdn), value)
}

// authServers trouve les adresses des serveurs faisant autorité pour name.
func (s *Solver) authServers(ctx context.Context, name string) ([]string, error) {
	labels := dns.SplitDomainName(name)
	var hosts []string
	for i := range labels {
		zone := dns.Fqdn(strings.Join(labels[i:], "."))
		r, err := s.recursive(ctx, zone, dns.TypeNS)
		if err != nil {
			return nil, err
		}
		for _, rr := range r.Answer {
			if ns, ok := rr.(*dns.NS); ok && strings.EqualFold(ns.Hdr.Name, zone) {
				hosts = append(hosts, ns.Ns)
			}
		}
		if len(hosts) > 0 {
			break
		}
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("serveurs de la zone de %s introuvables", name)
	}
	var addrs []string
	for _, h := range hosts {
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			r, err := s.recursive(ctx, h, qt)
			if err != nil {
				continue
			}
			for _, rr := range r.Answer {
				switch a := rr.(type) {
				case *dns.A:
					addrs = append(addrs, net.JoinHostPort(a.A.String(), "53"))
				case *dns.AAAA:
					addrs = append(addrs, net.JoinHostPort(a.AAAA.String(), "53"))
				}
			}
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("adresses des serveurs de la zone de %s introuvables", name)
	}
	return addrs, nil
}

// has interroge un serveur faisant autorité, sans récursion.
func (s *Solver) has(ctx context.Context, addr, name string, want []string) (bool, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeTXT)
	m.RecursionDesired = false
	r, err := s.ex(ctx, m, addr)
	if err != nil {
		return false, err
	}
	got := map[string]bool{}
	for _, rr := range r.Answer {
		if t, ok := rr.(*dns.TXT); ok && strings.EqualFold(t.Hdr.Name, name) {
			got[strings.Join(t.Txt, "")] = true
		}
	}
	for _, w := range want {
		if !got[w] {
			return false, nil
		}
	}
	return true, nil
}

// Wait attend que chaque TXT soit servi par tous les serveurs faisant
// autorité de sa zone. Si aucun ne répond (DNS sortant filtré), attend le
// délai fixe puis laisse l'AC essayer.
func (s *Solver) Wait(ctx context.Context, recs map[string][]string) error {
	timeout, interval, fallback := s.Timeout, s.Interval, s.Fallback
	if timeout <= 0 {
		timeout = 4 * time.Minute
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if fallback <= 0 {
		fallback = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type check struct {
		name    string
		want    []string
		servers []string
	}
	var checks []check
	for n, v := range recs {
		name := s.published(n)
		srv, err := s.authServers(ctx, name)
		if err != nil {
			s.say(fmt.Sprintf("vérification de la propagation impossible (%v) : attente fixe de %s", err, fallback))
			return sleep(ctx, fallback)
		}
		checks = append(checks, check{name, v, srv})
	}
	s.say("attente de la propagation chez les serveurs faisant autorité")
	answered := false
	for {
		pending := ""
		for _, c := range checks {
			for _, a := range c.servers {
				ok, err := s.has(ctx, a, c.name, c.want)
				if err == nil {
					answered = true
				}
				if !ok && pending == "" {
					pending = fmt.Sprintf("%s sur %s", strings.TrimSuffix(c.name, "."), a)
				}
			}
		}
		if pending == "" {
			return nil
		}
		if !answered {
			s.say(fmt.Sprintf("aucun serveur faisant autorité ne répond : attente fixe de %s", fallback))
			return sleep(ctx, fallback)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("le TXT n'est toujours pas visible (%s) après %s", pending, timeout)
		case <-time.After(interval):
		}
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
