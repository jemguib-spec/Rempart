// Package filter decides whether a domain is blocked.
//
// Rules from every enabled list are compiled into two hash sets (block and
// allow). A lookup walks the name's suffixes ("a.b.ads.com", "b.ads.com",
// "ads.com", "com"), so blocking a domain also blocks its subdomains and a
// lookup costs a handful of map accesses regardless of the number of rules.
// The compiled matcher is swapped atomically: reloads never block queries.
package filter

import (
	"bufio"
	"io"
	"net/netip"
	"strings"
)

// Source identifies where a rule comes from.
type Source struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Matcher is an immutable compiled rule set.
type Matcher struct {
	block   map[string]uint16
	allow   map[string]uint16
	sources []Source
}

// Result of a lookup.
type Result struct {
	Blocked bool   `json:"blocked"`
	Allowed bool   `json:"allowed"` // explicitly allow-listed
	Rule    string `json:"rule,omitempty"`
	Source  string `json:"source,omitempty"`
}

// Builder accumulates rules before compiling a Matcher.
type Builder struct {
	m *Matcher
}

func NewBuilder() *Builder {
	return &Builder{m: &Matcher{block: make(map[string]uint16, 1<<16), allow: map[string]uint16{}}}
}

// AddSource registers a source and returns its index.
func (b *Builder) AddSource(s Source) uint16 {
	b.m.sources = append(b.m.sources, s)
	return uint16(len(b.m.sources) - 1)
}

// Block adds a blocking rule. It returns false when the domain is invalid.
func (b *Builder) Block(domain string, src uint16) bool {
	d, ok := NormalizeDomain(domain)
	if !ok {
		return false
	}
	if _, exists := b.m.block[d]; !exists {
		b.m.block[d] = src
	}
	return true
}

// Allow adds an exception rule (it wins over blocking rules).
func (b *Builder) Allow(domain string, src uint16) bool {
	d, ok := NormalizeDomain(domain)
	if !ok {
		return false
	}
	b.m.allow[d] = src
	return true
}

// Build returns the compiled matcher. The builder must not be reused.
func (b *Builder) Build() *Matcher { return b.m }

// Len returns the number of blocking and allow rules.
func (m *Matcher) Len() (block, allow int) { return len(m.block), len(m.allow) }

// Match checks a fully-qualified or relative domain name.
func (m *Matcher) Match(name string) Result {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return Result{}
	}
	if d, src, ok := lookup(m.allow, name); ok {
		return Result{Allowed: true, Rule: "@@" + d, Source: m.sources[src].Name}
	}
	if d, src, ok := lookup(m.block, name); ok {
		return Result{Blocked: true, Rule: d, Source: m.sources[src].Name}
	}
	return Result{}
}

func lookup(set map[string]uint16, name string) (string, uint16, bool) {
	if len(set) == 0 {
		return "", 0, false
	}
	for {
		if src, ok := set[name]; ok {
			return name, src, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return "", 0, false
		}
		name = name[i+1:]
	}
}

var ignored = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"ip6-localhost": true, "ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true,
	"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true,
}

// NormalizeDomain lowercases a domain, strips the trailing dot and validates it.
func NormalizeDomain(d string) (string, bool) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if d == "" || len(d) > 253 || ignored[d] {
		return "", false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return "", false
		}
	}
	if d[0] == '.' || strings.Contains(d, "..") {
		return "", false
	}
	return d, true
}

// ParseStats summarises a parsed list.
type ParseStats struct {
	Block, Allow, Skipped int
}

// Parse reads a list in hosts, plain-domain or Adblock (DNS subset) format.
func Parse(r io.Reader, b *Builder, src uint16, forceAllow bool) (ParseStats, error) {
	var st ParseStats
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '!' || line[0] == '[' {
			continue
		}
		if i := strings.Index(line, " #"); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		allow := forceAllow
		switch {
		case strings.HasPrefix(line, "@@||"):
			allow = true
			line = line[4:]
			fallthrough
		case strings.HasPrefix(line, "||"):
			line = strings.TrimPrefix(line, "||")
			end := strings.IndexAny(line, "^$")
			if end < 0 {
				end = len(line)
			}
			opts := line[end:]
			// Only DNS-relevant rules: no path, no wildcard, no cosmetic options.
			if strings.Contains(opts, "$") && !strings.HasSuffix(opts, "$important") && !strings.HasSuffix(opts, "$all") {
				st.Skipped++
				continue
			}
			add(b, line[:end], src, allow, &st)
		default:
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if _, err := netip.ParseAddr(fields[0]); err == nil {
					for _, f := range fields[1:] {
						add(b, f, src, allow, &st)
					}
					continue
				}
			}
			if len(fields) == 1 && !strings.ContainsAny(line, "/*|^$") {
				add(b, fields[0], src, allow, &st)
				continue
			}
			st.Skipped++
		}
	}
	return st, sc.Err()
}

func add(b *Builder, d string, src uint16, allow bool, st *ParseStats) {
	var ok bool
	if allow {
		ok = b.Allow(d, src)
	} else {
		ok = b.Block(d, src)
	}
	switch {
	case !ok:
		st.Skipped++
	case allow:
		st.Allow++
	default:
		st.Block++
	}
}
