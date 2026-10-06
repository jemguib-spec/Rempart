// ixfr.go - historique des versions d'une zone pour les transferts
// incrémentaux (RFC 1995). L'historique est gardé en mémoire : après un
// redémarrage, un secondaire en retard reçoit la zone complète.

package zones

import (
	"strings"

	"github.com/miekg/dns"
)

const (
	maxDeltas    = 64      // versions gardées par zone
	maxDeltaRRs  = 200_000 // enregistrements gardés par zone, toutes versions
	maxDeltaSize = 50_000  // au-delà, une différence n'est pas gardée (AXFR)
)

// delta : passage d'une version à la suivante.
type delta struct {
	from, to *dns.SOA
	del, add []dns.RR
}

func (d delta) size() int { return len(d.del) + len(d.add) }

func rrKey(rr dns.RR) string {
	h := rr.Header()
	h.Name = strings.ToLower(h.Name)
	return rr.String()
}

// diff calcule les enregistrements retirés et ajoutés (hors SOA).
func diff(old, cur *Zone) (del, add []dns.RR) {
	set := func(z *Zone) map[string]dns.RR {
		m := map[string]dns.RR{}
		for _, rr := range z.AXFR() {
			if rr.Header().Rrtype == dns.TypeSOA {
				continue
			}
			m[rrKey(rr)] = rr
		}
		return m
	}
	a, b := set(old), set(cur)
	for k, rr := range a {
		if _, ok := b[k]; !ok {
			del = append(del, rr)
		}
	}
	for k, rr := range b {
		if _, ok := a[k]; !ok {
			add = append(add, rr)
		}
	}
	return del, add
}

// record ajoute à l'historique la différence entre deux versions.
func (m *Manager) record(old, cur *Zone) {
	if old.Serial() == cur.Serial() {
		return
	}
	del, add := diff(old, cur)
	d := delta{from: old.SOA(), to: cur.SOA(), del: del, add: add}
	m.histMu.Lock()
	defer m.histMu.Unlock()
	if m.hist == nil {
		m.hist = map[string][]delta{}
	}
	h := m.hist[cur.Origin]
	// L'historique doit être une chaîne continue jusqu'à la version courante.
	if n := len(h); n > 0 && h[n-1].to.Serial != old.Serial() {
		h = nil
	}
	if d.size() > maxDeltaSize {
		m.hist[cur.Origin] = nil
		return
	}
	h = append(h, d)
	total := 0
	for _, x := range h {
		total += x.size()
	}
	for len(h) > maxDeltas || (total > maxDeltaRRs && len(h) > 1) {
		total -= h[0].size()
		h = h[1:]
	}
	m.hist[cur.Origin] = h
}

// IXFR renvoie la réponse incrémentale (RFC 1995 §4) qui mène un secondaire
// de la version from à la version en service, ou false si l'historique ne
// le permet pas (le primaire envoie alors la zone complète).
func (m *Manager) IXFR(origin string, from uint32) ([]dns.RR, bool) {
	origin = strings.ToLower(dns.Fqdn(origin))
	z := m.Get(origin)
	if z == nil {
		return nil, false
	}
	m.histMu.Lock()
	defer m.histMu.Unlock()
	h := m.hist[origin]
	start := -1
	for i, d := range h {
		if d.from.Serial == from {
			start = i
			break
		}
	}
	if start < 0 || h[len(h)-1].to.Serial != z.Serial() {
		return nil, false
	}
	out := []dns.RR{z.SOA()}
	for _, d := range h[start:] {
		out = append(out, dns.Copy(d.from))
		for _, rr := range d.del {
			out = append(out, dns.Copy(rr))
		}
		out = append(out, dns.Copy(d.to))
		for _, rr := range d.add {
			out = append(out, dns.Copy(rr))
		}
	}
	return append(out, z.SOA()), true
}
