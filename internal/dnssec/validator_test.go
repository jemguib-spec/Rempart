package dnssec

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
	"github.com/rempart-dns/rempart/internal/zones"
)

// world : une hiérarchie de zones signées et un faux résolveur récursif qui
// répond comme le ferait un résolveur en amont (DS servi par le parent).
type world struct {
	zones   map[string]*zones.Zone
	anchor  string
	queries atomic.Int64
	tamper  func(q dns.Question, r *dns.Msg)
}

func build(t *testing.T, ks keystore.Keystore, name string, signed, nsec3 bool, records ...string) *zones.Zone {
	t.Helper()
	z, err := zones.Build(ks, state.Zone{Name: name, DNSSEC: signed, Algorithm: "ECDSAP256", Records: records,
		Policy: state.ZonePolicy{NSEC3: nsec3}})
	if err != nil {
		t.Fatalf("%s : %v", name, err)
	}
	return z
}

func newWorld(t *testing.T) *world {
	ks := testutil.Keystore(t)
	ks2 := testutil.Keystore(t) // clés d'une autre « zone » pour un DS faux
	secure := build(t, ks, "secure.test.", true, false,
		"www 600 IN A 192.0.2.1", "alias IN CNAME www", "out IN CNAME www.insecure.test.", "a.b IN TXT \"x\"")
	n3 := build(t, ks, "n3.test.", true, true, "host IN A 192.0.2.3", "deep.ent IN A 192.0.2.4")
	insecure := build(t, ks, "insecure.test.", false, false, "www IN A 192.0.2.9")
	bad := build(t, ks, "bad.test.", true, false, "www IN A 192.0.2.6")
	other := build(t, ks2, "bad.test.", true, false, "www IN A 192.0.2.66")
	ds := func(z *zones.Zone) string {
		d := z.DS()[0]
		f := strings.Fields(d)
		return strings.Join(f[len(f)-4:], " ")
	}
	tld := build(t, ks, "test.", true, false,
		"secure IN NS ns.secure.test.", "secure IN DS "+ds(secure),
		"n3 IN NS ns.n3.test.", "n3 IN DS "+ds(n3),
		"insecure IN NS ns.insecure.test.",
		"bad IN NS ns.bad.test.", "bad IN DS "+ds(other),
	)
	return &world{zones: map[string]*zones.Zone{"test.": tld, "secure.test.": secure, "n3.test.": n3, "insecure.test.": insecure, "bad.test.": bad},
		anchor: tld.DS()[0]}
}

func (w *world) zoneFor(name string, t uint16) *zones.Zone {
	var best *zones.Zone
	for apex, z := range w.zones {
		if !dns.IsSubDomain(apex, name) {
			continue
		}
		if t == dns.TypeDS && apex == strings.ToLower(name) {
			continue // le DS est servi par le parent
		}
		if best == nil || dns.CountLabel(apex) > dns.CountLabel(best.Origin) {
			best = z
		}
	}
	return best
}

func (w *world) Exchange(_ context.Context, q *dns.Msg) (*dns.Msg, string, error) {
	w.queries.Add(1)
	qq := q.Question[0]
	z := w.zoneFor(qq.Name, qq.Qtype)
	if z == nil {
		r := new(dns.Msg)
		r.SetRcode(q, dns.RcodeNameError)
		return r, "faux", nil
	}
	r := z.Answer(q, true)
	r.Authoritative = false
	// Comme un résolveur : suivre un CNAME qui sort de la zone.
	if n := len(r.Answer); n > 0 {
		if c, ok := lastCNAME(r.Answer); ok && !dns.IsSubDomain(z.Origin, c) {
			sub := new(dns.Msg)
			sub.SetQuestion(c, qq.Qtype)
			sub.SetEdns0(1232, true)
			sr, _, _ := w.Exchange(context.Background(), sub)
			r.Answer = append(r.Answer, sr.Answer...)
			r.Ns, r.Rcode = sr.Ns, sr.Rcode
		}
	}
	if w.tamper != nil {
		w.tamper(qq, r)
	}
	return r, "faux", nil
}

func lastCNAME(rrs []dns.RR) (string, bool) {
	t, ok := "", false
	for _, rr := range rrs {
		if c, isC := rr.(*dns.CNAME); isC {
			t, ok = c.Target, true
		}
	}
	return t, ok
}

func (w *world) validator(t *testing.T) *Validator {
	v, err := New(w, []string{w.anchor})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func ask(t *testing.T, w *world, v *Validator, name string, qt uint16) (Status, string, *dns.Msg) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, qt)
	q.SetEdns0(1232, true)
	q.CheckingDisabled = true
	r, _, _ := w.Exchange(context.Background(), q)
	st, why := v.Validate(context.Background(), q.Question[0], r)
	return st, why, r
}

func TestValidateOutcomes(t *testing.T) {
	w := newWorld(t)
	v := w.validator(t)
	for _, c := range []struct {
		name  string
		qt    uint16
		want  Status
		rcode int
	}{
		{"www.secure.test.", dns.TypeA, Secure, dns.RcodeSuccess},
		{"alias.secure.test.", dns.TypeA, Secure, dns.RcodeSuccess},
		{"nx.secure.test.", dns.TypeA, Secure, dns.RcodeNameError},
		{"www.secure.test.", dns.TypeMX, Secure, dns.RcodeSuccess},
		{"b.secure.test.", dns.TypeTXT, Secure, dns.RcodeSuccess}, // nom intermédiaire vide
		{"secure.test.", dns.TypeDNSKEY, Secure, dns.RcodeSuccess},
		{"host.n3.test.", dns.TypeA, Secure, dns.RcodeSuccess},
		{"nx.n3.test.", dns.TypeA, Secure, dns.RcodeNameError},
		{"x.y.n3.test.", dns.TypeA, Secure, dns.RcodeNameError},
		{"host.n3.test.", dns.TypeMX, Secure, dns.RcodeSuccess},
		{"ent.n3.test.", dns.TypeA, Secure, dns.RcodeSuccess},
		{"www.insecure.test.", dns.TypeA, Insecure, dns.RcodeSuccess},
		{"nx.insecure.test.", dns.TypeA, Insecure, dns.RcodeNameError},
		{"out.secure.test.", dns.TypeA, Insecure, dns.RcodeSuccess}, // CNAME vers une zone non signée
		{"www.bad.test.", dns.TypeA, Bogus, dns.RcodeSuccess},       // DS qui ne correspond pas
		{"nx.test.", dns.TypeA, Secure, dns.RcodeNameError},
		{"autre.", dns.TypeA, Insecure, dns.RcodeNameError}, // hors de l'ancre
	} {
		st, why, r := ask(t, w, v, c.name, c.qt)
		if st != c.want || r.Rcode != c.rcode {
			t.Errorf("%s %s : %s (%s), rcode %s ; attendu %s", c.name, dns.TypeToString[c.qt], st, why, dns.RcodeToString[r.Rcode], c.want)
		}
	}
}

func TestValidateTampering(t *testing.T) {
	w := newWorld(t)
	v := w.validator(t)
	cases := map[string]struct {
		name   string
		qt     uint16
		tamper func(q dns.Question, r *dns.Msg)
	}{
		"adresse modifiée": {"www.secure.test.", dns.TypeA, func(q dns.Question, r *dns.Msg) {
			if q.Qtype == dns.TypeA {
				for _, rr := range r.Answer {
					if a, ok := rr.(*dns.A); ok {
						a.A = net.IPv4(6, 6, 6, 6)
					}
				}
			}
		}},
		"signature retirée": {"www.secure.test.", dns.TypeA, func(q dns.Question, r *dns.Msg) {
			if q.Qtype == dns.TypeA {
				r.Answer = r.Answer[:1]
			}
		}},
		"NSEC retiré": {"nx.secure.test.", dns.TypeA, func(q dns.Question, r *dns.Msg) {
			if q.Name == "nx.secure.test." {
				out := r.Ns[:0]
				for _, rr := range r.Ns {
					if rr.Header().Rrtype == dns.TypeSOA || (rr.Header().Rrtype == dns.TypeRRSIG && rr.(*dns.RRSIG).TypeCovered == dns.TypeSOA) {
						out = append(out, rr)
					}
				}
				r.Ns = out
			}
		}},
		"DS supprimé chez le parent": {"www.secure.test.", dns.TypeA, func(q dns.Question, r *dns.Msg) {
			if q.Qtype == dns.TypeDS && q.Name == "secure.test." {
				r.Answer = nil // un attaquant tente de faire passer la zone pour non signée
			}
		}},
		"rcode NXDOMAIN usurpé": {"www.secure.test.", dns.TypeA, func(q dns.Question, r *dns.Msg) {
			if q.Name == "www.secure.test." && q.Qtype == dns.TypeA {
				r.Answer = nil
				r.Rcode = dns.RcodeNameError
				r.Ns = w.zones["secure.test."].Answer(func() *dns.Msg {
					m := new(dns.Msg)
					m.SetQuestion("nx.secure.test.", dns.TypeA)
					m.SetEdns0(1232, true)
					return m
				}(), true).Ns
			}
		}},
		"NSEC3 retiré": {"nx.n3.test.", dns.TypeA, func(q dns.Question, r *dns.Msg) {
			if q.Name == "nx.n3.test." {
				out := r.Ns[:0]
				for _, rr := range r.Ns {
					if rr.Header().Rrtype != dns.TypeNSEC3 {
						out = append(out, rr)
					}
				}
				r.Ns = out
			}
		}},
	}
	for name, c := range cases {
		v.Flush()
		w.tamper = c.tamper
		if st, why, _ := ask(t, w, v, c.name, c.qt); st != Bogus {
			t.Errorf("%s : %s (%s), attendu bogus", name, st, why)
		}
	}
	w.tamper = nil
	v.Flush()
	if st, _, _ := ask(t, w, v, "www.secure.test.", dns.TypeA); st != Secure {
		t.Fatal("réponse saine refusée après les tests")
	}
}

func TestValidateExpiredAndTTL(t *testing.T) {
	w := newWorld(t)
	v := w.validator(t)
	st, _, r := ask(t, w, v, "www.secure.test.", dns.TypeA)
	if st != Secure {
		t.Fatal(st)
	}
	for _, rr := range r.Answer {
		if rr.Header().Ttl > 600 {
			t.Fatalf("TTL non borné : %v", rr)
		}
	}
	v.Flush()
	v.Now = func() time.Time { return time.Now().Add(30 * 24 * time.Hour) }
	if st, _, _ := ask(t, w, v, "www.secure.test.", dns.TypeA); st != Bogus {
		t.Fatalf("signature expirée acceptée : %s", st)
	}
}

func TestValidateCacheAndNTA(t *testing.T) {
	w := newWorld(t)
	v := w.validator(t)
	ask(t, w, v, "www.secure.test.", dns.TypeA)
	before := w.queries.Load()
	ask(t, w, v, "www.secure.test.", dns.TypeA)
	if extra := w.queries.Load() - before; extra != 1 {
		t.Fatalf("%d requêtes pour une chaîne déjà connue (1 attendue)", extra)
	}
	v.NTA = func(n string) bool { return dns.IsSubDomain("bad.test.", n) }
	if st, _, _ := ask(t, w, v, "www.bad.test.", dns.TypeA); st != Insecure {
		t.Fatalf("ancre négative ignorée : %s", st)
	}
}

func TestWrongAnchor(t *testing.T) {
	w := newWorld(t)
	other := build(t, testutil.Keystore(t), "test.", true, false, "x IN A 192.0.2.1")
	v, err := New(w, []string{other.DS()[0]})
	if err != nil {
		t.Fatal(err)
	}
	if st, _, _ := ask(t, w, v, "www.secure.test.", dns.TypeA); st != Bogus {
		t.Fatalf("mauvaise ancre : %s", st)
	}
}

func TestRootAnchorsParse(t *testing.T) {
	v, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ds := v.anchors["."]
	if len(ds) != 2 || ds[0].KeyTag != 20326 || ds[1].KeyTag != 38696 {
		t.Fatalf("%v", ds)
	}
}

func TestCompareCanonical(t *testing.T) {
	order := []string{"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.", "zABC.a.EXAMPLE.", "z.example.", "\\001.z.example.", "*.z.example.", "\\200.z.example."}
	for i := 0; i+1 < len(order); i++ {
		if compare(order[i], order[i+1]) >= 0 {
			t.Fatalf("%s doit précéder %s (RFC 4034 §6.1)", order[i], order[i+1])
		}
	}
}

// Joker (RFC 4592) : réponses synthétisées par une zone locale, NSEC et
// NSEC3, validées de bout en bout comme le ferait un résolveur.
func TestValidateWildcard(t *testing.T) {
	ks := testutil.Keystore(t)
	recs := []string{"* IN A 192.0.2.7", "fixe IN A 192.0.2.8", "*.sub IN TXT \"t\"", "*.alias IN CNAME fixe"}
	wn := build(t, ks, "w.test.", true, false, recs...)
	wn3 := build(t, ks, "wn3.test.", true, true, recs...)
	ds := func(z *zones.Zone) string {
		f := strings.Fields(z.DS()[0])
		return strings.Join(f[len(f)-4:], " ")
	}
	tld := build(t, ks, "test.", true, false,
		"w IN NS ns.w.test.", "w IN DS "+ds(wn), "wn3 IN NS ns.wn3.test.", "wn3 IN DS "+ds(wn3))
	w := &world{zones: map[string]*zones.Zone{"test.": tld, "w.test.": wn, "wn3.test.": wn3}, anchor: tld.DS()[0]}
	v := w.validator(t)
	for _, apex := range []string{"w.test.", "wn3.test."} {
		for _, c := range []struct {
			name  string
			qt    uint16
			rcode int
			ans   string // adresse ou cible attendue dans la réponse, vide pour NODATA
		}{
			{"abc." + apex, dns.TypeA, dns.RcodeSuccess, "192.0.2.7"},
			{"x.y.z." + apex, dns.TypeA, dns.RcodeSuccess, "192.0.2.7"}, // plusieurs labels sous le joker
			{"fixe." + apex, dns.TypeA, dns.RcodeSuccess, "192.0.2.8"},  // le nom exact l'emporte
			{"abc." + apex, dns.TypeMX, dns.RcodeSuccess, ""},           // NODATA par le joker
			{"q.sub." + apex, dns.TypeTXT, dns.RcodeSuccess, "t"},
			{"q.alias." + apex, dns.TypeA, dns.RcodeSuccess, "192.0.2.8"}, // CNAME synthétisé, suivi
		} {
			st, why, r := ask(t, w, v, c.name, c.qt)
			if st != Secure || r.Rcode != c.rcode {
				t.Errorf("%s %s : %s (%s), rcode %s ; attendu sûr", c.name, dns.TypeToString[c.qt], st, why, dns.RcodeToString[r.Rcode])
				continue
			}
			got := ""
			for _, rr := range r.Answer {
				switch x := rr.(type) {
				case *dns.A:
					got = x.A.String()
				case *dns.TXT:
					got = strings.Join(x.Txt, "")
				}
			}
			if got != c.ans {
				t.Errorf("%s %s : réponse %q, attendu %q", c.name, dns.TypeToString[c.qt], got, c.ans)
			}
			if c.ans != "" && !strings.EqualFold(r.Answer[0].Header().Name, c.name) {
				t.Errorf("%s : propriétaire %s, attendu le nom demandé", c.name, r.Answer[0].Header().Name)
			}
		}
	}
	// Falsification : une adresse synthétisée modifiée doit être rejetée.
	w.tamper = func(q dns.Question, r *dns.Msg) {
		for _, rr := range r.Answer {
			if a, ok := rr.(*dns.A); ok && strings.HasPrefix(q.Name, "abc.") {
				a.A = a.A.To4()
				a.A[3] = 99
			}
		}
	}
	for _, apex := range []string{"w.test.", "wn3.test."} {
		if st, _, _ := ask(t, w, w.validator(t), "abc."+apex, dns.TypeA); st != Bogus {
			t.Errorf("abc.%s falsifié : %s, attendu falsifié", apex, st)
		}
	}
}
