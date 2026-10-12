package acmedns

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	appKey = "AbCdEf0123456789"
	appSec = "SecretSecretSecretSecret01234567"
	consKy = "ConsumerConsumerConsumer01234567"
)

// fakeOVH vérifie la signature de chaque requête comme l'API OVH.
type fakeOVH struct {
	mu      sync.Mutex
	records map[int64][2]string // id → sous-domaine, valeur
	next    int64
	refresh int
	srv     *httptest.Server
}

func newFakeOVH(t *testing.T) *fakeOVH {
	f := &fakeOVH{records: map[int64][2]string{}, next: 100}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /1.0/auth/time", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, time.Now().Unix()+42)
	})
	check := func(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
		body, _ := io.ReadAll(r.Body)
		u := f.srv.URL + r.URL.RequestURI()
		ts := r.Header.Get("X-Ovh-Timestamp")
		n, _ := strconv.ParseInt(ts, 10, 64)
		h := sha1.Sum([]byte(appSec + "+" + consKy + "+" + r.Method + "+" + u + "+" + string(body) + "+" + ts))
		if r.Header.Get("X-Ovh-Application") != appKey || r.Header.Get("X-Ovh-Consumer") != consKy ||
			r.Header.Get("X-Ovh-Signature") != "$1$"+hex.EncodeToString(h[:]) || abs(n-(time.Now().Unix()+42)) > 5 {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"message":"Invalid signature"}`)
			return nil, false
		}
		return body, true
	}
	mux.HandleFunc("POST /1.0/domain/zone/example.fr/record", func(w http.ResponseWriter, r *http.Request) {
		b, ok := check(w, r)
		if !ok {
			return
		}
		var in struct {
			FieldType, SubDomain, Target string
			TTL                          int
		}
		_ = json.Unmarshal(b, &in)
		if in.FieldType != "TXT" || in.TTL != 60 {
			w.WriteHeader(400)
			return
		}
		f.mu.Lock()
		f.next++
		f.records[f.next] = [2]string{in.SubDomain, in.Target}
		id := f.next
		f.mu.Unlock()
		fmt.Fprintf(w, `{"id":%d,"zone":"example.fr"}`, id)
	})
	mux.HandleFunc("GET /1.0/domain/zone/example.fr/record", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := check(w, r); !ok {
			return
		}
		ids := []int64{}
		f.mu.Lock()
		for id, rec := range f.records {
			if rec[0] == r.URL.Query().Get("subDomain") {
				ids = append(ids, id)
			}
		}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(ids)
	})
	mux.HandleFunc("GET /1.0/domain/zone/example.fr/record/{id}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := check(w, r); !ok {
			return
		}
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		f.mu.Lock()
		rec := f.records[id]
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "subDomain": rec[0], "target": `"` + rec[1] + `"`})
	})
	mux.HandleFunc("DELETE /1.0/domain/zone/example.fr/record/{id}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := check(w, r); !ok {
			return
		}
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		f.mu.Lock()
		delete(f.records, id)
		f.mu.Unlock()
		fmt.Fprint(w, "null")
	})
	mux.HandleFunc("POST /1.0/domain/zone/example.fr/refresh", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := check(w, r); !ok {
			return
		}
		f.mu.Lock()
		f.refresh++
		f.mu.Unlock()
		fmt.Fprint(w, "null")
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func ovhProvider(t *testing.T, f *fakeOVH, secret string) *ovh {
	p, err := New(Config{Provider: "ovh", Zone: "Example.fr.", OVHEndpoint: "ovh-eu", OVHAppKey: appKey,
		OVHAppSecret: secret, OVHConsumerKey: consKy, base: f.srv.URL + "/1.0"})
	if err != nil {
		t.Fatal(err)
	}
	o := p.(*ovh)
	o.hc.Transport = f.srv.Client().Transport
	return o
}

func TestOVH(t *testing.T) {
	f := newFakeOVH(t)
	o := ovhProvider(t, f, appSec)
	ctx := context.Background()
	if err := o.Present(ctx, "_acme-challenge.dns.example.fr.", "v1"); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 1 || f.refresh != 1 {
		t.Fatalf("records=%v refresh=%d", f.records, f.refresh)
	}
	for _, r := range f.records {
		if r != [2]string{"_acme-challenge.dns", "v1"} {
			t.Fatalf("enregistrement %v", r)
		}
	}
	if err := o.CleanUp(ctx, "_acme-challenge.dns.example.fr", "v1"); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 0 || f.refresh != 2 {
		t.Fatalf("après retrait : %v, %d", f.records, f.refresh)
	}
	// Retrait après un redémarrage : l'identifiant est retrouvé par la valeur.
	if err := o.Present(ctx, "_acme-challenge.dns.example.fr", "v2"); err != nil {
		t.Fatal(err)
	}
	o2 := ovhProvider(t, f, appSec)
	if err := o2.CleanUp(ctx, "_acme-challenge.dns.example.fr", "autre"); err != nil || len(f.records) != 1 {
		t.Fatalf("une autre valeur ne doit rien retirer : %v %v", err, f.records)
	}
	if err := o2.CleanUp(ctx, "_acme-challenge.dns.example.fr", "v2"); err != nil || len(f.records) != 0 {
		t.Fatalf("retrait par valeur : %v %v", err, f.records)
	}
	// Hors zone.
	if err := o.Present(ctx, "_acme-challenge.example.com", "v"); err == nil || !strings.Contains(err.Error(), "n'est pas dans la zone") {
		t.Fatalf("hors zone : %v", err)
	}
}

func TestOVHBadSecret(t *testing.T) {
	f := newFakeOVH(t)
	bad := strings.Repeat("x", 32)
	o := ovhProvider(t, f, bad)
	err := o.Present(context.Background(), "_acme-challenge.example.fr", "v")
	if err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), bad) || strings.Contains(err.Error(), consKy) {
		t.Fatalf("erreur attendue sans secret : %v", err)
	}
}

func TestCloudflare(t *testing.T) {
	const tok = "cf_Token-0123456789abcdefghij0123456789"
	var mu sync.Mutex
	recs := map[string]string{}
	n := 0
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+tok {
			w.WriteHeader(403)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}]}`)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /zones", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		if r.URL.Query().Get("name") != "example.fr" {
			fmt.Fprint(w, `{"success":true,"result":[]}`)
			return
		}
		fmt.Fprint(w, `{"success":true,"result":[{"id":"0123abcd","name":"example.fr"}]}`)
	})
	mux.HandleFunc("POST /zones/0123abcd/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		var in struct{ Type, Name, Content string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Type != "TXT" || in.Name != "_acme-challenge.example.fr" {
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		n++
		id := fmt.Sprintf("ab%02d", n)
		recs[id] = in.Content
		mu.Unlock()
		fmt.Fprintf(w, `{"success":true,"result":{"id":%q}}`, id)
	})
	mux.HandleFunc("GET /zones/0123abcd/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		out := []map[string]string{}
		mu.Lock()
		for id, c := range recs {
			out = append(out, map[string]string{"id": id, "content": c})
		}
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": out})
	})
	mux.HandleFunc("DELETE /zones/0123abcd/dns_records/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		mu.Lock()
		delete(recs, r.PathValue("id"))
		mu.Unlock()
		fmt.Fprint(w, `{"success":true,"result":{}}`)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	mk := func(token string) *cloudflare {
		p, err := New(Config{Provider: "cloudflare", Zone: "example.fr", CloudflareToken: token, base: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		c := p.(*cloudflare)
		c.hc.Transport = srv.Client().Transport
		return c
	}
	c := mk(tok)
	ctx := context.Background()
	if err := c.Present(ctx, "_acme-challenge.example.fr.", "val"); err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs["ab01"] != `"val"` {
		t.Fatalf("%v", recs)
	}
	if err := c.CleanUp(ctx, "_acme-challenge.example.fr.", "val"); err != nil || len(recs) != 0 {
		t.Fatalf("%v %v", err, recs)
	}
	_ = c.Present(ctx, "_acme-challenge.example.fr.", "v2")
	if err := mk(tok).CleanUp(ctx, "_acme-challenge.example.fr.", "v2"); err != nil || len(recs) != 0 {
		t.Fatalf("retrait après redémarrage : %v %v", err, recs)
	}
	err := mk("wrong-token-0123456789").Present(ctx, "_acme-challenge.example.fr", "v")
	if err == nil || !strings.Contains(err.Error(), "9109") || strings.Contains(err.Error(), "wrong-token") {
		t.Fatalf("jeton refusé : %v", err)
	}
}

func TestNoRedirect(t *testing.T) {
	leak := make(chan string, 1)
	other := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		leak <- r.Header.Get("Authorization")
	}))
	defer other.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/zones", http.StatusFound)
	}))
	defer srv.Close()
	p, _ := New(Config{Provider: "cloudflare", Zone: "example.fr", CloudflareToken: "token-0123456789", base: srv.URL})
	p.(*cloudflare).hc.Transport = srv.Client().Transport
	if err := p.Present(context.Background(), "_acme-challenge.example.fr", "v"); err == nil {
		t.Fatal("redirection suivie")
	}
	select {
	case h := <-leak:
		t.Fatalf("en-tête envoyé ailleurs : %q", h)
	default:
	}
}

func TestValidate(t *testing.T) {
	good := Config{Provider: "ovh", Zone: "example.fr", OVHEndpoint: "ovh-eu", OVHAppKey: appKey, OVHAppSecret: appSec, OVHConsumerKey: consKy}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []Config{
		{Provider: "ovh", Zone: "example.fr", OVHEndpoint: "ovh-xx", OVHAppKey: appKey, OVHAppSecret: appSec, OVHConsumerKey: consKy},
		{Provider: "ovh", Zone: "fr", OVHEndpoint: "ovh-eu", OVHAppKey: appKey, OVHAppSecret: appSec, OVHConsumerKey: consKy},
		{Provider: "ovh", Zone: "example.fr/../x", OVHEndpoint: "ovh-eu", OVHAppKey: appKey, OVHAppSecret: appSec, OVHConsumerKey: consKy},
		{Provider: "cloudflare", Zone: "example.fr"},
		{Provider: "gandi", Zone: "example.fr"},
	} {
		if c.Validate() == nil {
			t.Errorf("accepté : %+v", c)
		}
	}
	if u := OVHTokenURL("ovh-eu", "example.fr"); !strings.Contains(u, "DELETE=/domain/zone/example.fr/record/*") {
		t.Fatal(u)
	}
}

// fakeDNS simule résolveur récursif et serveurs faisant autorité.
type fakeDNS struct {
	mu        sync.Mutex
	cname     map[string]string
	published map[string][]string // nom → TXT visibles chez ns1 et ns2
	lagNS2    int                 // nombre de requêtes avant que ns2 voie le TXT
	down      bool
}

func (f *fakeDNS) exchange(_ context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := m.Question[0]
	r := new(dns.Msg)
	r.SetReply(m)
	auth := strings.HasPrefix(addr, "192.0.2.")
	if f.down && auth {
		return nil, errors.New("timeout")
	}
	if !auth { // récursif
		switch q.Qtype {
		case dns.TypeCNAME:
			if t, ok := f.cname[q.Name]; ok {
				r.Answer = append(r.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: 1}, Target: t})
			}
		case dns.TypeNS:
			if q.Name == "example.fr." || q.Name == "acme.example.net." {
				for _, h := range []string{"ns1.ovh.net.", "ns2.ovh.net."} {
					r.Answer = append(r.Answer, &dns.NS{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: 1}, Ns: h})
				}
			}
		case dns.TypeA:
			ip := map[string]string{"ns1.ovh.net.": "192.0.2.1", "ns2.ovh.net.": "192.0.2.2"}[q.Name]
			if ip != "" {
				r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: 1}, A: net.ParseIP(ip)})
			}
		}
		return r, nil
	}
	if q.Qtype == dns.TypeTXT && !m.RecursionDesired {
		if addr == "192.0.2.2:53" && f.lagNS2 > 0 {
			f.lagNS2--
			return r, nil
		}
		for _, v := range f.published[q.Name] {
			r.Answer = append(r.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: 1}, Txt: []string{v}})
		}
	}
	return r, nil
}

type memProvider struct{ f *fakeDNS }

func (p memProvider) Present(_ context.Context, fqdn, v string) error {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	p.f.published[dns.Fqdn(fqdn)] = append(p.f.published[dns.Fqdn(fqdn)], v)
	return nil
}

func (p memProvider) CleanUp(_ context.Context, fqdn, _ string) error {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	delete(p.f.published, dns.Fqdn(fqdn))
	return nil
}

func TestSolverWaitsForAllServers(t *testing.T) {
	f := &fakeDNS{cname: map[string]string{}, published: map[string][]string{}, lagNS2: 3}
	s := &Solver{P: memProvider{f}, Interval: time.Millisecond, exchange: f.exchange}
	ctx := context.Background()
	name := "_acme-challenge.dns.example.fr."
	_ = s.Present(ctx, name, "a")
	_ = s.Present(ctx, name, "b") // le nom et son joker
	if err := s.Wait(ctx, map[string][]string{name: {"a", "b"}}); err != nil {
		t.Fatal(err)
	}
	if f.lagNS2 != 0 {
		t.Fatal("ns2 n'a pas été attendu")
	}
}

func TestSolverFollowsCNAME(t *testing.T) {
	f := &fakeDNS{cname: map[string]string{"_acme-challenge.dns.example.fr.": "_acme-challenge.acme.example.net."}, published: map[string][]string{}}
	s := &Solver{P: memProvider{f}, Interval: time.Millisecond, exchange: f.exchange}
	ctx := context.Background()
	if err := s.Present(ctx, "_acme-challenge.dns.example.fr.", "x"); err != nil {
		t.Fatal(err)
	}
	if got := f.published["_acme-challenge.acme.example.net."]; len(got) != 1 {
		t.Fatalf("publié ailleurs : %v", f.published)
	}
	if err := s.Wait(ctx, map[string][]string{"_acme-challenge.dns.example.fr.": {"x"}}); err != nil {
		t.Fatal(err)
	}
	_ = s.CleanUp(ctx, "_acme-challenge.dns.example.fr.", "x")
	if len(f.published) != 0 {
		t.Fatal("non retiré")
	}
}

func TestSolverTimeoutAndFallback(t *testing.T) {
	f := &fakeDNS{cname: map[string]string{}, published: map[string][]string{}}
	s := &Solver{P: memProvider{f}, Interval: time.Millisecond, Timeout: 50 * time.Millisecond, exchange: f.exchange}
	err := s.Wait(context.Background(), map[string][]string{"_acme-challenge.example.fr.": {"absent"}})
	if err == nil || !strings.Contains(err.Error(), "toujours pas visible") {
		t.Fatalf("délai : %v", err)
	}
	// Serveurs faisant autorité injoignables (DNS sortant filtré) : délai fixe.
	f.down = true
	s.Fallback = 10 * time.Millisecond
	start := time.Now()
	if err := s.Wait(context.Background(), map[string][]string{"_acme-challenge.example.fr.": {"x"}}); err != nil || time.Since(start) < 10*time.Millisecond {
		t.Fatalf("repli : %v", err)
	}
}
