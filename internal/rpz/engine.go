package rpz

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/authority"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/sealed"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/tsig"
)

const maxFeedSize = 256 << 20

// Hit : règle déclenchée, flux d'origine et rang du flux (0 = prioritaire).
type Hit struct {
	Rule *Rule
	Feed string
	Rank int
}

// FeedStatus : état d'un flux, pour l'interface.
type FeedStatus struct {
	ID        string    `json:"id"`
	Serial    uint32    `json:"serial,omitempty"`
	Rules     int       `json:"rules"`
	Skipped   int       `json:"skipped"`
	LastOK    time.Time `json:"last_ok"`
	LastError string    `json:"last_error,omitempty"`
}

// Engine : flux RPZ en service, dans l'ordre de priorité de l'état.
type Engine struct {
	KS      keystore.Keystore
	DataDir string
	Log     *slog.Logger
	Prov    *tsig.Provider
	Client  *http.Client

	pols    atomic.Pointer[[]*Policy]
	cacheMu sync.Mutex // écritures des copies scellées

	mu     sync.Mutex
	order  []string
	byID   map[string]*Policy
	loops  map[string]*loop
	status map[string]*FeedStatus
}

type loop struct {
	conf   state.RPZFeed
	cancel context.CancelFunc
	kick   chan struct{}
}

// MatchName applique les déclencheurs QNAME, flux par flux.
func (e *Engine) MatchName(qname string) *Hit {
	return e.MatchQuery(qname, netip.Addr{})
}

// MatchQuery applique, flux par flux, les déclencheurs connus avant la
// résolution : adresse du client, puis QNAME (ordre de priorité d'une zone).
func (e *Engine) MatchQuery(qname string, client netip.Addr) *Hit {
	ps := e.pols.Load()
	if ps == nil {
		return nil
	}
	for i, p := range *ps {
		if client.IsValid() {
			if r := p.MatchClient(client); r != nil {
				return &Hit{r, p.Feed, i}
			}
		}
		if r := p.MatchName(qname); r != nil {
			return &Hit{r, p.Feed, i}
		}
	}
	return nil
}

// NameServers : serveurs de noms d'un domaine et leurs adresses, fournis
// par le serveur DNS (requêtes NS aux résolveurs en amont).
type NameServers func(ctx context.Context, qname string, withAddrs bool) (names []string, addrs []netip.Addr)

// NeedsNS indique si un flux de rang inférieur à limit contient des
// déclencheurs sur serveurs de noms.
func (e *Engine) NeedsNS(limit int) (need, addrs bool) {
	ps := e.pols.Load()
	if ps == nil {
		return false, false
	}
	for i, p := range *ps {
		if i >= limit {
			break
		}
		if p.HasNS() {
			need = true
			addrs = addrs || len(p.nsip.m) > 0
		}
	}
	return need, addrs
}

// MatchNS applique les déclencheurs rpz-nsdname puis rpz-nsip aux serveurs
// de noms du domaine demandé (priorité la plus basse dans une zone).
func (e *Engine) MatchNS(ctx context.Context, qname string, limit int, lookup NameServers) *Hit {
	need, withAddrs := e.NeedsNS(limit)
	if !need || lookup == nil {
		return nil
	}
	names, addrs := lookup(ctx, qname, withAddrs)
	ps := e.pols.Load()
	for i, p := range *ps {
		if i >= limit {
			break
		}
		for _, n := range names {
			if r := p.MatchNSName(n); r != nil {
				return &Hit{r, p.Feed, i}
			}
		}
		for _, a := range addrs {
			if r := p.MatchNSIP(a); r != nil {
				return &Hit{r, p.Feed, i}
			}
		}
	}
	return nil
}

// MatchResponse applique aux flux de rang inférieur à limit les
// déclencheurs QNAME aux cibles CNAME de la réponse (un nom listé ne se
// cache pas derrière un alias, comme le fait BIND) et les déclencheurs
// d'adresse aux A et AAAA.
func (e *Engine) MatchResponse(r *dns.Msg, limit int) *Hit {
	ps := e.pols.Load()
	if ps == nil {
		return nil
	}
	for i, p := range *ps {
		if i >= limit {
			break
		}
		for _, rr := range r.Answer {
			var ip netip.Addr
			switch v := rr.(type) {
			case *dns.CNAME:
				if rule := p.MatchName(strings.ToLower(v.Target)); rule != nil {
					return &Hit{rule, p.Feed, i}
				}
				continue
			case *dns.A:
				ip, _ = netip.AddrFromSlice(v.A.To4())
			case *dns.AAAA:
				ip, _ = netip.AddrFromSlice(v.AAAA)
			default:
				continue
			}
			if len(p.ipBits) == 0 {
				continue
			}
			if rule := p.MatchIP(ip); rule != nil {
				return &Hit{rule, p.Feed, i}
			}
		}
	}
	return nil
}

func (e *Engine) publish() {
	ps := []*Policy{}
	for _, id := range e.order {
		if p := e.byID[id]; p != nil {
			ps = append(ps, p)
		}
	}
	e.pols.Store(&ps)
}

// Status renvoie l'état des flux.
func (e *Engine) Status() map[string]FeedStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[string]FeedStatus{}
	for id, s := range e.status {
		out[id] = *s
	}
	return out
}

// Reconcile démarre ou arrête les flux selon l'état.
func (e *Engine) Reconcile(ctx context.Context, st state.State) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.loops == nil {
		e.loops, e.byID, e.status = map[string]*loop{}, map[string]*Policy{}, map[string]*FeedStatus{}
	}
	want := map[string]state.RPZFeed{}
	e.order = e.order[:0]
	for _, f := range st.RPZ {
		if f.Enabled {
			want[f.ID] = f
			e.order = append(e.order, f.ID)
		}
	}
	for id, l := range e.loops {
		if w, ok := want[id]; !ok || w != l.conf {
			l.cancel()
			delete(e.loops, id)
			if !ok {
				delete(e.byID, id)
				delete(e.status, id)
				if _, still := findFeed(st, id); !still {
					_ = os.Remove(e.cachePath(id))
				}
			}
		}
	}
	for id, f := range want {
		if e.loops[id] != nil {
			continue
		}
		lctx, cancel := context.WithCancel(ctx)
		l := &loop{conf: f, cancel: cancel, kick: make(chan struct{}, 1)}
		e.loops[id] = l
		if e.status[id] == nil {
			e.status[id] = &FeedStatus{ID: id}
		}
		go e.run(lctx, l)
	}
	e.publish()
}

func findFeed(st state.State, id string) (state.RPZFeed, bool) {
	for _, f := range st.RPZ {
		if f.ID == id {
			return f, true
		}
	}
	return state.RPZFeed{}, false
}

// OnNotify déclenche le rafraîchissement d'un flux AXFR sur NOTIFY signé de
// son primaire.
func (e *Engine) OnNotify(zone string, ip netip.Addr, key string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, l := range e.loops {
		c := l.conf
		if c.Source != "axfr" || strings.ToLower(dns.Fqdn(c.Zone)) != zone || tsig.CanonicalName(c.Key) != key {
			continue
		}
		h := c.Primary
		if hh, _, err := net.SplitHostPort(h); err == nil {
			h = hh
		}
		if a, err := netip.ParseAddr(h); err == nil && a.Unmap() == ip {
			select {
			case l.kick <- struct{}{}:
			default:
			}
			return true
		}
	}
	return false
}

func (e *Engine) cachePath(id string) string {
	return filepath.Join(e.DataDir, "rpz-"+safeID(id)+".sealed")
}

func safeID(id string) string {
	var b strings.Builder
	for _, c := range id {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func (e *Engine) setPolicy(id string, p *Policy, serial uint32, ok bool, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.status[id]
	if st == nil {
		return // flux retiré entre-temps
	}
	if p != nil {
		e.byID[id] = p
		st.Rules, st.Skipped, st.Serial = p.Rules, p.Skipped, serial
		e.publish()
	}
	if ok {
		st.LastOK, st.LastError = time.Now().UTC(), ""
	}
	if err != nil {
		st.LastError = err.Error()
	}
}

func (e *Engine) run(ctx context.Context, l *loop) {
	c := l.conf
	var serial uint32
	var etag string
	// Copie locale : le flux protège dès le démarrage, même sans réseau.
	if text, err := sealed.ReadFile(e.KS, e.cachePath(c.ID)); err == nil {
		if p, s, err := parseText(c, text); err == nil {
			serial = s
			e.setPolicy(c.ID, p, s, false, nil)
		}
	}
	wait := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.kick:
		case <-time.After(wait):
		}
		var err error
		var next time.Duration
		switch c.Source {
		case "axfr":
			next, err = e.refreshAXFR(ctx, c, &serial)
		case "https":
			next, err = e.refreshHTTPS(ctx, c, &etag)
		default:
			err = fmt.Errorf("source inconnue %q", c.Source)
		}
		if c.Minutes > 0 {
			next = time.Duration(c.Minutes) * time.Minute
		}
		if err != nil {
			e.Log.Warn("flux RPZ non rafraîchi", "flux", c.Name, "err", err)
			e.setPolicy(c.ID, nil, 0, false, err)
			wait = 5 * time.Minute
			continue
		}
		e.setPolicy(c.ID, nil, 0, true, nil)
		wait = min(max(next, time.Minute), 24*time.Hour)
	}
}

func (e *Engine) refreshAXFR(ctx context.Context, c state.RPZFeed, serial *uint32) (time.Duration, error) {
	key, ok := e.Prov.Key(c.Key)
	if !ok {
		return 0, errors.New("clé TSIG " + c.Key + " inconnue")
	}
	soa, err := authority.QuerySOA(c.Primary, c.Zone, key)
	if err != nil {
		return 0, err
	}
	next := time.Duration(soa.Refresh) * time.Second
	if *serial != 0 && soa.Serial == *serial {
		return next, nil
	}
	tctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	rrs, err := authority.Transfer(tctx, c.Primary, c.Zone, key)
	if err != nil {
		return 0, err
	}
	p, err := Parse(c.Name, c.Zone, rrs)
	if err != nil {
		return 0, err
	}
	*serial = soa.Serial
	e.setPolicy(c.ID, p, soa.Serial, true, nil)
	e.Log.Info("flux RPZ chargé", "flux", c.Name, "règles", p.Rules, "série", soa.Serial)
	var buf bytes.Buffer
	for _, rr := range rrs[:len(rrs)-1] {
		buf.WriteString(rr.String())
		buf.WriteByte('\n')
	}
	e.saveCache(c.ID, buf.Bytes())
	return next, nil
}

func (e *Engine) refreshHTTPS(ctx context.Context, c state.RPZFeed, etag *string) (time.Duration, error) {
	if !strings.HasPrefix(c.URL, "https://") {
		return 0, errors.New("adresse https:// attendue")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Rempart-DNS")
	if *etag != "" {
		req.Header.Set("If-None-Match", *etag)
	}
	cl := e.Client
	if cl == nil {
		cl = &http.Client{Timeout: 5 * time.Minute, CheckRedirect: httpsOnly}
	}
	resp, err := cl.Do(req)
	if err != nil {
		// L'erreur reprend l'URL, clé d'accès éventuelle comprise.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = fmt.Errorf("%s %s : %w", ue.Op, Redact(ue.URL), ue.Err)
		}
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return time.Hour, nil
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedSize+1))
	if err != nil {
		return 0, err
	}
	if len(data) > maxFeedSize {
		return 0, errors.New("flux trop volumineux (> 256 Mo)")
	}
	p, serial, err := parseText(c, data)
	if err != nil {
		return 0, err
	}
	*etag = resp.Header.Get("ETag")
	e.setPolicy(c.ID, p, serial, true, nil)
	e.Log.Info("flux RPZ chargé", "flux", c.Name, "règles", p.Rules)
	e.saveCache(c.ID, data)
	return time.Hour, nil
}

// MaxRules borne un flux : au-delà, il est refusé plutôt que d'épuiser la
// mémoire du résolveur (et celle de ses répliques).
const MaxRules = authority.MaxTransferRRs

// Redact masque la chaîne de requête d'une URL (clé d'accès de l'éditeur).
func Redact(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return u[:i] + "?…"
	}
	return u
}

// httpsOnly refuse une redirection vers autre chose que https://.
func httpsOnly(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return errors.New("redirection hors https refusée")
	}
	if len(via) >= 5 {
		return errors.New("trop de redirections")
	}
	return nil
}

// parseText lit une zone RPZ au format fichier de zone. $INCLUDE est refusé
// par la bibliothèque ; $GENERATE l'est ici (une ligne vaut 65 536
// enregistrements).
func parseText(c state.RPZFeed, data []byte) (*Policy, uint32, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) > 0 && strings.EqualFold(f[0], "$GENERATE") {
			return nil, 0, errors.New("zone RPZ : directive $GENERATE refusée")
		}
	}
	zp := dns.NewZoneParser(bufio.NewReader(bytes.NewReader(data)), dns.Fqdn(c.Zone), "")
	var rrs []dns.RR
	var serial uint32
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if len(rrs) >= MaxRules {
			return nil, 0, fmt.Errorf("zone RPZ : plus de %d enregistrements, flux refusé", MaxRules)
		}
		if soa, isSOA := rr.(*dns.SOA); isSOA && serial == 0 {
			serial = soa.Serial
		}
		rrs = append(rrs, rr)
	}
	if err := zp.Err(); err != nil {
		return nil, 0, fmt.Errorf("zone RPZ illisible : %w", err)
	}
	p, err := Parse(c.Name, c.Zone, rrs)
	return p, serial, err
}

func (e *Engine) saveCache(id string, data []byte) {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	if err := sealed.WriteFile(e.KS, e.cachePath(id), data); err != nil {
		e.Log.Error("copie du flux RPZ non enregistrée", "flux", id, "err", err)
	}
}

// Reseal réécrit les copies scellées avec la KEK en service (rotation).
// Toutes les copies présentes sont traitées, flux désactivés compris.
func (e *Engine) Reseal() error {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	files, err := filepath.Glob(filepath.Join(e.DataDir, "rpz-*.sealed"))
	if err != nil {
		return err
	}
	for _, p := range files {
		raw, err := sealed.ReadFile(e.KS, p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if err := sealed.WriteFile(e.KS, p, raw); err != nil {
			return err
		}
	}
	return nil
}
