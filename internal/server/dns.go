// Package server answers DNS queries over UDP, TCP, DoT and DoH.
//
// Pipeline for each query:
//
//	ACL → rate limit → sanity (ANY, opcode) → local zones (DNSSEC)
//	→ blocking → cache → encrypted upstreams → CNAME-cloaking check
//	→ DNS-rebinding check → cache store → padded response → privacy-aware log
package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/authority"
	"github.com/rempart-dns/rempart/internal/blocker"
	"github.com/rempart-dns/rempart/internal/cache"
	"github.com/rempart-dns/rempart/internal/dnssec"
	"github.com/rempart-dns/rempart/internal/filter"
	"github.com/rempart-dns/rempart/internal/metrics"
	"github.com/rempart-dns/rempart/internal/policy"
	"github.com/rempart-dns/rempart/internal/querylog"
	"github.com/rempart-dns/rempart/internal/rpz"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/tsig"
	"github.com/rempart-dns/rempart/internal/zones"
)

const blockedTTL = 10

// Resolver est implémenté par upstream.Group et upstream.Router.
type Resolver interface {
	Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, string, error)
}

// Settings is the subset of state used on the hot path (swapped atomically).
type Settings struct {
	state.Settings
	PausedUntil time.Time
}

type Server struct {
	Zones     *zones.Manager
	Blocker   *blocker.Engine
	Cache     *cache.Cache
	Upstreams Resolver
	// Validator valide localement les réponses DNSSEC (nil : validation
	// laissée aux résolveurs en amont).
	Validator *dnssec.Validator
	Log       *querylog.Logger
	Logger    *slog.Logger

	// Observer reçoit, si les suggestions sont activées, les noms résolus et
	// bloqués (jamais l'adresse du client).
	Observer interface {
		Resolved(name string, nxdomain bool, cname string)
		Blocked(name string)
	}

	ACL           []netip.Prefix
	RebindAllowed []string
	Limiter       *Limiter

	// Neighbors donne l'adresse MAC d'un client du réseau local (baux DHCP,
	// table de voisinage), pour les groupes définis par adresse MAC.
	Neighbors interface{ MAC(netip.Addr) string }
	// TSIG vérifie les signatures des requêtes signées ; Authority traite
	// transferts, NOTIFY et mises à jour dynamiques.
	TSIG      *tsig.Provider
	Authority *authority.Authority
	// RPZ applique les flux de menaces (Response Policy Zones), pour tous les
	// clients, pause comprise.
	RPZ *rpz.Engine
	// Hosts répond pour les noms des appareils (baux DHCP), s'il est défini.
	Hosts interface {
		Answer(q dns.Question) ([]dns.RR, bool)
	}

	// Latency : durée de traitement des requêtes ; ByProto : requêtes par
	// transport (udp, tcp, dot, doh).
	Latency *metrics.Histogram
	byProto sync.Map // string → *atomic.Uint64

	nsCache sync.Map // nom → nsEntry (déclencheurs RPZ sur serveurs de noms)

	settings atomic.Pointer[Settings]
	policy   atomic.Pointer[policy.Policy]
	seen     sync.Map // id d'appareil → time.Time de la dernière requête
	servers  []*dns.Server
	mu       sync.Mutex
}

func (s *Server) SetSettings(st state.State) {
	s.settings.Store(&Settings{Settings: st.Settings, PausedUntil: st.PausedUntil})
}

func (s *Server) Settings() *Settings { return s.settings.Load() }

func (s *Server) countProto(p string) {
	v, ok := s.byProto.Load(p)
	if !ok {
		v, _ = s.byProto.LoadOrStore(p, new(atomic.Uint64))
	}
	v.(*atomic.Uint64).Add(1)
}

// ByProto renvoie le nombre de requêtes servies par transport.
func (s *Server) ByProto() map[string]uint64 {
	out := map[string]uint64{}
	s.byProto.Range(func(k, v any) bool { out[k.(string)] = v.(*atomic.Uint64).Load(); return true })
	return out
}

// SetPolicy installe la politique par groupe compilée.
func (s *Server) SetPolicy(p *policy.Policy) { s.policy.Store(p) }

// Policy renvoie la politique en service (jamais nil après SetPolicy).
func (s *Server) Policy() *policy.Policy { return s.policy.Load() }

// DeviceSeen renvoie l'heure de la dernière requête d'un appareil identifié
// par son jeton (gardée en mémoire seulement).
func (s *Server) DeviceSeen(id string) time.Time {
	if v, ok := s.seen.Load(id); ok {
		return v.(time.Time)
	}
	return time.Time{}
}

type deviceKey struct{}

type devToken struct {
	token string
	admit bool // le jeton fait servir le client hors des réseaux autorisés
}

// WithDevice attache le jeton d'appareil présenté dans le chemin DoH. Ce
// chemin est chiffré par TLS : un jeton valide fait servir l'appareil hors
// des réseaux autorisés. Un jeton inconnu est ignoré.
func WithDevice(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, deviceKey{}, devToken{token, true})
}

// withSNIDevice : jeton lu dans le nom TLS de DoT. Ce nom circule en clair
// (ClientHello, et résolution préalable du nom par le résolveur du moment) :
// il identifie l'appareil sur les réseaux autorisés, sans ouvrir l'accès.
func withSNIDevice(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, deviceKey{}, devToken{token, false})
}

// deviceToken extrait un jeton du nom TLS demandé : premier label de
// « <jeton>.dns.example ».
func deviceToken(serverName string) string {
	if i := strings.IndexByte(serverName, '.'); i > 0 {
		return strings.ToLower(serverName[:i])
	}
	return ""
}

func (s *Server) allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range s.ACL {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ServeDNS implements dns.Handler for UDP, TCP and DoT.
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	var ip netip.Addr
	proto := "udp"
	ctx := context.Background()
	switch a := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		ip, _ = netip.AddrFromSlice(a.IP)
	case *net.TCPAddr:
		ip, _ = netip.AddrFromSlice(a.IP)
		proto = "tcp"
		if _, ok := w.(dns.ConnectionStater); ok {
			if cs := w.(dns.ConnectionStater).ConnectionState(); cs != nil {
				proto = "dot"
				ctx = withSNIDevice(ctx, deviceToken(cs.ServerName))
			}
		}
	}
	if authority.Handles(req) {
		// Transferts, NOTIFY et mises à jour : contrôlés par adresse et TSIG
		// dans Authority, indépendamment de la liste des clients DNS.
		if s.Authority == nil || !s.Limiter.Allow(ip.Unmap()) {
			if proto != "udp" {
				r := new(dns.Msg)
				_ = w.WriteMsg(r.SetRcode(req, dns.RcodeRefused))
			}
			return
		}
		s.Authority.Serve(w, req, ip.Unmap(), proto)
		return
	}
	resp := s.Handle(ctx, req, ip.Unmap(), proto)
	if resp == nil {
		return // silently dropped (ACL / rate limit over UDP)
	}
	if proto == "udp" {
		size := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil {
			size = int(min(max(opt.UDPSize(), dns.MinMsgSize), 1232))
		}
		resp.Truncate(size)
	}
	// RFC 8945 : une requête signée reçoit une réponse signée (le secondaire
	// qui vérifie le SOA de sa zone l'exige) ; une signature invalide, NOTAUTH.
	if ts := req.IsTsig(); ts != nil {
		if w.TsigStatus() != nil || s.TSIG == nil {
			r := new(dns.Msg)
			_ = w.WriteMsg(r.SetRcode(req, dns.RcodeNotAuth))
			return
		}
		resp.SetTsig(ts.Hdr.Name, ts.Algorithm, 300, time.Now().Unix())
	}
	_ = w.WriteMsg(resp)
}

// Handle is the protocol independent pipeline. A nil response means "drop".
func (s *Server) Handle(ctx context.Context, req *dns.Msg, ip netip.Addr, proto string) *dns.Msg {
	start := time.Now()
	pol := s.Policy()
	device, admitted := "", false
	if dt, _ := ctx.Value(deviceKey{}).(devToken); dt.token != "" && pol != nil {
		if device = pol.Device(dt.token); device != "" {
			s.seen.Store(device, start)
			admitted = dt.admit
		}
	}
	inACL := s.allowed(ip)
	if !inACL && !admitted {
		s.Log.Record(querylog.Entry{Time: start, Name: qname(req), Status: querylog.StatusRefused, Proto: proto, Rule: "client non autorisé"}, ip)
		if proto == "udp" {
			return nil // do not help reflection attacks
		}
		return reply(req, dns.RcodeRefused)
	}
	if !s.Limiter.Allow(ip) {
		if proto == "udp" {
			return nil
		}
		return reply(req, dns.RcodeRefused)
	}
	if req.Opcode != dns.OpcodeQuery {
		return reply(req, dns.RcodeNotImplemented)
	}
	if len(req.Question) != 1 || req.Response {
		return reply(req, dns.RcodeFormatError)
	}
	q := req.Question[0]
	q.Name = strings.ToLower(q.Name)
	req.Question[0] = q
	if q.Name == "healthcheck.rempart." && ip.IsLoopback() {
		return reply(req, dns.RcodeSuccess) // container health probe: no upstream, no log
	}
	do := false
	if opt := req.IsEdns0(); opt != nil {
		do = opt.Do()
		if opt.Version() != 0 {
			r := reply(req, dns.RcodeBadVers)
			r.SetEdns0(1232, do)
			return r
		}
	}
	var grp *policy.Group
	if pol != nil {
		mac := ""
		if s.Neighbors != nil && pol.UsesMAC() {
			mac = s.Neighbors.MAC(ip)
		}
		grp = pol.Identify(ip, device, mac)
	}
	entry := querylog.Entry{Time: start, Name: q.Name, Type: dns.TypeToString[q.Qtype], Proto: proto}
	if grp != nil {
		entry.Group = grp.Name
	}
	finish := func(resp *dns.Msg, status string) *dns.Msg {
		if s.Observer != nil {
			switch status {
			case querylog.StatusBlocked:
				s.Observer.Blocked(q.Name)
			case querylog.StatusAllowed, querylog.StatusCached:
				s.Observer.Resolved(q.Name, resp.Rcode == dns.RcodeNameError, firstCNAME(resp))
			}
		}
		s.finalize(req, resp, proto, do)
		if s.Latency != nil {
			s.Latency.Observe(time.Since(start))
		}
		s.countProto(proto)
		entry.Status = status
		entry.Rcode = dns.RcodeToString[resp.Rcode]
		entry.Millis = float64(time.Since(start).Microseconds()) / 1000
		s.Log.Record(entry, ip)
		return resp
	}

	// RFC 8482: ANY queries get a minimal answer (amplification hardening).
	if q.Qtype == dns.TypeANY {
		r := reply(req, dns.RcodeSuccess)
		r.Answer = []dns.RR{&dns.HINFO{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: 3600}, Cpu: "RFC8482"}}
		return finish(r, querylog.StatusAllowed)
	}

	set := s.Settings()

	// Firefox canary: tells browsers not to bypass this resolver with their own DoH.
	if set.BlockDoHCanary && (q.Name == "use-application-dns.net." || q.Name == "mask.icloud.com." || q.Name == "mask-h2.icloud.com.") {
		entry.Rule, entry.Source = q.Name, "protection anti-contournement"
		return finish(reply(req, dns.RcodeNameError), querylog.StatusBlocked)
	}

	// Un client admis par son seul jeton (hors du réseau) n'obtient que la
	// résolution publique : ni zones internes ni noms des appareils.
	if z := s.Zones.Find(q.Name); z != nil {
		if !inACL {
			entry.Rule = "zone interne, client hors réseau"
			return finish(reply(req, dns.RcodeRefused), querylog.StatusRefused)
		}
		return finish(z.Answer(req, do), querylog.StatusLocal)
	}
	if s.Hosts != nil && inACL {
		if rrs, ok := s.Hosts.Answer(q); ok {
			r := reply(req, dns.RcodeSuccess)
			if rrs == nil {
				r.Rcode = dns.RcodeNameError
			}
			r.Answer = rrs
			r.Authoritative = true
			return finish(r, querylog.StatusLocal)
		}
	}

	// RPZ : politique de sécurité, avant les groupes et leurs exceptions.
	// rpzLimit : un PASSTHRU (ou TCP-ONLY sur un transport fiable) d'un flux
	// n'écarte que les flux de rang inférieur ; ceux placés avant lui
	// s'appliquent encore à la réponse.
	rpzLimit := int(^uint(0) >> 1)
	if s.RPZ != nil {
		if hit := s.RPZ.MatchQuery(q.Name, ip); hit != nil {
			if hit.Rule.Action == rpz.Passthru {
				rpzLimit = hit.Rank
			} else if r, status := s.applyRPZ(ctx, req, hit, proto, do, &entry); status != "" {
				if r == nil {
					return s.dropped(entry, ip)
				}
				return finish(r, status)
			} else {
				rpzLimit = hit.Rank
			}
		}
	}

	// Pause et interrupteur généraux suspendent le filtrage de tous ; le
	// contrôle parental des groupes (plages horaires, SafeSearch) reste actif.
	blocking := set.BlockingEnabled && start.After(set.PausedUntil)
	m := s.Blocker.Matcher()
	var cm *filter.Matcher // catégories du groupe
	if grp != nil {
		blocking = blocking && grp.FilteringActive(start)
		if gm := s.Blocker.MatcherFor(grp.ListsKey); gm != nil {
			m = gm
		}
		v := grp.Check(q.Name, start.In(pol.Loc), blocking)
		if v.Blocked {
			entry.Rule, entry.Source = v.Rule, v.Source
			return finish(s.blocked(req, set.BlockingMode), querylog.StatusBlocked)
		}
		if v.Allowed {
			blocking = false // exception du groupe : ni listes ni CNAME
		} else if grp.CatsKey != "" {
			// Catégories (contrôle parental) : actives même filtrage en pause.
			if cm = s.Blocker.MatcherFor(grp.CatsKey); cm != nil {
				if res := cm.Match(q.Name); res.Blocked {
					entry.Rule, entry.Source = res.Rule, res.Source+", groupe "+grp.Name
					return finish(s.blocked(req, set.BlockingMode), querylog.StatusBlocked)
				}
			}
		}
	}
	if blocking {
		if res := m.Match(q.Name); res.Blocked {
			entry.Rule, entry.Source = res.Rule, res.Source
			return finish(s.blocked(req, set.BlockingMode), querylog.StatusBlocked)
		}
	}
	if grp != nil {
		if t := policy.SafeTarget(q.Name, grp.SafeSearch, grp.YouTube); t != "" {
			entry.Rule, entry.Source = "→ "+strings.TrimSuffix(t, "."), "SafeSearch, groupe "+grp.Name
			r, err := s.rewrite(ctx, req, t, do)
			if err != nil {
				return finish(reply(req, dns.RcodeServerFailure), querylog.StatusError)
			}
			return finish(r, querylog.StatusRewritten)
		}
	}

	// Le cache est commun à toutes les politiques : le contrôle des CNAME
	// est rejoué sur une réponse en cache, qui a pu être obtenue pour un
	// client non filtré.
	key := cache.Key(q, do || s.validating())
	if r, ok := s.Cache.Get(key); ok {
		r.Id = req.Id
		if blocked, rule, src := s.cnameCheck(m, cm, blocking, set.BlockCNAMECloak, q.Name, r); blocked {
			entry.Rule, entry.Source = rule, src
			return finish(s.blocked(req, set.BlockingMode), querylog.StatusBlocked)
		}
		if s.RPZ != nil {
			if hit := s.rpzAfter(ctx, q.Name, r, rpzLimit); hit != nil && hit.Rule.Action != rpz.Passthru {
				if rr, status := s.applyRPZ(ctx, req, hit, proto, do, &entry); status != "" {
					if rr == nil {
						return s.dropped(entry, ip)
					}
					return finish(rr, status)
				}
			}
		}
		return finish(r, querylog.StatusCached)
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r, via, vst, why, err := s.resolve(ctx, q, do, req.CheckingDisabled)
	entry.Upstream = via
	if err != nil {
		s.Logger.Debug("upstreams en échec", "nom", q.Name, "err", err)
		return finish(reply(req, dns.RcodeServerFailure), querylog.StatusError)
	}
	if vst == dnssec.Bogus {
		s.Logger.Warn("réponse DNSSEC invalide refusée", "nom", q.Name, "type", dns.TypeToString[q.Qtype], "motif", why)
		entry.Rule, entry.Source = why, "validation DNSSEC"
		return finish(bogusReply(req, why), querylog.StatusError)
	}
	r.Id = req.Id
	r.Question = req.Question

	if blocked, rule, src := s.cnameCheck(m, cm, blocking, set.BlockCNAMECloak, q.Name, r); blocked {
		entry.Rule, entry.Source = rule, src
		return finish(s.blocked(req, set.BlockingMode), querylog.StatusBlocked)
	}
	if s.RPZ != nil {
		if hit := s.rpzAfter(ctx, q.Name, r, rpzLimit); hit != nil && hit.Rule.Action != rpz.Passthru {
			if rr, status := s.applyRPZ(ctx, req, hit, proto, do, &entry); status != "" {
				if rr == nil {
					return s.dropped(entry, ip)
				}
				return finish(rr, status)
			}
		}
	}
	if set.RebindProtect && !s.rebindAllowed(q.Name) && !s.forwarded(q.Name) {
		if bad := privateAnswer(r); bad != "" {
			entry.Rule, entry.Source = "réponse privée "+bad, "protection anti-rebinding"
			return finish(s.blocked(req, "nxdomain"), querylog.StatusBlocked)
		}
	}
	if !req.CheckingDisabled {
		// Une réponse obtenue avec CD n'est pas validée : elle ne doit pas
		// être servie aux autres clients depuis le cache.
		s.Cache.Set(key, r)
	}
	return finish(r, querylog.StatusAllowed)
}

// validating indique si la validation DNSSEC locale s'applique.
func (s *Server) validating() bool {
	return s.Validator != nil && !s.Settings().DNSSECValidationOff
}

// resolve interroge les résolveurs en amont et, si la validation locale est
// active, valide la réponse (bits DO et CD envoyés en amont : Rempart ne
// délègue pas la validation). Le bit AD n'est posé que sur une réponse
// validée localement.
func (s *Server) resolve(ctx context.Context, q dns.Question, do, cd bool) (*dns.Msg, string, dnssec.Status, string, error) {
	validate := s.validating() && !cd
	up := new(dns.Msg)
	up.Id = dns.Id()
	up.RecursionDesired = true
	up.CheckingDisabled = cd || validate
	up.Question = []dns.Question{q}
	up.SetEdns0(1232, do || validate) // a fresh OPT: client ECS / cookies are never forwarded
	r, via, err := s.Upstreams.Exchange(ctx, up)
	if err != nil {
		return nil, via, dnssec.Indeterminate, "", err
	}
	if !validate {
		// Validation locale coupée : le bit AD du résolveur en amont (lien
		// chiffré) est conservé, comme avant ; jamais pour une requête CD.
		if cd {
			r.AuthenticatedData = false
		}
		return r, via, dnssec.Indeterminate, "", nil
	}
	st, why := s.Validator.Validate(ctx, q, r)
	r.AuthenticatedData = st == dnssec.Secure
	return r, via, st, why, nil
}

// bogusReply : SERVFAIL avec l'erreur étendue « DNSSEC Bogus » (RFC 8914).
func bogusReply(req *dns.Msg, why string) *dns.Msg {
	r := reply(req, dns.RcodeServerFailure)
	r.SetEdns0(1232, false)
	if len(why) > 200 {
		why = why[:200]
	}
	r.IsEdns0().Option = append(r.IsEdns0().Option, &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeDNSBogus, ExtraText: why})
	return r
}

// dropped journalise une requête abandonnée (rpz-drop) : sans réponse, mais
// pas sans trace.
func (s *Server) dropped(entry querylog.Entry, ip netip.Addr) *dns.Msg {
	entry.Status = querylog.StatusBlocked
	entry.Millis = float64(time.Since(entry.Time).Microseconds()) / 1000
	s.Log.Record(entry, ip)
	return nil
}

// applyRPZ construit la réponse imposée par une règle RPZ. Une réponse nil
// avec un statut signifie « ne pas répondre » (rpz-drop). Un statut vide :
// la règle ne s'applique pas sur ce transport (TCP-ONLY hors UDP).
func (s *Server) applyRPZ(ctx context.Context, req *dns.Msg, hit *rpz.Hit, proto string, do bool, entry *querylog.Entry) (*dns.Msg, string) {
	q := req.Question[0]
	entry.Rule, entry.Source = hit.Rule.Trigger+" ("+hit.Rule.Action.String()+")", "RPZ "+hit.Feed
	switch hit.Rule.Action {
	case rpz.NXDomain:
		return s.blocked(req, "nxdomain"), querylog.StatusBlocked
	case rpz.NoData:
		return reply(req, dns.RcodeSuccess), querylog.StatusBlocked
	case rpz.Drop:
		return nil, querylog.StatusBlocked
	case rpz.TCPOnly:
		if proto != "udp" {
			return nil, ""
		}
		r := reply(req, dns.RcodeSuccess)
		r.Truncated = true
		return r, querylog.StatusRewritten
	case rpz.Rewrite:
		target := hit.Rule.Target
		if strings.HasPrefix(target, "*.") { // CNAME *.cible : nom demandé préfixé
			target = q.Name + target[2:]
		}
		r, err := s.rewrite(ctx, req, target, do)
		if err != nil {
			return reply(req, dns.RcodeServerFailure), querylog.StatusError
		}
		return r, querylog.StatusRewritten
	case rpz.Local:
		r := reply(req, dns.RcodeSuccess)
		for _, rr := range hit.Rule.Local {
			t := rr.Header().Rrtype
			if t == q.Qtype || t == dns.TypeCNAME || q.Qtype == dns.TypeANY {
				c := dns.Copy(rr)
				c.Header().Name = q.Name
				r.Answer = append(r.Answer, c)
			}
		}
		return r, querylog.StatusRewritten
	}
	return nil, ""
}

// rewrite répond par un CNAME vers target (adresse SafeSearch de l'éditeur),
// suivi de la résolution de target pour le même type.
func (s *Server) rewrite(ctx context.Context, req *dns.Msg, target string, do bool) (*dns.Msg, error) {
	q := req.Question[0]
	r := reply(req, dns.RcodeSuccess)
	r.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: target}}
	tq := dns.Question{Name: target, Qtype: q.Qtype, Qclass: dns.ClassINET}
	key := cache.Key(tq, do || s.validating())
	t, ok := s.Cache.Get(key)
	if !ok {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var err error
		var st dnssec.Status
		var why string
		if t, _, st, why, err = s.resolve(ctx, tq, do, false); err != nil {
			return nil, err
		}
		if st == dnssec.Bogus {
			return nil, errors.New("DNSSEC invalide : " + why)
		}
		s.Cache.Set(key, t)
	}
	// La réponse synthétisée (CNAME de Rempart) n'est pas signée.
	r.AuthenticatedData = false
	r.Answer = append(r.Answer, t.Answer...)
	return r, nil
}

func firstCNAME(m *dns.Msg) string {
	for _, rr := range m.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			return c.Target
		}
	}
	return ""
}

func qname(req *dns.Msg) string {
	if len(req.Question) > 0 {
		return strings.ToLower(req.Question[0].Name)
	}
	return ""
}

func reply(req *dns.Msg, rcode int) *dns.Msg {
	r := new(dns.Msg)
	r.SetRcode(req, rcode)
	r.RecursionAvailable = true
	return r
}

// finalize sets RA, rebuilds the OPT record and pads encrypted responses.
func (s *Server) finalize(req, resp *dns.Msg, proto string, do bool) {
	resp.RecursionAvailable = true
	resp.Compress = true
	// Remove any OPT coming from upstream, then add ours if the client used
	// EDNS. Extended errors (RFC 8914) are kept.
	var ede []dns.EDNS0
	extra := resp.Extra[:0]
	for _, rr := range resp.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			for _, o := range opt.Option {
				if e, ok := o.(*dns.EDNS0_EDE); ok {
					ede = append(ede, e)
				}
			}
			continue
		}
		extra = append(extra, rr)
	}
	resp.Extra = extra
	if !do {
		stripDNSSEC(resp)
		// RFC 6840 §5.8 : AD seulement pour un client qui l'a demandé (DO ou AD).
		if !req.AuthenticatedData {
			resp.AuthenticatedData = false
		}
	}
	reqOpt := req.IsEdns0()
	if reqOpt == nil {
		return
	}
	resp.SetEdns0(1232, do)
	resp.IsEdns0().Option = append(resp.IsEdns0().Option, ede...)
	if proto == "dot" || proto == "doh" || proto == "doq" {
		// RFC 8467: pad responses to a multiple of 468 bytes.
		opt := resp.IsEdns0()
		n := resp.Len() + 4
		opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, (468-n%468)%468)})
	}
}

func stripDNSSEC(m *dns.Msg) {
	clean := func(rrs []dns.RR) []dns.RR {
		out := rrs[:0]
		for _, rr := range rrs {
			switch rr.Header().Rrtype {
			case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
				continue
			}
			out = append(out, rr)
		}
		return out
	}
	m.Answer, m.Ns, m.Extra = clean(m.Answer), clean(m.Ns), clean(m.Extra)
}

func (s *Server) blocked(req *dns.Msg, mode string) *dns.Msg {
	q := req.Question[0]
	if mode == "refused" {
		return reply(req, dns.RcodeRefused)
	}
	r := reply(req, dns.RcodeSuccess)
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: blockedTTL},
		Ns: "rempart.blocked.", Mbox: "rempart.blocked.", Serial: 1, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: blockedTTL}
	if mode == "nxdomain" {
		r.Rcode = dns.RcodeNameError
		r.Ns = []dns.RR{soa}
		return r
	}
	hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: blockedTTL}
	switch q.Qtype {
	case dns.TypeA:
		hdr.Rrtype = dns.TypeA
		r.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4zero}}
	case dns.TypeAAAA:
		hdr.Rrtype = dns.TypeAAAA
		r.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.IPv6unspecified}}
	default:
		r.Ns = []dns.RR{soa}
	}
	return r
}

// cnameCheck applique le démasquage CNAME : listes de filtrage si le
// filtrage est actif, catégories du groupe dans tous les cas.
func (s *Server) cnameCheck(m, cats *filter.Matcher, blocking, cloak bool, qname string, r *dns.Msg) (bool, string, string) {
	if !cloak {
		return false, "", ""
	}
	for _, mm := range []*filter.Matcher{cats, m} {
		if mm == nil || (mm == m && !blocking) {
			continue
		}
		if res, target := cnameBlocked(mm, r); res.Blocked {
			return true, res.Rule + " (CNAME de " + strings.TrimSuffix(qname, ".") + " → " + target + ")", res.Source
		}
	}
	return false, "", ""
}

// cnameBlocked detects trackers hidden behind a first-party CNAME.
func cnameBlocked(m *filter.Matcher, r *dns.Msg) (filter.Result, string) {
	for _, rr := range r.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			if res := m.Match(c.Target); res.Blocked {
				return res, strings.TrimSuffix(c.Target, ".")
			}
		}
	}
	return filter.Result{}, ""
}

// forwarded : un domaine interne transféré à ses propres serveurs répond
// normalement avec des adresses privées.
func (s *Server) forwarded(name string) bool {
	f, ok := s.Upstreams.(interface{ Forwarded(string) bool })
	return ok && f.Forwarded(name)
}

func (s *Server) rebindAllowed(name string) bool {
	name = strings.TrimSuffix(name, ".")
	for _, d := range s.RebindAllowed {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// privateAnswer returns the first private/loopback address in the answer.
func privateAnswer(r *dns.Msg) string {
	for _, rr := range r.Answer {
		var ip net.IP
		switch v := rr.(type) {
		case *dns.A:
			ip = v.A
		case *dns.AAAA:
			ip = v.AAAA
		default:
			continue
		}
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		a = a.Unmap()
		if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || netip.MustParsePrefix("100.64.0.0/10").Contains(a) {
			return a.String()
		}
	}
	return ""
}

// ---- listeners ----

// ListenDNS starts UDP and TCP listeners. On Linux several UDP sockets share
// the port (SO_REUSEPORT) so that the kernel spreads queries across cores.
func (s *Server) ListenDNS(addr string) error {
	n := 1
	if runtime.GOOS == "linux" {
		n = runtime.NumCPU()
	}
	for i := 0; i < n; i++ {
		srv := &dns.Server{Addr: addr, Net: "udp", Handler: s, UDPSize: 65535, ReusePort: n > 1, TsigProvider: s.tsigProvider(), MsgAcceptFunc: acceptMsg}
		if err := s.start(srv); err != nil {
			return err
		}
	}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: s, MaxTCPQueries: 256,
		ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second,
		IdleTimeout: func() time.Duration { return 10 * time.Second }, TsigProvider: s.tsigProvider(), MsgAcceptFunc: acceptMsg}
	return s.start(tcp)
}

// ListenDoT starts DNS-over-TLS. Le serveur rendu permet de l'arrêter seul
// (Stop), quand DoT est désactivé depuis l'interface.
func (s *Server) ListenDoT(addr string, tlsConf *tls.Config) (*dns.Server, error) {
	srv := &dns.Server{Addr: addr, Net: "tcp-tls", Handler: s, MaxTCPQueries: 1024,
		ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second,
		IdleTimeout: func() time.Duration { return 30 * time.Second }}
	srv.TLSConfig = tlsConf
	srv.TsigProvider, srv.MsgAcceptFunc = s.tsigProvider(), acceptMsg
	if err := s.start(srv); err != nil {
		return nil, err
	}
	return srv, nil
}

// Stop arrête un seul serveur démarré par ListenDoT et libère son port.
func (s *Server) Stop(ctx context.Context, srv *dns.Server) error {
	s.mu.Lock()
	s.servers = slices.DeleteFunc(s.servers, func(x *dns.Server) bool { return x == srv })
	s.mu.Unlock()
	return srv.ShutdownContext(ctx)
}

// acceptMsg accepte aussi les mises à jour dynamiques (refusées par défaut
// par la bibliothèque), avec des sections bornées.
func acceptMsg(dh dns.Header) dns.MsgAcceptAction {
	if dh.Bits&(1<<15) != 0 { // réponse
		return dns.MsgIgnore
	}
	if int(dh.Bits>>11)&0xF == dns.OpcodeUpdate {
		if dh.Qdcount != 1 || dh.Ancount > 64 || dh.Nscount > 256 || dh.Arcount > 2 {
			return dns.MsgReject
		}
		return dns.MsgAccept
	}
	return dns.DefaultMsgAcceptFunc(dh)
}

// tsigProvider : nil sans clés configurées (une interface non nil
// contenant un pointeur nil ferait échouer toute requête signée).
func (s *Server) tsigProvider() dns.TsigProvider {
	if s.TSIG == nil {
		return nil
	}
	return s.TSIG
}

func (s *Server) start(srv *dns.Server) error {
	errc := make(chan error, 1)
	srv.NotifyStartedFunc = func() { errc <- nil }
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			select {
			case errc <- err:
			default:
				s.Logger.Error("serveur DNS arrêté", "addr", srv.Addr, "net", srv.Net, "err", err)
			}
		}
	}()
	select {
	case err := <-errc:
		if err != nil {
			return err
		}
	case <-time.After(5 * time.Second):
	}
	s.mu.Lock()
	s.servers = append(s.servers, srv)
	s.mu.Unlock()
	return nil
}

func (s *Server) Shutdown(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, srv := range s.servers {
		_ = srv.ShutdownContext(ctx)
	}
}

// DoHHandler serves RFC 8484 (GET ?dns= and POST application/dns-message)
// on base and on base/<jeton d'appareil>.
func (s *Server) DoHHandler(base string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if rest, ok := strings.CutPrefix(r.URL.Path, strings.TrimSuffix(base, "/")+"/"); ok {
			if strings.Contains(rest, "/") || len(rest) > 64 {
				http.Error(w, "introuvable", http.StatusNotFound)
				return
			}
			token = rest
		}
		var wire []byte
		var err error
		switch r.Method {
		case http.MethodGet:
			wire, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		case http.MethodPost:
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/dns-message") {
				http.Error(w, "content-type attendu: application/dns-message", http.StatusUnsupportedMediaType)
				return
			}
			wire, err = io.ReadAll(io.LimitReader(r.Body, 65535))
		default:
			http.Error(w, "méthode non supportée", http.StatusMethodNotAllowed)
			return
		}
		req := new(dns.Msg)
		if err != nil || len(wire) == 0 || req.Unpack(wire) != nil {
			http.Error(w, "requête DNS invalide", http.StatusBadRequest)
			return
		}
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "adresse client invalide", http.StatusBadRequest)
			return
		}
		resp := s.Handle(WithDevice(r.Context(), token), req, ap.Addr().Unmap(), "doh")
		if resp == nil {
			resp = reply(req, dns.RcodeRefused)
		}
		out, err := resp.Pack()
		if err != nil {
			http.Error(w, "erreur interne", http.StatusInternalServerError)
			return
		}
		ttl := uint32(0)
		for i, rr := range resp.Answer {
			if t := rr.Header().Ttl; i == 0 || t < ttl {
				ttl = t
			}
		}
		w.Header().Set("Content-Type", "application/dns-message")
		// La réponse dépend du client (groupe) : aucun cache partagé.
		w.Header().Set("Cache-Control", "private, max-age="+itoa(ttl))
		_, _ = w.Write(out)
	})
}

func itoa(u uint32) string {
	if u == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}

// rpzAfter applique les déclencheurs RPZ connus après la résolution :
// réponse (cibles CNAME, adresses), puis serveurs de noms du domaine.
func (s *Server) rpzAfter(ctx context.Context, qname string, r *dns.Msg, limit int) *rpz.Hit {
	if hit := s.RPZ.MatchResponse(r, limit); hit != nil {
		return hit
	}
	return s.RPZ.MatchNS(ctx, qname, limit, s.nameServers)
}

type nsEntry struct {
	names   []string
	addrs   []netip.Addr
	full    bool // adresses résolues
	expires time.Time
}

const (
	nsCacheTTL   = 10 * time.Minute
	nsMaxServers = 6
)

// nameServers trouve les serveurs de noms de la zone la plus proche qui
// contient qname (requêtes NS en remontant les labels) et, si demandé, leurs
// adresses. Résultats en cache ; les échecs donnent une liste vide.
func (s *Server) nameServers(ctx context.Context, qname string, withAddrs bool) ([]string, []netip.Addr) {
	if v, ok := s.nsCache.Load(qname); ok {
		e := v.(nsEntry)
		if time.Now().Before(e.expires) && (e.full || !withAddrs) {
			return e.names, e.addrs
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ask := func(name string, t uint16) *dns.Msg {
		m := new(dns.Msg)
		m.Id = dns.Id()
		m.RecursionDesired = true
		m.SetQuestion(name, t)
		r, _, err := s.Upstreams.Exchange(ctx, m)
		if err != nil {
			return nil
		}
		return r
	}
	var names []string
	for name, i := qname, 0; i < 8 && names == nil; i++ {
		if r := ask(name, dns.TypeNS); r != nil {
			for _, rr := range r.Answer {
				if ns, ok := rr.(*dns.NS); ok && strings.EqualFold(ns.Hdr.Name, name) && len(names) < nsMaxServers {
					names = append(names, strings.ToLower(ns.Ns))
				}
			}
		}
		j := strings.IndexByte(name, '.')
		if j < 0 || j == len(name)-1 {
			break
		}
		name = name[j+1:]
	}
	var addrs []netip.Addr
	if withAddrs {
		for _, n := range names {
			for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
				if r := ask(n, t); r != nil {
					for _, rr := range r.Answer {
						switch v := rr.(type) {
						case *dns.A:
							if a, ok := netip.AddrFromSlice(v.A.To4()); ok {
								addrs = append(addrs, a)
							}
						case *dns.AAAA:
							if a, ok := netip.AddrFromSlice(v.AAAA); ok {
								addrs = append(addrs, a)
							}
						}
					}
				}
			}
		}
	}
	s.nsCache.Store(qname, nsEntry{names: names, addrs: addrs, full: withAddrs, expires: time.Now().Add(nsCacheTTL)})
	return names, addrs
}
