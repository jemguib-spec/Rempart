// Package authority sert ce qui relève du DNS faisant autorité, au-delà des
// réponses aux requêtes : transferts de zone sortants (AXFR, IXFR) vers les
// secondaires, NOTIFY envoyés et reçus, mises à jour dynamiques (RFC 2136) et
// zones secondaires copiées d'un primaire. Toutes ces opérations exigent à la
// fois une adresse source autorisée et une signature TSIG valide.
package authority

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/sealed"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/tsig"
	"github.com/rempart-dns/rempart/internal/zones"
)

// MaxUpdatesPerSecond borne le débit des mises à jour dynamiques acceptées.
const MaxUpdatesPerSecond = 20

type rate struct {
	mu  sync.Mutex
	sec int64
	n   int
}

func (r *rate) allow(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s := now.Unix(); s != r.sec {
		r.sec, r.n = s, 0
	}
	r.n++
	return r.n <= MaxUpdatesPerSecond
}

// MaxFudge : fenêtre de temps TSIG admise pour une mise à jour (secondes).
const MaxFudge = 300

// Authority : voir le commentaire du paquet.
type Authority struct {
	Store   *state.Store
	Zones   *zones.Manager
	Prov    *tsig.Provider
	KS      keystore.Keystore
	DataDir string
	Log     *slog.Logger
	// Record inscrit une action dans le journal d'audit.
	Record func(actor, action, detail string)
	// OnNotify reçoit les NOTIFY qui ne concernent pas une zone secondaire
	// (flux RPZ) ; il renvoie true si le NOTIFY est accepté.
	OnNotify func(zone string, ip netip.Addr, key string) bool

	updMu      sync.Mutex
	replay     tsig.Replay
	replayOnce sync.Once
	replayMu   sync.Mutex // écritures de tsig-replay.sealed
	// replayBlockedUntil : mémoire anti-rejeu illisible au démarrage.
	replayBlockedUntil time.Time

	notMu    sync.Mutex
	notified map[string]uint32 // zone → dernier numéro de série notifié

	secMu sync.Mutex
	sec   map[string]*secLoop

	cacheMu sync.Mutex // écritures des copies scellées des zones secondaires

	updRate rate
}

// Handles indique si la requête relève de l'autorité (et non de la résolution).
func Handles(req *dns.Msg) bool {
	switch req.Opcode {
	case dns.OpcodeNotify, dns.OpcodeUpdate:
		return true
	case dns.OpcodeQuery:
		return len(req.Question) == 1 && (req.Question[0].Qtype == dns.TypeAXFR || req.Question[0].Qtype == dns.TypeIXFR)
	}
	return false
}

func hostIP(addr string) (netip.Addr, bool) {
	h := addr
	if hh, _, err := net.SplitHostPort(addr); err == nil {
		h = hh
	}
	a, err := netip.ParseAddr(h)
	return a.Unmap(), err == nil
}

func reply(req *dns.Msg, rcode int) *dns.Msg {
	r := new(dns.Msg)
	r.SetRcode(req, rcode)
	return r
}

// signedBy renvoie la clé TSIG de la requête si sa signature est valide.
func signedBy(w dns.ResponseWriter, req *dns.Msg) (string, *dns.TSIG) {
	ts := req.IsTsig()
	if ts == nil || w.TsigStatus() != nil {
		return "", nil
	}
	return tsig.CanonicalName(ts.Hdr.Name), ts
}

func sign(r *dns.Msg, ts *dns.TSIG) *dns.Msg {
	r.SetTsig(ts.Hdr.Name, ts.Algorithm, 300, time.Now().Unix())
	return r
}

// Serve traite une requête d'autorité. proto : udp, tcp, dot.
func (a *Authority) Serve(w dns.ResponseWriter, req *dns.Msg, ip netip.Addr, proto string) {
	key, ts := signedBy(w, req)
	deny := func(rcode int, why string) {
		a.Log.Warn("opération d'autorité refusée", "op", dns.OpcodeToString[req.Opcode], "client", ip, "motif", why)
		_ = w.WriteMsg(reply(req, rcode))
	}
	if len(req.Question) != 1 {
		deny(dns.RcodeFormatError, "question absente")
		return
	}
	if ts == nil {
		deny(dns.RcodeNotAuth, "signature TSIG absente ou invalide")
		return
	}
	zone := strings.ToLower(dns.Fqdn(req.Question[0].Name))
	st := a.Store.Get()
	switch req.Opcode {
	case dns.OpcodeQuery:
		if proto == "udp" {
			deny(dns.RcodeRefused, "transfert en UDP")
			return
		}
		if !a.transferAllowed(st, zone, ip, key) {
			deny(dns.RcodeRefused, "transfert non autorisé pour cette adresse ou cette clé")
			return
		}
		a.transferOut(w, req, ts, zone, ip)
	case dns.OpcodeNotify:
		if !a.notifyIn(st, zone, ip, key) {
			deny(dns.RcodeRefused, "NOTIFY inattendu")
			return
		}
		r := reply(req, dns.RcodeSuccess)
		r.Opcode, r.Authoritative = dns.OpcodeNotify, true
		_ = w.WriteMsg(sign(r, ts))
	case dns.OpcodeUpdate:
		rcode := a.update(st, req, ts, zone, ip, key)
		_ = w.WriteMsg(sign(reply(req, rcode), ts))
	}
}

func (a *Authority) transferAllowed(st state.State, zone string, ip netip.Addr, key string) bool {
	for _, z := range st.Zones {
		if strings.ToLower(dns.Fqdn(z.Name)) != zone {
			continue
		}
		if z.Transfer.Key != "" && key == tsig.CanonicalName(z.Transfer.Key) && listed(z.Transfer.Secondaries, ip) {
			return true
		}
	}
	r := st.Replication
	return r.Role == "primary" && r.Key != "" && key == tsig.CanonicalName(r.Key) && listed(r.Replicas, ip) && a.Zones.Get(zone) != nil
}

func listed(addrs []string, ip netip.Addr) bool {
	return slices.ContainsFunc(addrs, func(s string) bool { a, ok := hostIP(s); return ok && a == ip })
}

func (a *Authority) transferOut(w dns.ResponseWriter, req *dns.Msg, ts *dns.TSIG, zone string, ip netip.Addr) {
	z := a.Zones.Get(zone)
	if z == nil {
		_ = w.WriteMsg(sign(reply(req, dns.RcodeNotAuth), ts))
		return
	}
	// IXFR (RFC 1995) : un secondaire à jour reçoit le seul SOA ; sinon les
	// différences depuis sa version, si l'historique les contient, ou la
	// zone complète.
	rrs := []dns.RR(nil)
	kind := "AXFR"
	if req.Question[0].Qtype == dns.TypeIXFR && len(req.Ns) > 0 {
		if soa, ok := req.Ns[0].(*dns.SOA); ok {
			if !zones.SerialNewer(z.Serial(), soa.Serial) {
				r := reply(req, dns.RcodeSuccess)
				r.Authoritative = true
				r.Answer = []dns.RR{z.SOA()}
				_ = w.WriteMsg(sign(r, ts))
				return
			}
			if inc, ok := a.Zones.IXFR(zone, soa.Serial); ok {
				rrs, kind = inc, "IXFR"
			}
		}
	}
	if rrs == nil {
		rrs = z.AXFR()
	}
	ch := make(chan *dns.Envelope)
	tr := new(dns.Transfer)
	go func() {
		for i := 0; i < len(rrs); i += 400 {
			ch <- &dns.Envelope{RR: rrs[i:min(i+400, len(rrs))]}
		}
		close(ch)
	}()
	if err := tr.Out(w, req, ch); err != nil {
		a.Log.Warn("transfert de zone interrompu", "zone", zone, "secondaire", ip, "err", err)
		for range ch { // libère l'émetteur
		}
		return
	}
	_ = w.Close()
	a.Log.Info("zone transférée", "zone", zone, "secondaire", ip, "série", z.Serial(), "type", kind, "enregistrements", len(rrs))
}

func (a *Authority) notifyIn(st state.State, zone string, ip netip.Addr, key string) bool {
	for _, s := range st.Secondaries {
		if strings.ToLower(dns.Fqdn(s.Name)) != zone {
			continue
		}
		p, ok := hostIP(s.Primary)
		if ok && p == ip && key == tsig.CanonicalName(s.Key) {
			a.kick(zone)
			return true
		}
		return false
	}
	return a.OnNotify != nil && a.OnNotify(zone, ip, key)
}

// update applique une mise à jour dynamique ; renvoie le code de réponse.
func (a *Authority) update(st state.State, req *dns.Msg, ts *dns.TSIG, zone string, ip netip.Addr, key string) int {
	idx := slices.IndexFunc(st.Zones, func(z state.Zone) bool { return strings.ToLower(dns.Fqdn(z.Name)) == zone })
	if idx < 0 || req.Question[0].Qtype != dns.TypeSOA {
		return dns.RcodeNotAuth
	}
	tr := st.Zones[idx].Transfer
	if tr.UpdateKey == "" || key != tsig.CanonicalName(tr.UpdateKey) || !inPrefixes(tr.UpdateFrom, ip) {
		a.Log.Warn("mise à jour dynamique refusée", "zone", zone, "client", ip, "clé", key)
		return dns.RcodeRefused
	}
	// Une mise à jour capturée ne doit pas pouvoir être rejouée pendant la
	// fenêtre de validité de sa signature.
	// La signature reste valable jusqu'à TimeSigned + Fudge : son MAC est
	// retenu jusque-là (plus une marge). Un fudge large allongerait la
	// fenêtre de rejeu au-delà de ce que couvre la mémoire du serveur.
	if ts.Fudge > MaxFudge {
		return dns.RcodeRefused
	}
	until := time.Unix(int64(ts.TimeSigned), 0).Add(time.Duration(ts.Fudge)*time.Second + time.Minute)
	a.replayOnce.Do(a.loadReplay)
	if a.replayBlocked(time.Now()) {
		return dns.RcodeRefused
	}
	if !a.replay.Fresh(ts.MAC, time.Now(), until) {
		return dns.RcodeRefused
	}
	// Chaque mise à jour re-signe et réécrit l'état : débit borné, même
	// pour le détenteur légitime d'une clé.
	if !a.updRate.allow(time.Now()) {
		return dns.RcodeRefused
	}
	a.updMu.Lock()
	defer a.updMu.Unlock()
	var changed bool
	var uerr error
	err := a.Store.Update(func(s *state.State) error {
		i := slices.IndexFunc(s.Zones, func(z state.Zone) bool { return strings.ToLower(dns.Fqdn(z.Name)) == zone })
		if i < 0 {
			return fmt.Errorf("zone disparue")
		}
		cur := a.Zones.Get(zone)
		if cur == nil {
			return fmt.Errorf("zone non chargée")
		}
		dyn, err := zones.ApplyUpdate(cur, s.Zones[i], req)
		if err != nil {
			uerr = err
			return err
		}
		if slices.Equal(dyn, s.Zones[i].Dynamic) {
			return nil
		}
		s.Zones[i].Dynamic = dyn
		s.Zones[i].Serial = zones.NextSerial(max(s.Zones[i].Serial, cur.Serial()))
		if _, err := zones.Build(a.KS, s.Zones[i]); err != nil {
			uerr = &zones.UpdateError{Rcode: dns.RcodeRefused, Msg: err.Error()}
			return err
		}
		changed = true
		return nil
	})
	if uerr != nil {
		if ue, ok := uerr.(*zones.UpdateError); ok {
			a.Log.Info("mise à jour dynamique rejetée", "zone", zone, "motif", ue.Msg)
			return ue.Rcode
		}
	}
	if err != nil {
		a.Log.Error("mise à jour dynamique", "zone", zone, "err", err)
		return dns.RcodeServerFailure
	}
	if changed {
		if err := a.Zones.Load(a.Store.Get().Zones); err != nil {
			a.Log.Error("rechargement après mise à jour", "zone", zone, "err", err)
			return dns.RcodeServerFailure
		}
		a.Record("tsig:"+strings.TrimSuffix(key, "."), "zone.mise-à-jour-dynamique", fmt.Sprintf("%s depuis %s : %d modification(s)", zone, ip, len(req.Ns)))
	}
	return dns.RcodeSuccess
}

func inPrefixes(ps []string, ip netip.Addr) bool {
	for _, s := range ps {
		if p, err := netip.ParsePrefix(s); err == nil && p.Contains(ip) {
			return true
		}
		if a, ok := hostIP(s); ok && a == ip {
			return true
		}
	}
	return false
}

// NotifyAll envoie un NOTIFY aux secondaires des zones dont le numéro de série
// a changé depuis le dernier envoi (appelé après chaque chargement).
func (a *Authority) NotifyAll(zs []*zones.Zone) {
	st := a.Store.Get()
	a.notMu.Lock()
	if a.notified == nil {
		a.notified = map[string]uint32{}
	}
	type job struct {
		addr, zone string
		serial     uint32
		key        state.TSIGKey
	}
	var jobs []job
	for _, z := range zs {
		if a.notified[z.Origin] == z.Serial() {
			continue
		}
		a.notified[z.Origin] = z.Serial()
		for _, sz := range st.Zones {
			if strings.ToLower(dns.Fqdn(sz.Name)) != z.Origin || sz.Transfer.Key == "" {
				continue
			}
			if k, ok := a.Prov.Key(sz.Transfer.Key); ok {
				for _, s := range sz.Transfer.Secondaries {
					jobs = append(jobs, job{s, z.Origin, z.Serial(), k})
				}
			}
		}
		if r := st.Replication; r.Role == "primary" && r.Key != "" {
			if k, ok := a.Prov.Key(r.Key); ok {
				for _, s := range r.Replicas {
					jobs = append(jobs, job{s, z.Origin, z.Serial(), k})
				}
			}
		}
	}
	a.notMu.Unlock()
	for _, j := range jobs {
		go func() {
			if err := SendNotify(j.addr, j.zone, j.serial, j.key); err != nil {
				a.Log.Warn("NOTIFY non remis", "zone", j.zone, "secondaire", j.addr, "err", err)
			}
		}()
	}
}

// cachePath : copie scellée d'une zone secondaire (nom encodé, sans risque
// de traversée de chemin).
func (a *Authority) cachePath(zone string) string {
	return filepath.Join(a.DataDir, "secondary-"+hex.EncodeToString([]byte(zone))+".sealed")
}

// replayPath : mémoire anti-rejeu des mises à jour dynamiques, scellée.
func (a *Authority) replayPath() string { return filepath.Join(a.DataDir, "tsig-replay.sealed") }

// loadReplay reprend la mémoire anti-rejeu enregistrée avant un redémarrage
// et branche son enregistrement. Une mémoire illisible (fichier altéré,
// autre keystore) ne peut pas être ignorée sans rouvrir la fenêtre de rejeu :
// les mises à jour sont alors refusées jusqu'à l'expiration de la fenêtre la
// plus longue (fudge maximal), puis le fichier est remplacé.
func (a *Authority) loadReplay() {
	path := a.replayPath()
	raw, err := sealed.ReadFile(a.KS, path)
	var saved map[string]int64
	if err == nil {
		err = json.Unmarshal(raw, &saved)
	}
	switch {
	case err == nil:
		m := make(map[string]time.Time, len(saved))
		for k, v := range saved {
			m[k] = time.Unix(v, 0)
		}
		a.replay.Load(m)
	case errors.Is(err, os.ErrNotExist):
	default:
		a.Log.Error("mémoire anti-rejeu illisible : mises à jour dynamiques refusées pendant la fenêtre TSIG", "err", err)
		block := time.Now().Add((MaxFudge + 120) * time.Second)
		a.replayBlockedUntil = block
	}
	a.replay.Save = func(m map[string]time.Time) error {
		out := make(map[string]int64, len(m))
		for k, v := range m {
			out[k] = v.Unix()
		}
		raw, err := json.Marshal(out)
		if err != nil {
			return err
		}
		a.replayMu.Lock()
		defer a.replayMu.Unlock()
		return sealed.WriteFile(a.KS, path, raw)
	}
}

// replayBlocked indique que la mémoire anti-rejeu n'a pas pu être relue et
// que la fenêtre de prudence n'est pas écoulée.
func (a *Authority) replayBlocked(now time.Time) bool {
	return now.Before(a.replayBlockedUntil)
}

// resealReplay réécrit la mémoire anti-rejeu avec la KEK en service.
func (a *Authority) resealReplay() error {
	a.replayMu.Lock()
	defer a.replayMu.Unlock()
	raw, err := sealed.ReadFile(a.KS, a.replayPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return sealed.WriteFile(a.KS, a.replayPath(), raw)
}
