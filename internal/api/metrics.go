// metrics.go - exposition Prometheus (/metrics) et sauvegarde (/api/backup).
package api

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rempart-dns/rempart/internal/audit"
	"github.com/rempart-dns/rempart/internal/backup"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/metrics"
	"github.com/rempart-dns/rempart/internal/zones"
)

func (a *API) loadedZones() []*zones.Zone { return a.Zones.All() }

// auditCheck : la vérification complète du journal relit tout le fichier ;
// son résultat est gardé cinq minutes entre deux collectes.
type auditCheck struct {
	mu  sync.Mutex
	at  time.Time
	rep audit.Report
}

func (a *API) auditOK() audit.Report {
	a.auditChk.mu.Lock()
	defer a.auditChk.mu.Unlock()
	if time.Since(a.auditChk.at) > 5*time.Minute {
		a.auditChk.rep, a.auditChk.at = a.Audit.Verify(), time.Now()
	}
	return a.auditChk.rep
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// metricsHandler : aucune métrique ne porte d'adresse ni de nom de client.
func (a *API) metricsHandler(w http.ResponseWriter, r *http.Request, _ string) {
	var buf bytes.Buffer
	m := metrics.NewWriter(&buf)
	st := a.Store.Get()
	m.Gauge("rempart_build_info", "Version de Rempart.", 1, "version", a.Version, "keystore", a.KS.Backend())
	m.Gauge("rempart_uptime_seconds", "Durée depuis le démarrage.", time.Since(a.Started).Seconds())
	s := a.QLog.Stats
	other := s.Blocked.Load() + s.Cached.Load() + s.Local.Load() + s.Errors.Load() + s.Refused.Load() + s.Rewritten.Load()
	total := s.Total.Load()
	for _, kv := range []struct {
		k string
		v uint64
	}{{"blocked", s.Blocked.Load()}, {"cached", s.Cached.Load()}, {"local", s.Local.Load()}, {"error", s.Errors.Load()},
		{"refused", s.Refused.Load()}, {"rewritten", s.Rewritten.Load()}, {"resolved", total - min(total, other)}} {
		m.Counter("rempart_dns_queries_total", "Requêtes DNS traitées, par issue.", float64(kv.v), "status", kv.k)
	}
	for p, v := range a.Server.ByProto() {
		m.Counter("rempart_dns_queries_by_transport_total", "Requêtes DNS traitées, par transport.", float64(v), "transport", p)
	}
	if a.Server.Latency != nil {
		m.Histogram("rempart_dns_request_duration_seconds", "Durée de traitement d'une requête DNS.", a.Server.Latency)
	}
	entries, hits, miss := a.Cache.Stats()
	m.Gauge("rempart_cache_entries", "Réponses en cache.", float64(entries))
	m.Counter("rempart_cache_hits_total", "Réponses servies depuis le cache.", float64(hits))
	m.Counter("rempart_cache_misses_total", "Réponses absentes du cache.", float64(miss))
	if a.Server != nil && a.Server.Validator != nil {
		vc := &a.Server.Validator.Counts
		for _, x := range []struct {
			s string
			n uint64
		}{{"secure", vc.Secure.Load()}, {"insecure", vc.Insecure.Load()}, {"bogus", vc.Bogus.Load()}} {
			m.Counter("rempart_dnssec_validations_total", "Réponses validées localement, par résultat.", float64(x.n), "result", x.s)
		}
	}
	for _, u := range a.Upstreams.Stats() {
		l := []string{"upstream", u.Name, "domain", u.Domain}
		m.Counter("rempart_upstream_queries_total", "Requêtes envoyées aux résolveurs en amont.", float64(u.Queries), l...)
		m.Counter("rempart_upstream_errors_total", "Échecs des résolveurs en amont.", float64(u.Errors), l...)
		m.Gauge("rempart_upstream_latency_avg_seconds", "Latence moyenne d'un résolveur en amont.", u.AvgMs/1000, l...)
	}
	bl, al := a.Blocker.Matcher().Len()
	m.Gauge("rempart_filter_rules", "Règles de la politique générale.", float64(bl), "kind", "block")
	m.Gauge("rempart_filter_rules", "Règles de la politique générale.", float64(al), "kind", "allow")
	for _, l := range st.Lists {
		// L'identifiant rend chaque série unique même si deux listes
		// portent le même nom (Prometheus rejetterait la collecte).
		m.Gauge("rempart_list_rules", "Règles chargées par liste.", float64(a.Blocker.Count(l.ID)), "id", l.ID, "list", l.Name)
		m.Time("rempart_list_last_update_timestamp_seconds", "Dernière mise à jour réussie d'une liste.", l.LastUpdate, "id", l.ID, "list", l.Name)
		m.Gauge("rempart_list_error", "1 si la dernière mise à jour d'une liste a échoué.", b2f(l.LastError != ""), "id", l.ID, "list", l.Name)
	}
	m.Gauge("rempart_groups", "Groupes d'appareils.", float64(len(st.Groups)))
	for _, z := range a.Zones.All() {
		m.Gauge("rempart_zone_serial", "Numéro de série d'une zone primaire.", float64(z.Serial()), "zone", z.Origin)
		if z.DNSSEC {
			m.Time("rempart_zone_signature_expiry_timestamp_seconds", "Expiration des signatures DNSSEC d'une zone.", z.Expires, "zone", z.Origin)
		}
	}
	if a.Authority != nil {
		for _, sz := range a.Authority.Secondaries() {
			m.Gauge("rempart_secondary_zone_serial", "Numéro de série d'une zone secondaire.", float64(sz.Serial), "zone", sz.Name)
			m.Time("rempart_secondary_zone_last_refresh_timestamp_seconds", "Dernier rafraîchissement réussi d'une zone secondaire.", sz.LastOK, "zone", sz.Name)
			m.Gauge("rempart_secondary_zone_expired", "1 si la zone secondaire a expiré (plus servie).", b2f(sz.Expired), "zone", sz.Name)
		}
	}
	if a.RPZ != nil {
		names := map[string]string{}
		for _, f := range st.RPZ {
			names[f.ID] = f.Name
		}
		for id, fs := range a.RPZ.Status() {
			m.Gauge("rempart_rpz_rules", "Règles chargées par flux RPZ.", float64(fs.Rules), "id", id, "feed", names[id])
			m.Time("rempart_rpz_last_success_timestamp_seconds", "Dernier rafraîchissement réussi d'un flux RPZ.", fs.LastOK, "id", id, "feed", names[id])
			m.Gauge("rempart_rpz_error", "1 si le dernier rafraîchissement d'un flux RPZ a échoué.", b2f(fs.LastError != ""), "id", id, "feed", names[id])
		}
	}
	if a.TLS != nil {
		m.Time("rempart_tls_certificate_expiry_timestamp_seconds", "Expiration du certificat de DoT, DoH et de l'interface.", a.TLS.Info().NotAfter)
	}
	rep := a.auditOK()
	m.Gauge("rempart_audit_chain_ok", "1 si le journal d'audit est intègre (chaînage, signatures, tête).", b2f(rep.OK))
	m.Gauge("rempart_audit_events", "Événements du journal d'audit.", float64(rep.Count))
	if a.Forwarder != nil {
		fs := a.Forwarder.Status()
		m.Gauge("rempart_syslog_enabled", "1 si la copie de l'audit vers un syslog est active.", b2f(fs.Enabled))
		m.Gauge("rempart_syslog_pending_events", "Événements d'audit pas encore remis au syslog.", float64(fs.Pending))
		m.Counter("rempart_syslog_sent_total", "Événements d'audit remis au syslog.", float64(fs.Sent))
		m.Time("rempart_syslog_last_success_timestamp_seconds", "Dernière remise réussie au syslog.", fs.LastOK)
	}
	if a.DHCP != nil {
		active := 0
		for _, l := range a.DHCP.Leases() {
			if !l.Static && time.Now().Before(l.Expires) {
				active++
			}
		}
		m.Gauge("rempart_dhcp_leases_active", "Baux DHCP dynamiques en cours.", float64(active))
		m.Gauge("rempart_dhcp_running", "1 si le serveur DHCP écoute.", b2f(a.DHCP.Running()))
	}
	if a.Replica != nil && st.Replication.Role == "replica" {
		rs := a.Replica.Status()
		m.Time("rempart_replication_last_sync_timestamp_seconds", "Dernière synchronisation réussie depuis l'instance principale.", rs.LastSync)
		m.Gauge("rempart_replication_error", "1 si la dernière synchronisation a échoué.", b2f(rs.LastError != ""))
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	m.Gauge("rempart_memory_alloc_bytes", "Mémoire allouée.", float64(mem.Alloc))
	m.Gauge("rempart_goroutines", "Goroutines.", float64(runtime.NumGoroutine()))
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// backupHandler produit une sauvegarde complète dans un fichier temporaire
// du dossier de données, puis l'envoie. Les rotations de KEK et les
// reconfigurations du quorum n'attendent que la fin de l'écriture (données
// et keystore de la même génération), pas celle de l'envoi.
func (a *API) backupHandler(w http.ResponseWriter, r *http.Request, user string) {
	tmp, err := os.CreateTemp(a.DataDir, backup.TempPrefix+"*.tar.gz")
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	a.record(user, "sauvegarde.début", "depuis "+a.clientIP(r).String())
	got, err := a.writeBackup(tmp, r.URL.Query().Get("lists") == "1")
	if err != nil {
		a.record(user, "sauvegarde.échec", err.Error())
		jsonError(w, http.StatusInternalServerError, "sauvegarde impossible : "+err.Error())
		return
	}
	a.record(user, "sauvegarde.fin", fmt.Sprintf("%d fichier(s), KEK génération %d, audit jusqu'à %d", len(got.Files), got.KEKGen, got.AuditSeq))
	info, err := tmp.Stat()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// L'envoi d'une grosse archive dépasse le délai d'écriture du serveur.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Hour))
	name := fmt.Sprintf("rempart-%s-%s.tar.gz", strings.ReplaceAll(a.Version, "/", "-"), got.Created.Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeContent(w, r, "", info.ModTime(), tmp)
}

func (a *API) writeBackup(f *os.File, lists bool) (backup.Manifest, error) {
	a.quorum.rot.Lock()
	defer a.quorum.rot.Unlock()
	a.QLog.Flush()
	if a.DHCP != nil {
		_ = a.DHCP.Flush()
	}
	m := backup.Manifest{Version: a.Version, Backend: a.KS.Backend(), KeyDetail: a.KS.Describe(), AuditSeq: a.Audit.Seq()}
	ksDir := ""
	if sw, ok := a.KS.(*keystore.Software); ok {
		ksDir = sw.Dir()
		m.KEKGen = sw.QuorumStatus().Current
	}
	got, err := backup.Create(f, backup.Source{DataDir: a.DataDir, KeystoreDir: ksDir, SkipLists: !lists}, m)
	if err != nil {
		return got, err
	}
	if err := f.Sync(); err != nil {
		return got, err
	}
	_, err = f.Seek(0, 0)
	return got, err
}
