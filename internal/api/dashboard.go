// dashboard.go - données du tableau de bord (GET /api/stats).
//
// Tout ce qui est renvoyé ici est soit anonyme (compteurs, séries, état des
// composants), soit déjà soumis au mode de confidentialité par querylog :
// le tableau de bord reste utile quand le journal est désactivé.
package api

import (
	"net/http"
	"runtime"
	"time"

	"github.com/rempart-dns/rempart/internal/querylog"
)

type dashboardStats struct {
	querylog.Snapshot
	LogMode string         `json:"log_mode"`
	Health  dashboardState `json:"health"`
}

type dashboardState struct {
	UptimeS    int     `json:"uptime_s"`
	MemoryMB   uint64  `json:"memory_mb"`
	Goroutines int     `json:"goroutines"`
	Cache      dashKV  `json:"cache"`
	DNSSEC     *dashKV `json:"dnssec,omitempty"`
	Lists      dashKV  `json:"lists"`
	Rules      dashKV  `json:"rules"`
	Groups     int     `json:"groups"`
	Zones      dashKV  `json:"zones"`
	Secondary  *dashKV `json:"secondaries,omitempty"`
	RPZ        *dashKV `json:"rpz,omitempty"`
	TLS        *dashKV `json:"tls,omitempty"`
	Audit      dashKV  `json:"audit"`
	Syslog     *dashKV `json:"syslog,omitempty"`
	DHCP       *dashKV `json:"dhcp,omitempty"`
	Replica    *dashKV `json:"replication,omitempty"`
}

type dashKV map[string]any

func (a *API) stats(w http.ResponseWriter, r *http.Request, _ string) {
	writeJSON(w, dashboardStats{Snapshot: a.QLog.Stats.Snapshot(), LogMode: a.QLog.Mode(), Health: a.dashHealth()})
}

func (a *API) dashHealth() dashboardState {
	st := a.Store.Get()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	h := dashboardState{UptimeS: int(time.Since(a.Started).Seconds()), MemoryMB: mem.Alloc >> 20,
		Goroutines: runtime.NumGoroutine(), Groups: len(st.Groups)}

	if a.Cache != nil {
		entries, hits, miss := a.Cache.Stats()
		h.Cache = dashKV{"entries": entries, "hits": hits, "misses": miss}
	}
	if a.Server != nil && a.Server.Validator != nil {
		vc := &a.Server.Validator.Counts
		h.DNSSEC = &dashKV{"secure": vc.Secure.Load(), "insecure": vc.Insecure.Load(), "bogus": vc.Bogus.Load()}
	}

	enabled, failing := 0, 0
	var oldest time.Time
	for _, l := range st.Lists {
		if !l.Enabled {
			continue
		}
		enabled++
		if l.LastError != "" {
			failing++
		}
		if !l.LastUpdate.IsZero() && (oldest.IsZero() || l.LastUpdate.Before(oldest)) {
			oldest = l.LastUpdate
		}
	}
	h.Lists = dashKV{"total": len(st.Lists), "enabled": enabled, "errors": failing}
	if !oldest.IsZero() {
		h.Lists["oldest_update"] = oldest
	}
	if a.Blocker != nil {
		bl, al := a.Blocker.Matcher().Len()
		h.Rules = dashKV{"block": bl, "allow": al, "mine": len(st.Rules)}
	}

	signed := 0
	var sigExp time.Time
	if a.Zones != nil {
		for _, z := range a.Zones.All() {
			if !z.DNSSEC {
				continue
			}
			signed++
			if sigExp.IsZero() || z.Expires.Before(sigExp) {
				sigExp = z.Expires
			}
		}
	}
	h.Zones = dashKV{"total": len(st.Zones), "signed": signed}
	if !sigExp.IsZero() {
		h.Zones["signature_expiry"] = sigExp
	}
	if a.Authority != nil {
		if sec := a.Authority.Secondaries(); len(sec) > 0 {
			expired := 0
			for _, s := range sec {
				if s.Expired {
					expired++
				}
			}
			h.Secondary = &dashKV{"total": len(sec), "expired": expired}
		}
	}
	if a.RPZ != nil && len(st.RPZ) > 0 {
		rules, failing := 0, 0
		for _, fs := range a.RPZ.Status() {
			rules += fs.Rules
			if fs.LastError != "" {
				failing++
			}
		}
		h.RPZ = &dashKV{"feeds": len(st.RPZ), "rules": rules, "errors": failing}
	}
	if a.TLS != nil {
		ti := a.TLS.Info()
		h.TLS = &dashKV{"not_after": ti.NotAfter, "self_signed": ti.SelfSigned, "mode": ti.Mode}
	}
	if a.Audit != nil {
		rep := a.auditOK()
		h.Audit = dashKV{"ok": rep.OK, "events": rep.Count}
	}
	if a.Forwarder != nil {
		if fs := a.Forwarder.Status(); fs.Enabled {
			h.Syslog = &dashKV{"pending": fs.Pending, "sent": fs.Sent, "last_ok": fs.LastOK, "error": fs.LastError != ""}
		}
	}
	if a.DHCP != nil && a.DHCP.Running() {
		active := 0
		for _, l := range a.DHCP.Leases() {
			if !l.Static && time.Now().Before(l.Expires) {
				active++
			}
		}
		h.DHCP = &dashKV{"active": active}
	}
	if role := st.Replication.Role; role != "" {
		rp := dashKV{"role": role}
		if a.Replica != nil && role == "replica" {
			rs := a.Replica.Status()
			rp["last_sync"], rp["error"] = rs.LastSync, rs.LastError != ""
		}
		h.Replica = &rp
	}
	return h
}
