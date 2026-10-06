// Package api is the administration REST API and serves the web interface.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/audit"
	"github.com/rempart-dns/rempart/internal/auditfwd"
	"github.com/rempart-dns/rempart/internal/authority"
	"github.com/rempart-dns/rempart/internal/blocker"
	"github.com/rempart-dns/rempart/internal/cache"
	"github.com/rempart-dns/rempart/internal/dhcp"
	"github.com/rempart-dns/rempart/internal/filter"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/querylog"
	"github.com/rempart-dns/rempart/internal/replica"
	"github.com/rempart-dns/rempart/internal/rpz"
	"github.com/rempart-dns/rempart/internal/server"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/suggest"
	"github.com/rempart-dns/rempart/internal/tlsutil"
	"github.com/rempart-dns/rempart/internal/upstream"
	"github.com/rempart-dns/rempart/internal/zones"
)

const cookieName = "rempart_session"

type API struct {
	Store     *state.Store
	Blocker   *blocker.Engine
	Zones     *zones.Manager
	Server    *server.Server
	QLog      *querylog.Logger
	Audit     *audit.Log
	KS        keystore.Keystore
	Cache     *cache.Cache
	Upstreams *upstream.Router
	TLS       *tlsutil.Manager
	Suggest   *suggest.Observer
	DHCP      *dhcp.Server
	Authority *authority.Authority
	RPZ       *rpz.Engine
	Forwarder *auditfwd.Forwarder
	Replica   *replica.Client
	// Resealers réécrivent les fichiers scellés tenus par d'autres
	// composants (zones secondaires, flux RPZ) lors d'une rotation de KEK.
	Resealers []func() error
	Version   string
	Started   time.Time
	Hardening []string
	AdminACL  []netip.Prefix
	SecureCk  bool
	Listeners map[string]string // écoutes fixes (DNS, interface)
	// Encrypted pilote DoT et DoH (Réglages → Chiffrement) ; nil dans les tests.
	Encrypted *server.Encrypted
	Web       fs.FS

	// Paramètres d'exploitation venant du fichier de configuration.
	DataDir       string
	ModuleDirs    []string // dossiers autorisés pour les modules PKCS#11
	ActiveModule  string   // module PKCS#11 du keystore en service
	ActiveToken   string   // token PKCS#11 en service
	Bootstrap     []string // bootstrap par défaut des résolveurs
	HTTP01Listen  string
	PINConfigured bool // REMPART_PKCS11_PIN(_FILE) présent dans l'environnement
	// ApplyResolvers applique une configuration de résolution (validation
	// comprise) ; fourni par main pour partager les options de bootstrap.
	ApplyResolvers func(state.Resolvers) error
	// ServerPassphrase lit la phrase de passe serveur configurée (secret du
	// conteneur), celle que Rempart utilisera au prochain démarrage.
	ServerPassphrase func() (string, error)

	sess     sessions
	guard    loginGuard
	tokenUse tokenUsage
	chal     challenges
	wa       waChallenges
	otpNew   pendingOTP
	quorum   quorumState
	idp      identityState
	auditChk auditCheck
}

func (a *API) Handler(ttl time.Duration) http.Handler {
	a.sess = sessions{m: map[string]session{}, ttl: ttl}
	a.guard = loginGuard{fail: map[netip.Addr]*attempts{}}
	a.idp.ldapSem = make(chan struct{}, ldapParallel)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/login/otp", a.loginOTP)
	mux.HandleFunc("POST /api/login/passkey/begin", a.passkeyLoginBegin)
	mux.HandleFunc("POST /api/login/passkey/finish", a.passkeyLoginFinish)
	mux.HandleFunc("POST /api/logout", a.logout)
	// Portées : read (consultation), admin (toute modification), tls,
	// dnssec (automatisation), session (réservé à l'interface : mots de passe,
	// jetons, HSM). Une session ouverte dans l'interface a toutes les portées.
	auth := func(scope, p string, h func(http.ResponseWriter, *http.Request, string)) {
		mux.Handle(p, a.requireAuth(scope, h))
	}
	mux.HandleFunc("GET /api/auth/providers", a.authProviders)
	mux.HandleFunc("GET /api/oidc/login", a.oidcLogin)
	mux.HandleFunc("GET /api/oidc/callback", a.oidcCallback)
	auth("read", "GET /api/me", a.me)
	auth("read", "GET /api/status", a.status)
	auth("read", "GET /api/stats", a.stats)
	auth("read", "GET /api/querylog", a.queryLog)
	auth("read", "GET /api/querylog/days", a.queryLogDays)
	auth("admin", "GET /api/querylog/days/{day}", a.queryLogDay)
	auth("read", "GET /api/settings", a.getSettings)
	auth("admin", "PUT /api/settings", a.putSettings)
	auth("read", "GET /api/encryption", a.getEncryption)
	auth("admin", "PUT /api/encryption", a.putEncryption)
	auth("admin", "POST /api/pause", a.pause)
	auth("read", "GET /api/lists", a.getLists)
	auth("admin", "POST /api/lists", a.addList)
	auth("admin", "PATCH /api/lists/{id}", a.patchList)
	auth("admin", "DELETE /api/lists/{id}", a.deleteList)
	auth("admin", "POST /api/lists/refresh", a.refreshLists)
	auth("read", "GET /api/rules", a.getRules)
	auth("admin", "POST /api/rules", a.addRule)
	auth("admin", "POST /api/rules/bulk", a.bulkRules)
	auth("read", "GET /api/rules/export", a.exportRules)
	auth("admin", "DELETE /api/rules", a.deleteRule)
	auth("read", "GET /api/check", a.check)
	auth("read", "GET /api/check/client", a.checkClient)
	auth("read", "GET /api/groups", a.getGroups)
	auth("admin", "POST /api/groups", a.addGroup)
	auth("admin", "PUT /api/groups/{id}", a.putGroup)
	auth("admin", "DELETE /api/groups/{id}", a.deleteGroup)
	auth("admin", "POST /api/groups/{id}/pause", a.pauseGroup)
	// Appareils : chaque création remet un jeton, réservée à l'interface
	// comme les jetons d'API.
	auth("session", "POST /api/devices", a.createDevice)
	auth("session", "DELETE /api/devices/{id}", a.deleteDevice)
	auth("read", "GET /api/dhcp", a.getDHCP)
	auth("admin", "PUT /api/dhcp", a.putDHCP)
	auth("admin", "DELETE /api/dhcp/leases/{mac}", a.deleteLease)
	auth("admin", "POST /api/dhcp/reserve", a.reserveLease)
	auth("read", "GET /api/inventory", a.getInventory)
	auth("admin", "PUT /api/inventory/name", a.nameDevice)
	auth("admin", "POST /api/groups/assign", a.assignGroup)
	auth("session", "GET /api/tsig", a.listTSIG)
	auth("session", "POST /api/tsig", a.createTSIG)
	auth("session", "DELETE /api/tsig/{name}", a.deleteTSIG)
	auth("dnssec", "PUT /api/zones/{name}/transfer", a.putZoneTransfer)
	auth("read", "GET /api/secondaries", a.getSecondaries)
	auth("admin", "PUT /api/secondaries", a.putSecondaries)
	auth("read", "GET /api/rpz", a.getRPZ)
	auth("admin", "POST /api/rpz", a.addRPZ)
	auth("admin", "PUT /api/rpz/order", a.orderRPZ)
	auth("admin", "PUT /api/rpz/{id}", a.putRPZ)
	auth("admin", "DELETE /api/rpz/{id}", a.deleteRPZ)
	auth("session", "GET /api/syslog", a.getSyslog)
	auth("session", "PUT /api/syslog", a.putSyslog)
	auth("session", "GET /api/replication", a.getReplication)
	auth("session", "PUT /api/replication", a.putReplication)
	auth("sync", "GET /api/sync", a.syncExport)
	auth("sync", "GET /api/sync/role", a.syncRole)
	auth("backup", "GET /api/backup", a.backupHandler)
	auth("metrics", "GET /metrics", a.metricsHandler)
	auth("read", "GET /api/suggestions", a.suggestions)
	auth("admin", "POST /api/suggestions/dismiss", a.dismissSuggestion)
	auth("read", "GET /api/resolvers", a.getResolvers)
	auth("admin", "PUT /api/resolvers", a.putResolvers)
	auth("read", "GET /api/zones", a.getZones)
	auth("admin", "POST /api/zones", a.addZone)
	auth("admin", "PUT /api/zones/{name}", a.putZone)
	auth("admin", "POST /api/zones/check", a.checkZone)
	auth("read", "GET /api/zones/{name}/lookup", a.lookupZone)
	auth("admin", "DELETE /api/zones/{name}", a.deleteZone)
	auth("dnssec", "POST /api/zones/{name}/resign", a.resignZone)
	auth("read", "GET /api/zones/{name}/ds", a.zoneDS)
	auth("read", "GET /api/dnssec/keystore", a.dnssecKeystore)
	auth("dnssec", "POST /api/zones/{name}/rollover", a.rollover)
	auth("dnssec", "POST /api/zones/{name}/algorithm", a.algorithmRollover)
	auth("dnssec", "POST /api/zones/{name}/ds-confirm", a.confirmDS)
	auth("dnssec", "PUT /api/zones/{name}/policy", a.zonePolicy)
	auth("read", "GET /api/tls", a.getTLS)
	auth("tls", "PUT /api/tls/config", a.putTLSConfig)
	auth("tls", "POST /api/tls/acme/register", a.acmeRegister)
	auth("tls", "POST /api/tls/acme/issue", a.acmeIssue)
	auth("tls", "POST /api/tls/csr", a.tlsCSR)
	auth("tls", "POST /api/tls/certificate", a.tlsInstall)
	auth("tls", "POST /api/tls/selfsigned", a.tlsSelfSigned)
	auth("read", "GET /api/security", a.security)
	auth("read", "GET /api/audit", a.auditLog)
	auth("admin", "POST /api/cache/flush", a.flushCache)
	// « local » : compte administrateur local uniquement (son mot de passe,
	// son second facteur, et la configuration des sources de comptes).
	auth("local", "POST /api/password", a.changePassword)
	auth("local", "GET /api/otp", a.otpStatus)
	auth("local", "POST /api/otp/setup", a.otpSetup)
	auth("local", "POST /api/otp/enable", a.otpEnable)
	auth("local", "POST /api/otp/disable", a.otpDisable)
	auth("local", "POST /api/otp/recovery", a.otpRecovery)
	auth("local", "GET /api/passkeys", a.passkeyList)
	auth("local", "POST /api/passkeys/begin", a.passkeyRegisterBegin)
	auth("local", "POST /api/passkeys/finish", a.passkeyRegisterFinish)
	auth("local", "POST /api/passkeys/{id}/delete", a.passkeyDelete)
	auth("session", "GET /api/identity", a.getIdentity)
	auth("local", "PUT /api/identity", a.putIdentity)
	auth("session", "POST /api/identity/ldap/test", a.testLDAP)
	auth("session", "POST /api/identity/oidc/test", a.testOIDC)
	auth("session", "GET /api/tokens", a.listTokens)
	auth("session", "POST /api/tokens", a.createToken)
	auth("session", "DELETE /api/tokens/{id}", a.deleteToken)
	auth("session", "GET /api/quorum", a.quorumStatus)
	auth("session", "POST /api/quorum/ops", a.quorumOpen)
	auth("session", "POST /api/quorum/ops/approve", a.quorumApprove)
	auth("session", "DELETE /api/quorum/ops", a.quorumCancel)
	auth("session", "POST /api/quorum/reconfigure", a.quorumReconfigure)
	auth("session", "POST /api/kek/rotate", a.kekRotate)
	auth("session", "POST /api/kek/destroy", a.kekDestroy)
	auth("session", "POST /api/kek/policy", a.kekPolicy)
	auth("session", "GET /api/hsm", a.hsmStatus)
	auth("session", "POST /api/hsm/probe", a.hsmProbe)
	auth("session", "POST /api/hsm/test", a.hsmTest)
	auth("session", "POST /api/hsm/apply", a.hsmApply)
	auth("session", "POST /api/hsm/clone/verify", a.hsmCloneVerify)
	auth("session", "POST /api/hsm/clone/apply", a.hsmCloneApply)
	auth("session", "DELETE /api/hsm/pending", a.hsmCancel)
	auth("session", "POST /api/hsm/destroy-retired", a.hsmDestroyRetired)
	mux.Handle("GET /", a.static())
	return a.harden(a.replicaGuard(mux))
}

// ---- middleware ----

func (a *API) clientIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func (a *API) harden(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if a.SecureCk {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if len(a.AdminACL) > 0 {
			ip := a.clientIP(r)
			if !slices.ContainsFunc(a.AdminACL, func(p netip.Prefix) bool { return p.Contains(ip) }) {
				http.Error(w, "accès refusé", http.StatusForbidden)
				return
			}
		}
		// CSRF: state-changing requests must carry a custom header, which a
		// cross-site form or image cannot add without a CORS preflight. A
		// bearer token is not sent automatically by a browser either.
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-Rempart") != "1" && !hasBearer(r) {
			jsonError(w, http.StatusForbidden, "en-tête X-Rempart manquant")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next.ServeHTTP(w, r)
	})
}

func (a *API) requireAuth(scope string, h func(http.ResponseWriter, *http.Request, string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if hasBearer(r) {
			user, err := a.tokenAuth(r, scope)
			if err != nil {
				jsonError(w, http.StatusUnauthorized, err.Error())
				return
			}
			h(w, r, user)
			return
		}
		c, err := r.Cookie(cookieName)
		if err != nil {
			jsonError(w, http.StatusUnauthorized, "non authentifié")
			return
		}
		p, ok := a.sess.get(c.Value)
		if !ok {
			jsonError(w, http.StatusUnauthorized, "session expirée")
			return
		}
		if scope == "local" && p.Source != "local" {
			jsonError(w, http.StatusForbidden, "action réservée au compte administrateur local")
			return
		}
		if !roleAllows(p.Role, scope) {
			jsonError(w, http.StatusForbidden, "votre rôle ("+roleLabel(p.Role)+") ne permet pas cette action")
			return
		}
		h(w, r, p.User)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("JSON invalide: " + err.Error())
	}
	return nil
}

func (a *API) record(user, action, detail string) {
	_ = a.Audit.Add(user, action, detail)
}

// ---- auth ----

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	ip := a.clientIP(r)
	if d := a.guard.blocked(ip); d > 0 {
		jsonError(w, http.StatusTooManyRequests, fmt.Sprintf("trop d'échecs, réessayez dans %s", d.Round(time.Second)))
		return
	}
	var in struct{ Username, Password string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	st := a.Store.Get()
	adm := st.Admin
	// Le nom du compte local va toujours au compte local (accès de secours,
	// même si l'annuaire est indisponible ou contient un homonyme).
	if in.Username != adm.Username && st.Identity.LDAP.Enabled {
		a.loginLDAP(w, r, ip, in.Username, in.Password)
		return
	}
	// Always run the hash to keep timing independent of the username.
	ok := CheckPassword(in.Password, adm.PasswordHash) && in.Username == adm.Username
	if !ok {
		a.guard.failed(ip)
		a.record(in.Username, "connexion.échec", "depuis "+ip.String())
		jsonError(w, http.StatusUnauthorized, "identifiants incorrects")
		return
	}
	// Second facteur actif : le mot de passe ne suffit pas. Le compteur
	// d'échecs n'est remis à zéro qu'après le code.
	if adm.TOTPSecret != "" || len(adm.Passkeys) > 0 {
		writeJSON(w, map[string]any{"second_factor": true, "otp_required": adm.TOTPSecret != "", "passkey": len(adm.Passkeys) > 0,
			"challenge": a.chal.create(adm.Username, ip)})
		return
	}
	a.guard.success(ip)
	a.startSession(w, localPrincipal(adm.Username))
	a.record(adm.Username, "connexion", "depuis "+ip.String())
	writeJSON(w, map[string]any{"user": adm.Username, "otp_enabled": false})
}

func localPrincipal(user string) Principal {
	return Principal{User: user, Name: user, Role: RoleAdmin, Source: "local"}
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"ok": true}
	if c, err := r.Cookie(cookieName); err == nil {
		if p, ok := a.sess.get(c.Value); ok && p.Source == "oidc" {
			// Déconnexion aussi chez le fournisseur, sinon un clic sur
			// « Keycloak » rouvrirait la session sans mot de passe.
			if u := a.oidcLogoutURL(r.Context(), p.idToken); u != "" {
				out["redirect"] = u
			}
		}
		a.sess.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.SecureCk, SameSite: http.SameSiteStrictMode})
	writeJSON(w, out)
}

func (a *API) changePassword(w http.ResponseWriter, r *http.Request, user string) {
	var in struct{ Old, New string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !CheckPassword(in.Old, a.Store.Get().Admin.PasswordHash) {
		jsonError(w, http.StatusForbidden, "mot de passe actuel incorrect")
		return
	}
	if err := ValidatePassword(in.New); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.Store.Update(func(s *state.State) error { s.Admin.PasswordHash = HashPassword(in.New); return nil }); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.sess.clear() // every session must log in again (local and external)
	a.chal.clear()
	a.record(user, "mot-de-passe.changé", "")
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- status & stats ----

func (a *API) status(w http.ResponseWriter, r *http.Request, _ string) {
	st := a.Store.Get()
	bl, al := a.Blocker.Matcher().Len()
	entries, hits, miss := a.Cache.Stats()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	writeJSON(w, map[string]any{
		"version": a.Version, "uptime_s": int(time.Since(a.Started).Seconds()),
		"blocking_enabled": st.Settings.BlockingEnabled, "paused_until": st.PausedUntil,
		"rules_block": bl, "rules_allow": al,
		"cache":     map[string]any{"entries": entries, "hits": hits, "misses": miss},
		"upstreams": a.Upstreams.Stats(), "listeners": a.listeners(),
		"keystore": a.KS.Describe(), "keystore_backend": a.KS.Backend(),
		"log_mode": st.Settings.LogMode, "memory_mb": mem.Alloc >> 20, "goroutines": runtime.NumGoroutine(),
		"zones": len(st.Zones),
	})
}

func (a *API) queryLog(w http.ResponseWriter, r *http.Request, _ string) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	writeJSON(w, map[string]any{"mode": a.QLog.Mode(), "entries": a.QLog.Recent(limit, r.URL.Query().Get("q"), r.URL.Query().Get("status"))})
}

func (a *API) queryLogDays(w http.ResponseWriter, r *http.Request, _ string) {
	writeJSON(w, map[string]any{"days": a.QLog.Days()})
}

func (a *API) queryLogDay(w http.ResponseWriter, r *http.Request, user string) {
	day := r.PathValue("day")
	q := strings.ToLower(r.URL.Query().Get("q"))
	out := []querylog.Entry{}
	err := a.QLog.ReadDay(day, func(e querylog.Entry) bool {
		if q == "" || strings.Contains(e.Name, q) || strings.Contains(e.Client, q) {
			out = append(out, e)
		}
		return len(out) < 2000
	})
	if err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	a.record(user, "journal.consultation", "jour "+day+" (déchiffrement)")
	slices.Reverse(out)
	writeJSON(w, map[string]any{"entries": out})
}

// ---- settings ----

// listeners : écoutes fixes, plus DoT et DoH quand ils sont en service.
func (a *API) listeners() map[string]string {
	out := maps.Clone(a.Listeners)
	if out == nil {
		out = map[string]string{}
	}
	if a.Encrypted != nil {
		maps.Copy(out, a.Encrypted.Listeners())
	}
	return out
}

func (a *API) getSettings(w http.ResponseWriter, r *http.Request, _ string) {
	writeJSON(w, a.Store.Get().Settings)
}

func (a *API) putSettings(w http.ResponseWriter, r *http.Request, user string) {
	var in state.Settings
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !slices.Contains([]string{"zero", "nxdomain", "refused"}, in.BlockingMode) ||
		!slices.Contains([]string{"none", "stats", "full"}, in.LogMode) ||
		!slices.Contains([]string{"pseudonymize", "truncate", "clear"}, in.ClientIDs) ||
		in.RetentionDays < 1 || in.RetentionDays > 3650 {
		jsonError(w, http.StatusBadRequest, "paramètres invalides")
		return
	}
	if in.TimeZone != "" {
		if _, err := time.LoadLocation(in.TimeZone); err != nil {
			jsonError(w, http.StatusBadRequest, "fuseau horaire inconnu (nom IANA attendu, par exemple Europe/Paris)")
			return
		}
	}
	old := a.Store.Get().Settings
	if err := a.Store.Update(func(s *state.State) error { s.Settings = in; return nil }); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.record(user, "paramètres.modifiés", diffSettings(old, in))
	writeJSON(w, in)
}

func diffSettings(a, b state.Settings) string {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	var ma, mb map[string]any
	_ = json.Unmarshal(ja, &ma)
	_ = json.Unmarshal(jb, &mb)
	var parts []string
	for k, v := range mb {
		if fmt.Sprint(ma[k]) != fmt.Sprint(v) {
			parts = append(parts, fmt.Sprintf("%s: %v → %v", k, ma[k], v))
		}
	}
	slices.Sort(parts)
	return strings.Join(parts, ", ")
}

func (a *API) pause(w http.ResponseWriter, r *http.Request, user string) {
	var in struct{ Minutes int }
	if err := decode(r, &in); err != nil || in.Minutes < 0 || in.Minutes > 24*60 {
		jsonError(w, http.StatusBadRequest, "durée invalide")
		return
	}
	until := time.Time{}
	if in.Minutes > 0 {
		until = time.Now().Add(time.Duration(in.Minutes) * time.Minute).UTC()
	}
	if err := a.Store.Update(func(s *state.State) error { s.PausedUntil = until; return nil }); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if in.Minutes > 0 {
		a.record(user, "blocage.pause", fmt.Sprintf("%d minutes", in.Minutes))
	} else {
		a.record(user, "blocage.reprise", "")
	}
	writeJSON(w, map[string]any{"paused_until": until})
}

// ---- lists & rules ----

func (a *API) getLists(w http.ResponseWriter, r *http.Request, _ string) {
	lists := a.Store.Get().Lists
	for i := range lists {
		lists[i].Count = a.Blocker.Count(lists[i].ID)
	}
	writeJSON(w, lists)
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (a *API) addList(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		Name, URL, SHA256 string
		Allow             bool
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !strings.HasPrefix(in.URL, "https://") {
		jsonError(w, http.StatusBadRequest, "seules les URL https:// sont acceptées (intégrité en transit)")
		return
	}
	if in.Name == "" {
		in.Name = in.URL
	}
	l := state.List{ID: newID(), Name: in.Name, URL: in.URL, Allow: in.Allow, Enabled: true, SHA256: strings.ToLower(in.SHA256)}
	if err := a.Store.Update(func(s *state.State) error {
		for _, e := range s.Lists {
			if e.URL == l.URL {
				return errors.New("cette liste existe déjà")
			}
		}
		s.Lists = append(s.Lists, l)
		return nil
	}); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.record(user, "liste.ajout", l.Name+" "+l.URL)
	go func() { _ = a.Blocker.Refresh(context.Background(), l.ID) }()
	writeJSON(w, l)
}

func (a *API) patchList(w http.ResponseWriter, r *http.Request, user string) {
	id := r.PathValue("id")
	var in struct{ Enabled bool }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := ""
	if err := a.Store.Update(func(s *state.State) error {
		for i := range s.Lists {
			if s.Lists[i].ID == id {
				s.Lists[i].Enabled, name = in.Enabled, s.Lists[i].Name
				return nil
			}
		}
		return errors.New("liste introuvable")
	}); err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	a.record(user, "liste.modifiée", fmt.Sprintf("%s activée=%v", name, in.Enabled))
	if in.Enabled {
		go func() { _ = a.Blocker.Refresh(context.Background(), id) }()
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) deleteList(w http.ResponseWriter, r *http.Request, user string) {
	id := r.PathValue("id")
	name := ""
	if err := a.Store.Update(func(s *state.State) error {
		for i, l := range s.Lists {
			if l.ID == id {
				name = l.Name
				s.Lists = slices.Delete(s.Lists, i, i+1)
				for j := range s.Groups {
					s.Groups[j].Lists = slices.DeleteFunc(s.Groups[j].Lists, func(x string) bool { return x == id })
				}
				return nil
			}
		}
		return errors.New("liste introuvable")
	}); err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	a.Blocker.RemoveCache(id)
	a.record(user, "liste.suppression", name)
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) refreshLists(w http.ResponseWriter, r *http.Request, user string) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	if err := a.Blocker.Refresh(ctx, ""); err != nil {
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.record(user, "listes.mise-à-jour", "")
	a.getLists(w, r, user)
}

func (a *API) getRules(w http.ResponseWriter, r *http.Request, _ string) {
	writeJSON(w, a.Store.Get().Rules)
}

func (a *API) addRule(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		Domain, Comment string
		Allow           bool
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	d, ok := filter.NormalizeDomain(strings.TrimPrefix(strings.TrimPrefix(in.Domain, "*."), "||"))
	if !ok {
		jsonError(w, http.StatusBadRequest, "nom de domaine invalide")
		return
	}
	rule := state.Rule{Domain: d, Allow: in.Allow, Comment: in.Comment, Created: time.Now().UTC()}
	if err := a.Store.Update(func(s *state.State) error {
		s.Rules = slices.DeleteFunc(s.Rules, func(x state.Rule) bool { return x.Domain == d })
		s.Rules = append(s.Rules, rule)
		return nil
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.Cache.Flush()
	kind := "blocage"
	if in.Allow {
		kind = "autorisation"
	}
	a.record(user, "règle.ajout", kind+" "+d)
	writeJSON(w, rule)
}

func (a *API) deleteRule(w http.ResponseWriter, r *http.Request, user string) {
	d := r.URL.Query().Get("domain")
	if err := a.Store.Update(func(s *state.State) error {
		n := len(s.Rules)
		s.Rules = slices.DeleteFunc(s.Rules, func(x state.Rule) bool { return x.Domain == d })
		if len(s.Rules) == n {
			return errors.New("règle introuvable")
		}
		return nil
	}); err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	a.Cache.Flush()
	a.record(user, "règle.suppression", d)
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) check(w http.ResponseWriter, r *http.Request, _ string) {
	d, ok := filter.NormalizeDomain(r.URL.Query().Get("domain"))
	if !ok {
		jsonError(w, http.StatusBadRequest, "nom de domaine invalide")
		return
	}
	res := a.Blocker.Matcher().Match(d)
	local := a.Zones.Find(d) != nil
	writeJSON(w, map[string]any{"domain": d, "result": res, "local_zone": local})
}

// ---- zones ----

type zoneView struct {
	Name      string             `json:"name"`
	DNSSEC    bool               `json:"dnssec"`
	Algorithm string             `json:"algorithm"`
	Records   []string           `json:"records"`
	Serial    uint32             `json:"serial"`
	Policy    state.ZonePolicy   `json:"policy"`
	Keys      []zones.KeyView    `json:"keys"`
	DS        []string           `json:"ds"`
	Pending   []string           `json:"pending_ds"` // DS d'une KSK prête, à publier chez le parent
	CDS       bool               `json:"cds"`
	SignedAt  string             `json:"signed_at,omitempty"`
	Expires   string             `json:"expires,omitempty"`
	KeyStore  string             `json:"key_store,omitempty"`
	KeyStoreD string             `json:"key_store_desc,omitempty"`
	Rolling   map[string]bool    `json:"rolling"`
	NextAlg   string             `json:"next_algorithm,omitempty"`
	Transfer  state.ZoneTransfer `json:"transfer"`
	Dynamic   []string           `json:"dynamic"`
}

func (a *API) getZones(w http.ResponseWriter, r *http.Request, _ string) {
	out := []zoneView{}
	origin := map[string]string{}
	for _, k := range a.KS.Keys() {
		origin[k.Label] = k.Origin
	}
	for _, sz := range a.Store.Get().Zones {
		v := zoneView{Name: sz.Name, DNSSEC: sz.DNSSEC, Algorithm: sz.Algorithm, Records: sz.Records, Serial: sz.Serial,
			Policy: sz.Policy, Keys: []zones.KeyView{}, DS: []string{}, Pending: []string{},
			Rolling:  map[string]bool{"ksk": zones.InProgress(sz, "ksk") || sz.NextAlgorithm != "", "zsk": zones.InProgress(sz, "zsk") || sz.NextAlgorithm != ""},
			NextAlg:  sz.NextAlgorithm,
			Transfer: sz.Transfer, Dynamic: sz.Dynamic}
		if z := a.Zones.Get(sz.Name); z != nil && z.DNSSEC {
			v.Keys = append([]zones.KeyView{}, z.Keys...)
			for i := range v.Keys {
				// Origine réelle lue dans le keystore (CKA_LOCAL pour un HSM).
				v.Keys[i].Imported = v.Keys[i].Imported || origin[v.Keys[i].Label] == "importée"
			}
			v.DS = z.DS()
			if p := zones.ReadyDS(sz, z); p != nil {
				v.Pending = p
			}
			v.CDS = sz.Policy.PublishCDS
			v.SignedAt, v.Expires = z.SignedAt.Format(time.RFC3339), z.Expires.Format(time.RFC3339)
			v.KeyStore, v.KeyStoreD = a.KS.Backend(), a.KS.Describe()
			v.Algorithm = string(z.Algorithm)
		}
		out = append(out, v)
	}
	writeJSON(w, out)
}

func (a *API) saveZone(user, action, name string, mutate func(*state.State) (*state.Zone, error)) (*state.Zone, error) {
	var saved *state.Zone
	err := a.Store.Update(func(s *state.State) error {
		z, err := mutate(s)
		if err != nil {
			return err
		}
		if z != nil {
			prev := z.Serial
			if cur := a.Zones.Get(z.Name); cur != nil {
				prev = max(prev, cur.Serial())
			}
			z.Serial = zones.NextSerial(prev)
			if _, err := zones.Build(a.KS, *z); err != nil { // validate and sign before saving
				return err
			}
			cp := *z
			saved = &cp
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := a.Zones.Load(a.Store.Get().Zones); err != nil {
		return nil, err
	}
	a.Cache.Flush()
	a.record(user, action, name)
	return saved, nil
}

func (a *API) addZone(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		Name, Algorithm string
		DNSSEC          bool
		Records         []string
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.ToLower(dns.Fqdn(strings.TrimSpace(in.Name)))
	if _, ok := dns.IsDomainName(name); !ok || name == "." {
		jsonError(w, http.StatusBadRequest, "nom de zone invalide")
		return
	}
	// Un seul label détournerait tout un domaine de premier niveau (« fr »,
	// « com ») pour les clients : même règle que le domaine du DHCP.
	if label := strings.TrimSuffix(name, "."); !strings.Contains(label, ".") && !dhcp.PrivateTLD(label) {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("« %s » est un domaine de premier niveau : tous les sites qui en dépendent deviendraient injoignables. Utilisez home.arpa, maison.lan ou un sous-domaine à vous (interne.mondomaine.fr)", label))
		return
	}
	if d := a.Store.Get().DHCP.Domain; dhcp.Overlaps(d, name) {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("cette zone recouvre le domaine des appareils du DHCP (%s), dont les noms ne sont pas signés : choisissez un autre nom, ou changez le domaine dans Appareils → DHCP", strings.Trim(d, ".")))
		return
	}
	if in.Algorithm == "" {
		in.Algorithm = "ECDSAP256SHA256"
	}
	if in.DNSSEC {
		alg, err := keystore.ParseAlgorithm(in.Algorithm)
		if err == nil {
			err = keystore.Supports(a.KS, alg)
		}
		if err != nil {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("%s : %v", in.Algorithm, err))
			return
		}
	}
	_, err := a.saveZone(user, "zone.création", name, func(s *state.State) (*state.Zone, error) {
		for _, z := range s.Zones {
			if z.Name == name {
				return nil, errors.New("cette zone existe déjà")
			}
		}
		s.Zones = append(s.Zones, state.Zone{Name: name, DNSSEC: in.DNSSEC, Algorithm: in.Algorithm, Records: in.Records, Policy: zones.DefaultPolicy()})
		z := &s.Zones[len(s.Zones)-1]
		if zones.Normalize(z, time.Now().UTC()) {
			if err := zones.GenerateKeys(a.KS, *z); err != nil {
				return nil, err
			}
		}
		return z, nil
	})
	if err != nil {
		jsonError(w, http.StatusBadRequest, zones.Explain(err))
		return
	}
	a.getZones(w, r, user)
}

// dnssecKeystore indique, avant la création d'une zone, où ses clés seront
// générées et quels algorithmes ce keystore sait produire.
func (a *API) dnssecKeystore(w http.ResponseWriter, r *http.Request, _ string) {
	ov, _ := keystore.LoadOverride(a.DataDir)
	writeJSON(w, map[string]any{
		"backend": a.KS.Backend(), "keystore": a.KS.Describe(),
		"algorithms": keystore.SigningAlgorithms(a.KS),
		// Bascule vers un HSM programmée mais pas encore faite : une clé créée
		// maintenant y sera importée, donc marquée « importée ».
		"hsm_pending": ov != nil && a.KS.Backend() != "pkcs11",
	})
}

func (a *API) putZone(w http.ResponseWriter, r *http.Request, user string) {
	name := strings.ToLower(dns.Fqdn(r.PathValue("name")))
	var in struct {
		Records []string
		DNSSEC  bool
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	var clean []string
	for _, l := range in.Records {
		if l = strings.TrimSpace(l); l != "" {
			clean = append(clean, l)
		}
	}
	_, err := a.saveZone(user, "zone.modification", name, func(s *state.State) (*state.Zone, error) {
		for i := range s.Zones {
			if s.Zones[i].Name == name {
				s.Zones[i].Records, s.Zones[i].DNSSEC = clean, in.DNSSEC
				if zones.Normalize(&s.Zones[i], time.Now().UTC()) {
					if err := zones.GenerateKeys(a.KS, s.Zones[i]); err != nil {
						return nil, err
					}
				}
				return &s.Zones[i], nil
			}
		}
		return nil, errors.New("zone introuvable")
	})
	if err != nil {
		jsonError(w, http.StatusBadRequest, zones.Explain(err))
		return
	}
	a.getZones(w, r, user)
}

// checkZone vérifie des lignes à blanc (assistant et mode expert de
// l'interface) : rien n'est enregistré, signé ni journalisé.
func (a *API) checkZone(w http.ResponseWriter, r *http.Request, _ string) {
	var in struct {
		Zone    string
		Records []string
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.ToLower(dns.Fqdn(strings.TrimSpace(in.Zone)))
	if _, ok := dns.IsDomainName(name); !ok || name == "." {
		jsonError(w, http.StatusBadRequest, "nom de zone invalide")
		return
	}
	if len(in.Records) > 10000 {
		jsonError(w, http.StatusBadRequest, "trop de lignes (10 000 au plus)")
		return
	}
	sz := state.Zone{Name: name}
	for _, z := range a.Store.Get().Zones {
		if z.Name == name {
			sz = z // ses enregistrements dynamiques comptent dans les conflits
		}
	}
	writeJSON(w, zones.Check(a.KS, sz, in.Records))
}

// lookupZone répond comme la zone chargée répondrait à un client.
func (a *API) lookupZone(w http.ResponseWriter, r *http.Request, _ string) {
	zone := r.PathValue("name")
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" || q == "@" {
		q = zone
	} else if !dns.IsSubDomain(strings.ToLower(dns.Fqdn(zone)), strings.ToLower(dns.Fqdn(q))) {
		q = q + "." + zone // nom relatif à la zone
	}
	if _, ok := dns.IsDomainName(q); !ok {
		jsonError(w, http.StatusBadRequest, "nom invalide")
		return
	}
	t := dns.TypeA
	if s := strings.ToUpper(r.URL.Query().Get("type")); s != "" {
		v, ok := dns.StringToType[s]
		if !ok {
			jsonError(w, http.StatusBadRequest, "type inconnu")
			return
		}
		t = v
	}
	rcode, ans, ok := a.Zones.Lookup(zone, q, t)
	if !ok {
		jsonError(w, http.StatusNotFound, "zone introuvable")
		return
	}
	writeJSON(w, map[string]any{"name": strings.ToLower(dns.Fqdn(q)), "type": dns.TypeToString[t], "rcode": rcode, "answers": ans})
}

func (a *API) deleteZone(w http.ResponseWriter, r *http.Request, user string) {
	name := strings.ToLower(dns.Fqdn(r.PathValue("name")))
	_, err := a.saveZone(user, "zone.suppression", name, func(s *state.State) (*state.Zone, error) {
		for i := range s.Zones {
			if s.Zones[i].Name == name {
				s.Zones = slices.Delete(s.Zones, i, i+1)
				return nil, nil
			}
		}
		return nil, errors.New("zone introuvable")
	})
	if err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) resignZone(w http.ResponseWriter, r *http.Request, user string) {
	if err := a.Zones.Resign(a.Store.Get().Zones); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.Cache.Flush()
	a.record(user, "zone.re-signature", r.PathValue("name"))
	a.getZones(w, r, user)
}

// ---- security ----

func (a *API) security(w http.ResponseWriter, r *http.Request, _ string) {
	var tlsInfo any = map[string]any{}
	if a.TLS != nil {
		tlsInfo = a.TLS.Info()
	}
	hard := a.Hardening
	if hard == nil {
		hard = []string{}
	}
	writeJSON(w, map[string]any{
		"keystore": a.KS.Describe(), "backend": a.KS.Backend(), "pkcs11_available": keystore.PKCS11Available,
		"keys": a.KS.Keys(), "tls": tlsInfo, "hardening": hard, "audit": a.Audit.Verify(),
		"querylog_days": a.QLog.Days(),
	})
}

func (a *API) auditLog(w http.ResponseWriter, r *http.Request, _ string) {
	writeJSON(w, map[string]any{"verify": a.Audit.Verify(), "events": a.Audit.Last(200)})
}

func (a *API) flushCache(w http.ResponseWriter, r *http.Request, user string) {
	a.Cache.Flush()
	if a.Server != nil && a.Server.Validator != nil {
		a.Server.Validator.Flush()
	}
	a.record(user, "cache.vidé", "")
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- static files ----

func (a *API) static() http.Handler {
	files := http.FileServer(http.FS(a.Web))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			jsonError(w, http.StatusNotFound, "introuvable")
			return
		}
		if _, err := fs.Stat(a.Web, strings.TrimPrefix(r.URL.Path, "/")); err != nil || r.URL.Path == "/" {
			r.URL.Path = "/"
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}
