// blockpage.go - page de blocage servie aux navigateurs (mode « page ») et demandes de déblocage.
// Entrées : navigateur d'un réseau autorisé, sur l'écoute DoH (443), pour un nom bloqué ; administrateur pour traiter les demandes.
// Contexte : Rempart ; la page ne montre que le nom bloqué et un formulaire : ni interface, ni règle, ni version, ni autre port.
package api

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/rempart-dns/rempart/internal/filter"
	"github.com/rempart-dns/rempart/internal/state"
)

const (
	maxUnblockPending = 200 // demandes en attente au plus (état scellé)
	maxUnblockMessage = 500 // caractères du motif
	pageRateBurst     = 5   // demandes par appareil…
	pageRateWindow    = 10 * time.Minute
)

// pageStyle : feuille en ligne, autorisée par son empreinte dans la CSP
// (aucun script, aucune ressource externe).
const pageStyle = `:root{color-scheme:light dark;--bg:#f5f6f8;--fg:#1d2330;--mut:#5b6474;--card:#fff;--line:#d9dde4;--acc:#b3261e;--btn:#1d4ed8;--ok:#166534}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--fg:#e8eaee;--mut:#a3abb9;--card:#1b2028;--line:#2e3542;--acc:#f2b8b5;--btn:#3b82f6;--ok:#86efac}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{width:100%;max-width:520px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px}
h1{margin:0 0 8px;font-size:1.4rem;color:var(--acc)}p{margin:.6em 0}.mut{color:var(--mut);font-size:.9rem}
code{display:block;margin:12px 0;padding:10px 12px;border-radius:8px;background:var(--bg);border:1px solid var(--line);font:600 1rem ui-monospace,Menlo,Consolas,monospace;overflow-wrap:anywhere}
label{display:block;margin-top:16px;font-weight:600}textarea{width:100%;min-height:90px;margin-top:6px;padding:10px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--fg);font:inherit;resize:vertical}
button{margin-top:14px;padding:10px 18px;border:0;border-radius:8px;background:var(--btn);color:#fff;font:600 1rem system-ui,sans-serif;cursor:pointer}
.ok{color:var(--ok);font-weight:600}.err{color:var(--acc);font-weight:600}`

var (
	pageCSP = "default-src 'none'; style-src 'sha256-" + styleHash() + "'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
	pageTpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Site bloqué</title><style>` + pageStyle + `</style></head>
<body><main>
<h1>Ce site est bloqué</h1>
<p>Le filtrage DNS de votre réseau empêche l'accès à :</p>
<code>{{.Domain}}</code>
{{if .Sent}}<p class="ok">Demande envoyée.</p><p>L'administrateur du réseau va l'examiner. Si elle est acceptée, rechargez la page dans quelques instants.</p>
{{else if .Error}}<p class="err">{{.Error}}</p>
{{else if .Pending}}<p class="ok">Une demande de déblocage est déjà en attente pour ce site.</p>
{{else if .Requests}}<form method="post" action="/">
<label for="m">Pourquoi en avez-vous besoin ? <span class="mut">(facultatif)</span></label>
<textarea id="m" name="message" maxlength="500"></textarea>
<button type="submit">Demander le déblocage</button>
<p class="mut">Seuls le nom du site, votre message et l'identifiant de votre appareil sont transmis à l'administrateur du réseau.</p>
</form>
{{else}}<p class="mut">Si vous pensez que c'est une erreur, contactez l'administrateur du réseau.</p>
{{end}}</main></body></html>`))
)

func styleHash() string {
	h := sha256.Sum256([]byte(pageStyle))
	return base64.StdEncoding.EncodeToString(h[:])
}

type pageData struct {
	Domain                  string
	Requests, Pending, Sent bool
	Error                   string
}

// pageRate limite les demandes par appareil (mémoire seule).
type pageRate struct {
	mu sync.Mutex
	m  map[netip.Addr][]time.Time
}

func (p *pageRate) allow(ip netip.Addr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.m == nil {
		p.m = map[netip.Addr][]time.Time{}
	}
	if len(p.m) > 4096 {
		for k, v := range p.m {
			if len(v) == 0 || now.Sub(v[len(v)-1]) > pageRateWindow {
				delete(p.m, k)
			}
		}
	}
	recent := slices.DeleteFunc(p.m[ip], func(t time.Time) bool { return now.Sub(t) > pageRateWindow })
	if len(recent) >= pageRateBurst {
		p.m[ip] = recent
		return false
	}
	p.m[ip] = append(recent, now)
	return true
}

// BlockPageHandler sert la page de blocage. Il n'est appelé que pour un nom
// bloqué récemment en mode « page », depuis un réseau autorisé (voir
// server.Encrypted) : tout chemin donne la même page.
func (a *API) BlockPageHandler() http.Handler { return http.HandlerFunc(a.blockPage) }

func (a *API) blockPage(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", pageCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	// same-origin et non no-referrer : avec no-referrer, le navigateur
	// envoie « Origin: null » avec le formulaire, refusé par samePageOrigin.
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
	host := r.Host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		host = hh
	}
	domain, ok := filter.NormalizeDomain(host)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// Scripts, images, appels des régies : rien à afficher.
	if d := r.Header.Get("Sec-Fetch-Dest"); d != "" && d != "document" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	ip := a.clientIP(r)
	client := a.pageClient(ip)
	st := a.Store.Get()
	data := pageData{Domain: domain, Requests: st.BlockPage.Requests}
	data.Pending = slices.ContainsFunc(st.UnblockRequests, func(u state.UnblockRequest) bool { return u.Domain == domain && u.Client == client })
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		renderPage(w, http.StatusForbidden, data)
	case http.MethodPost:
		code := http.StatusOK
		switch {
		case !data.Requests:
			code = http.StatusForbidden
		case !samePageOrigin(r):
			code, data.Error = http.StatusForbidden, "Demande refusée : elle doit venir de cette page."
		case !a.pageRate.allow(ip):
			code, data.Error = http.StatusTooManyRequests, "Trop de demandes depuis cet appareil. Réessayez dans quelques minutes."
		default:
			r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
			if err := r.ParseForm(); err != nil {
				code, data.Error = http.StatusBadRequest, "Demande illisible."
				break
			}
			if err := a.addUnblockRequest(domain, cleanMessage(r.PostFormValue("message")), client, ip); err != nil {
				code, data.Error = http.StatusServiceUnavailable, err.Error()
				break
			}
			data.Sent = true
		}
		renderPage(w, code, data)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func renderPage(w http.ResponseWriter, code int, d pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = pageTpl.Execute(w, d)
}

// samePageOrigin : le formulaire est posté depuis la page elle-même (même
// nom), pas par un autre site qui ferait envoyer des demandes.
func samePageOrigin(r *http.Request) bool {
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "same-origin" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && o != "https://"+r.Host {
		return false
	}
	return true
}

// cleanMessage : texte d'une ligne ou plus, sans caractères de contrôle, borné.
func cleanMessage(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return -1
		}
		return r
	}, strings.ReplaceAll(s, "\r\n", "\n"))
	s = strings.TrimSpace(s)
	if rs := []rune(s); len(rs) > maxUnblockMessage {
		s = string(rs[:maxUnblockMessage])
	}
	return s
}

// pageClient désigne l'appareil comme le journal (Réglages → Confidentialité).
func (a *API) pageClient(ip netip.Addr) string {
	if a.QLog == nil {
		return "appareil"
	}
	return a.QLog.ClientID(ip)
}

var (
	errTooManyRequests = errors.New("Trop de demandes en attente : réessayez plus tard.")
	errNotFound        = errors.New("introuvable")
)

func (a *API) addUnblockRequest(domain, msg, client string, ip netip.Addr) error {
	gid, gname := "", ""
	if a.Server != nil {
		if g := a.Server.GroupOf(ip); g != nil {
			gid, gname = g.ID, g.Name
		}
	}
	now := time.Now().UTC()
	return a.Store.Update(func(s *state.State) error {
		for i := range s.UnblockRequests {
			u := &s.UnblockRequests[i]
			if u.Domain == domain && u.Client == client {
				u.Count++
				u.Updated = now
				u.GroupID, u.GroupName = gid, gname
				if msg != "" {
					u.Message = msg
				}
				return nil
			}
		}
		if len(s.UnblockRequests) >= maxUnblockPending {
			return errTooManyRequests
		}
		s.UnblockRequests = append(s.UnblockRequests, state.UnblockRequest{ID: newID(), Domain: domain, Message: msg, Client: client,
			GroupID: gid, GroupName: gname, Count: 1, Created: now, Updated: now})
		return nil
	})
}

// ---- administration ----

func (a *API) getBlockPage(w http.ResponseWriter, r *http.Request, _ string) {
	st := a.Store.Get()
	enc := a.encStatus()
	writeJSON(w, map[string]any{
		"ipv4": st.BlockPage.IPv4, "ipv6": st.BlockPage.IPv6, "requests": st.BlockPage.Requests,
		"active":  st.Settings.BlockingMode == "page",
		"doh":     enc.DoH,
		"pending": len(st.UnblockRequests),
	})
}

// pageAddr valide une adresse de la page : une adresse réelle de Rempart,
// ni nulle, ni de bouclage, ni de diffusion de groupe.
func pageAddr(s string, v6 bool) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	ip, err := netip.ParseAddr(s)
	if err != nil || ip.Zone() != "" || ip.Is6() != v6 || ip.Is4In6() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
		if v6 {
			return "", errors.New("adresse IPv6 invalide (adresse de Rempart sur le réseau local attendue)")
		}
		return "", errors.New("adresse IPv4 invalide (adresse de Rempart sur le réseau local attendue)")
	}
	return ip.String(), nil
}

func (a *API) putBlockPage(w http.ResponseWriter, r *http.Request, user string) {
	var in state.BlockPage
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	var err error
	if in.IPv4, err = pageAddr(in.IPv4, false); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.IPv6, err = pageAddr(in.IPv6, true); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	old := a.Store.Get().BlockPage
	if err := a.Store.Update(func(s *state.State) error { s.BlockPage = in; return nil }); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if old != in {
		a.record(user, "page-blocage.modifiée", "IPv4 "+orNone(in.IPv4)+", IPv6 "+orNone(in.IPv6)+", demandes de déblocage "+onOff(in.Requests))
	}
	a.getBlockPage(w, r, user)
}

func orNone(s string) string {
	if s == "" {
		return "aucune"
	}
	return s
}

func (a *API) listUnblock(w http.ResponseWriter, r *http.Request, _ string) {
	reqs := a.Store.Get().UnblockRequests
	slices.SortFunc(reqs, func(x, y state.UnblockRequest) int { return y.Updated.Compare(x.Updated) })
	writeJSON(w, reqs)
}

// approveUnblock ajoute une exception pour le nom demandé, au groupe de
// l'appareil (scope « group ») ou à « Ma liste » (partout).
func (a *API) approveUnblock(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		Scope string `json:"scope"` // group | global
	}
	if err := decode(r, &in); err != nil || (in.Scope != "group" && in.Scope != "global") {
		jsonError(w, http.StatusBadRequest, "portée attendue : group ou global")
		return
	}
	if a.Store.Get().Replication.Role == "replica" {
		jsonError(w, http.StatusConflict, "instance réplique : ajoutez l'exception sur l'instance principale, puis refusez la demande ici")
		return
	}
	id := r.PathValue("id")
	var done state.UnblockRequest
	where := "partout (Ma liste)"
	err := a.Store.Update(func(s *state.State) error {
		i := slices.IndexFunc(s.UnblockRequests, func(u state.UnblockRequest) bool { return u.ID == id })
		if i < 0 {
			return errNotFound
		}
		done = s.UnblockRequests[i]
		rule := state.Rule{Domain: done.Domain, Allow: true, Comment: "demande de déblocage", Created: time.Now().UTC()}
		if in.Scope == "group" {
			g := slices.IndexFunc(s.Groups, func(g state.Group) bool { return g.ID == done.GroupID })
			if done.GroupID == "" || g < 0 {
				return errors.New("l'appareil n'appartient à aucun groupe : autorisez partout")
			}
			grp := &s.Groups[g]
			grp.Rules = slices.DeleteFunc(grp.Rules, func(x state.Rule) bool { return x.Domain == done.Domain })
			grp.Rules = append(grp.Rules, rule)
			where = "groupe " + grp.Name
		} else {
			s.Rules = slices.DeleteFunc(s.Rules, func(x state.Rule) bool { return x.Domain == done.Domain })
			s.Rules = append(s.Rules, rule)
		}
		// Les autres demandes satisfaites par cette exception disparaissent.
		s.UnblockRequests = slices.DeleteFunc(s.UnblockRequests, func(u state.UnblockRequest) bool {
			return u.Domain == done.Domain && (in.Scope == "global" || u.GroupID == done.GroupID)
		})
		return nil
	})
	if errors.Is(err, errNotFound) {
		jsonError(w, http.StatusNotFound, "demande introuvable")
		return
	}
	if err != nil {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	if a.Cache != nil {
		a.Cache.Flush()
	}
	if a.Server != nil {
		a.Server.ForgetBlocked(done.Domain)
	}
	a.record(user, "déblocage.accepté", done.Domain+", "+where)
	writeJSON(w, map[string]string{"domain": done.Domain, "where": where})
}

func (a *API) rejectUnblock(w http.ResponseWriter, r *http.Request, user string) {
	id := r.PathValue("id")
	var done state.UnblockRequest
	err := a.Store.Update(func(s *state.State) error {
		i := slices.IndexFunc(s.UnblockRequests, func(u state.UnblockRequest) bool { return u.ID == id })
		if i < 0 {
			return errNotFound
		}
		done = s.UnblockRequests[i]
		s.UnblockRequests = slices.Delete(s.UnblockRequests, i, i+1)
		return nil
	})
	if err != nil {
		jsonError(w, http.StatusNotFound, "demande introuvable")
		return
	}
	a.record(user, "déblocage.refusé", done.Domain)
	writeJSON(w, map[string]bool{"ok": true})
}
