// ops.go - API d'exploitation : clés TSIG, transferts et mises à jour de
// zone, zones secondaires, flux RPZ, copie de l'audit vers un syslog,
// sauvegarde, réplication.
package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/auditfwd"
	"github.com/rempart-dns/rempart/internal/replica"
	"github.com/rempart-dns/rempart/internal/rpz"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/tsig"
)

// ---- clés TSIG ----

type tsigView struct {
	Name      string    `json:"name"`
	Algorithm string    `json:"algorithm"`
	Created   time.Time `json:"created"`
	Managed   bool      `json:"managed"`
	UsedBy    []string  `json:"used_by"`
}

// keyUses liste ce qui utilise chaque clé (une clé utilisée ne se supprime pas).
func keyUses(st state.State) map[string][]string {
	u := map[string][]string{}
	add := func(k, what string) {
		if k != "" {
			k = tsig.CanonicalName(k)
			u[k] = append(u[k], what)
		}
	}
	for _, z := range st.Zones {
		add(z.Transfer.Key, "transferts "+strings.TrimSuffix(z.Name, "."))
		add(z.Transfer.UpdateKey, "mises à jour "+strings.TrimSuffix(z.Name, "."))
	}
	for _, s := range st.Secondaries {
		add(s.Key, "secondaire "+strings.TrimSuffix(s.Name, "."))
	}
	for _, f := range st.RPZ {
		add(f.Key, "RPZ "+f.Name)
	}
	add(st.Replication.Key, "réplication")
	return u
}

func (a *API) listTSIG(w http.ResponseWriter, r *http.Request, _ string) {
	st := a.Store.Get()
	uses := keyUses(st)
	out := []tsigView{}
	for _, k := range st.TSIGKeys {
		out = append(out, tsigView{k.Name, k.Algorithm, k.Created, k.Managed, append([]string{}, uses[k.Name]...)})
	}
	writeJSON(w, out)
}

// createTSIG génère une clé (ou importe celle d'un éditeur RPZ). Le secret
// n'est renvoyé qu'ici, une fois, avec les extraits de configuration.
func (a *API) createTSIG(w http.ResponseWriter, r *http.Request, user string) {
	var in struct{ Name, Algorithm, Secret string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	var k state.TSIGKey
	var err error
	imported := in.Secret != ""
	if imported {
		k, err = tsig.ImportKey(in.Name, in.Algorithm, in.Secret)
	} else {
		k, err = tsig.NewKey(in.Name, in.Algorithm)
	}
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.Store.Update(func(s *state.State) error {
		if slices.ContainsFunc(s.TSIGKeys, func(x state.TSIGKey) bool { return x.Name == k.Name }) {
			return errors.New("une clé porte déjà ce nom")
		}
		s.TSIGKeys = append(s.TSIGKeys, k)
		return nil
	}); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	action := "tsig.création"
	if imported {
		action = "tsig.import"
	}
	a.record(user, action, k.Name+" ("+strings.TrimSuffix(k.Algorithm, ".")+")")
	out := map[string]any{"name": k.Name, "algorithm": k.Algorithm}
	if !imported {
		alg := strings.TrimSuffix(k.Algorithm, ".")
		name := strings.TrimSuffix(k.Name, ".")
		out["secret"] = k.Secret
		out["bind"] = fmt.Sprintf("key \"%s\" {\n\talgorithm %s;\n\tsecret \"%s\";\n};", name, alg, k.Secret)
		out["knot"] = fmt.Sprintf("key:\n  - id: %s\n    algorithm: %s\n    secret: %s", name, alg, k.Secret)
	}
	writeJSON(w, out)
}

func (a *API) deleteTSIG(w http.ResponseWriter, r *http.Request, user string) {
	name := tsig.CanonicalName(r.PathValue("name"))
	if err := a.Store.Update(func(s *state.State) error {
		if uses := keyUses(*s)[name]; len(uses) > 0 {
			return fmt.Errorf("clé utilisée : %s", strings.Join(uses, ", "))
		}
		i := slices.IndexFunc(s.TSIGKeys, func(k state.TSIGKey) bool { return k.Name == name })
		if i < 0 {
			return errors.New("clé introuvable")
		}
		s.TSIGKeys = slices.Delete(s.TSIGKeys, i, i+1)
		return nil
	}); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.record(user, "tsig.suppression", name)
	writeJSON(w, map[string]bool{"ok": true})
}

func keyKnown(st state.State, name string) bool {
	n := tsig.CanonicalName(name)
	return slices.ContainsFunc(st.TSIGKeys, func(k state.TSIGKey) bool { return k.Name == n })
}

func validHostPort(s string) bool {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Port() != 0
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// ---- transferts et mises à jour d'une zone ----

func (a *API) putZoneTransfer(w http.ResponseWriter, r *http.Request, user string) {
	name := strings.ToLower(dns.Fqdn(r.PathValue("name")))
	var in state.ZoneTransfer
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	st := a.Store.Get()
	for _, s := range in.Secondaries {
		if !validHostPort(s) {
			jsonError(w, http.StatusBadRequest, "secondaire "+s+" : adresse IP (ou IP:port) attendue")
			return
		}
	}
	for _, p := range in.UpdateFrom {
		if _, err := netip.ParsePrefix(p); err != nil {
			if _, err := netip.ParseAddr(p); err != nil {
				jsonError(w, http.StatusBadRequest, "origine des mises à jour "+p+" : adresse ou préfixe attendu")
				return
			}
		}
	}
	if len(in.Secondaries) > 0 && !keyKnown(st, in.Key) {
		jsonError(w, http.StatusBadRequest, "les transferts exigent une clé TSIG existante")
		return
	}
	if in.UpdateKey != "" && (!keyKnown(st, in.UpdateKey) || len(in.UpdateFrom) == 0) {
		jsonError(w, http.StatusBadRequest, "les mises à jour exigent une clé TSIG existante et au moins une origine autorisée")
		return
	}
	if in.UpdateKey != "" && in.Key != "" && tsig.CanonicalName(in.UpdateKey) == tsig.CanonicalName(in.Key) {
		jsonError(w, http.StatusBadRequest, "utilisez des clés distinctes pour les transferts et les mises à jour")
		return
	}
	if in.Key != "" {
		in.Key = tsig.CanonicalName(in.Key)
	}
	if in.UpdateKey != "" {
		in.UpdateKey = tsig.CanonicalName(in.UpdateKey)
	}
	if in.Secondaries == nil {
		in.Secondaries = []string{}
	}
	if in.UpdateFrom == nil {
		in.UpdateFrom = []string{}
	}
	if err := a.Store.Update(func(s *state.State) error {
		for i := range s.Zones {
			if strings.ToLower(dns.Fqdn(s.Zones[i].Name)) == name {
				s.Zones[i].Transfer = in
				return nil
			}
		}
		return errors.New("zone introuvable")
	}); err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	a.record(user, "zone.transferts", fmt.Sprintf("%s : secondaires %v (clé %s), mises à jour %v (clé %s)", name, in.Secondaries, in.Key, in.UpdateFrom, in.UpdateKey))
	if a.Authority != nil {
		a.Authority.NotifyAll(a.loadedZones())
	}
	writeJSON(w, in)
}

// ---- zones secondaires ----

func (a *API) getSecondaries(w http.ResponseWriter, r *http.Request, _ string) {
	out := map[string]any{"config": a.Store.Get().Secondaries, "status": []any{}}
	if a.Authority != nil {
		out["status"] = a.Authority.Secondaries()
	}
	writeJSON(w, out)
}

func (a *API) putSecondaries(w http.ResponseWriter, r *http.Request, user string) {
	var in []state.SecondaryZone
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	st := a.Store.Get()
	seen := map[string]bool{}
	for i := range in {
		s := &in[i]
		s.Name, s.Managed = strings.ToLower(dns.Fqdn(strings.TrimSpace(s.Name))), false
		if _, ok := dns.IsDomainName(s.Name); !ok || s.Name == "." || seen[s.Name] {
			jsonError(w, http.StatusBadRequest, "nom de zone invalide ou en double : "+s.Name)
			return
		}
		seen[s.Name] = true
		if slices.ContainsFunc(st.Zones, func(z state.Zone) bool { return strings.ToLower(dns.Fqdn(z.Name)) == s.Name }) {
			jsonError(w, http.StatusBadRequest, s.Name+" est déjà une zone primaire de ce serveur")
			return
		}
		if !validHostPort(s.Primary) || !keyKnown(st, s.Key) {
			jsonError(w, http.StatusBadRequest, s.Name+" : primaire (IP ou IP:port) et clé TSIG existante requis")
			return
		}
		s.Key = tsig.CanonicalName(s.Key)
	}
	if err := a.Store.Update(func(s *state.State) error {
		keep := slices.DeleteFunc(slices.Clone(s.Secondaries), func(z state.SecondaryZone) bool { return !z.Managed })
		s.Secondaries = append(keep, in...)
		return nil
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.record(user, "zones-secondaires.configuration", fmt.Sprintf("%d zone(s)", len(in)))
	a.getSecondaries(w, r, user)
}

// ---- RPZ ----

func (a *API) getRPZ(w http.ResponseWriter, r *http.Request, _ string) {
	// La chaîne de requête d'une URL de flux porte souvent la clé d'accès
	// de l'éditeur : elle n'est pas renvoyée (rôle lecture compris).
	feeds := a.Store.Get().RPZ
	for i := range feeds {
		feeds[i].URL = rpz.Redact(feeds[i].URL)
	}
	out := map[string]any{"feeds": feeds, "status": map[string]any{}}
	if a.RPZ != nil {
		out["status"] = a.RPZ.Status()
	}
	writeJSON(w, out)
}

func cleanFeed(st state.State, f *state.RPZFeed) error {
	f.Name = strings.TrimSpace(f.Name)
	f.Zone = strings.ToLower(dns.Fqdn(strings.TrimSpace(f.Zone)))
	if f.Name == "" || len(f.Name) > 64 {
		return errors.New("nom du flux requis (64 caractères au plus)")
	}
	if _, ok := dns.IsDomainName(f.Zone); !ok || f.Zone == "." {
		return errors.New("nom de la zone RPZ invalide")
	}
	if f.Minutes < 0 || f.Minutes > 24*60 {
		return errors.New("période de rafraîchissement entre 1 minute et 24 heures (0 : celle du SOA)")
	}
	switch f.Source {
	case "axfr":
		if !validHostPort(f.Primary) || !keyKnown(st, f.Key) {
			return errors.New("AXFR : primaire (IP ou IP:port) et clé TSIG existante requis")
		}
		f.Key, f.URL = tsig.CanonicalName(f.Key), ""
	case "https":
		u, err := url.Parse(f.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return errors.New("HTTPS : adresse https:// requise")
		}
		f.Primary, f.Key = "", ""
	default:
		return errors.New("source : axfr ou https")
	}
	return nil
}

func (a *API) addRPZ(w http.ResponseWriter, r *http.Request, user string) {
	var f state.RPZFeed
	if err := decode(r, &f); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := cleanFeed(a.Store.Get(), &f); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	f.ID = newID()
	if err := a.Store.Update(func(s *state.State) error { s.RPZ = append(s.RPZ, f); return nil }); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.record(user, "rpz.ajout", f.Name+" ("+f.Zone+", "+f.Source+")")
	writeJSON(w, f)
}

func (a *API) putRPZ(w http.ResponseWriter, r *http.Request, user string) {
	id := r.PathValue("id")
	var f state.RPZFeed
	if err := decode(r, &f); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, old := range a.Store.Get().RPZ {
		if old.ID == id && f.URL != "" && f.URL == rpz.Redact(old.URL) {
			f.URL = old.URL // URL masquée renvoyée telle quelle : inchangée
		}
	}
	if err := cleanFeed(a.Store.Get(), &f); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	f.ID = id
	// L'ordre compte (le premier flux qui correspond l'emporte) : « position »
	// optionnelle dans la requête n'existe pas, l'ordre se règle par
	// suppression et ajout, ou par /api/rpz/order.
	if err := a.Store.Update(func(s *state.State) error {
		i := slices.IndexFunc(s.RPZ, func(x state.RPZFeed) bool { return x.ID == id })
		if i < 0 {
			return errors.New("flux introuvable")
		}
		s.RPZ[i] = f
		return nil
	}); err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	a.record(user, "rpz.modification", fmt.Sprintf("%s actif=%v", f.Name, f.Enabled))
	writeJSON(w, f)
}

func (a *API) orderRPZ(w http.ResponseWriter, r *http.Request, user string) {
	var ids []string
	if err := decode(r, &ids); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.Store.Update(func(s *state.State) error {
		if len(ids) != len(s.RPZ) {
			return errors.New("ordre incomplet")
		}
		var out []state.RPZFeed
		for _, id := range ids {
			i := slices.IndexFunc(s.RPZ, func(x state.RPZFeed) bool { return x.ID == id })
			if i < 0 {
				return errors.New("flux inconnu " + id)
			}
			out = append(out, s.RPZ[i])
		}
		s.RPZ = out
		return nil
	}); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.record(user, "rpz.ordre", strings.Join(ids, ", "))
	a.getRPZ(w, r, user)
}

func (a *API) deleteRPZ(w http.ResponseWriter, r *http.Request, user string) {
	id := r.PathValue("id")
	name := ""
	if err := a.Store.Update(func(s *state.State) error {
		i := slices.IndexFunc(s.RPZ, func(x state.RPZFeed) bool { return x.ID == id })
		if i < 0 {
			return errors.New("flux introuvable")
		}
		name = s.RPZ[i].Name
		s.RPZ = slices.Delete(s.RPZ, i, i+1)
		return nil
	}); err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	a.record(user, "rpz.suppression", name)
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- syslog / SIEM ----

func (a *API) getSyslog(w http.ResponseWriter, r *http.Request, _ string) {
	out := map[string]any{"config": a.Store.Get().Syslog, "status": nil}
	if a.Forwarder != nil {
		out["status"] = a.Forwarder.Status()
	}
	writeJSON(w, out)
}

func (a *API) putSyslog(w http.ResponseWriter, r *http.Request, user string) {
	var in state.SyslogConfig
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := auditfwd.Validate(in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Enabled && in.Network != "tls" {
		// Accepté (collecteurs internes), mais signalé dans l'audit.
		a.record(user, "syslog.transport-en-clair", in.Network+" vers "+in.Address)
	}
	if err := a.Store.Update(func(s *state.State) error { s.Syslog = in; return nil }); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	detail := "désactivée"
	if in.Enabled {
		detail = in.Network + "://" + in.Address
	}
	a.record(user, "syslog.configuration", detail)
	a.getSyslog(w, r, user)
}

// ---- réplication ----

func (a *API) getReplication(w http.ResponseWriter, r *http.Request, _ string) {
	rep := a.Store.Get().Replication
	hasToken := rep.Token != ""
	rep.Token = ""
	out := map[string]any{"config": rep, "token_set": hasToken, "status": nil}
	if a.Replica != nil && (rep.Role == "replica" || rep.Failover) {
		out["status"] = a.Replica.Status()
	}
	writeJSON(w, out)
}

func (a *API) putReplication(w http.ResponseWriter, r *http.Request, user string) {
	var in state.Replication
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	st := a.Store.Get()
	if in.Replicas == nil {
		in.Replicas = []string{}
	}
	// Champs de l'autre instance : URL, DNS, jeton, AC.
	checkPeer := func() bool {
		u, err := url.Parse(in.PrimaryURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			jsonError(w, http.StatusBadRequest, "adresse de l'autre instance : https://hôte:port")
			return false
		}
		if !validHostPort(in.PrimaryDNS) {
			jsonError(w, http.StatusBadRequest, "adresse DNS de l'autre instance : IP ou IP:port")
			return false
		}
		if in.Token == "" {
			in.Token = st.Replication.Token // inchangé : jamais renvoyé par l'API
		}
		if !strings.HasPrefix(in.Token, tokenPrefix) {
			jsonError(w, http.StatusBadRequest, "jeton de synchronisation (portée « sync ») de l'autre instance requis")
			return false
		}
		if _, err := replica.HTTPClient(in.CABundle); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return false
		}
		return true
	}
	checkPrimary := func() bool {
		if len(in.Replicas) == 0 {
			jsonError(w, http.StatusBadRequest, "déclarez au moins une réplique : seules ses adresses lisent la configuration")
			return false
		}
		for _, ip := range in.Replicas {
			if !validHostPort(ip) {
				jsonError(w, http.StatusBadRequest, "réplique "+ip+" : adresse IP attendue")
				return false
			}
		}
		if !keyKnown(st, in.Key) {
			jsonError(w, http.StatusBadRequest, "une clé TSIG existante est requise pour les transferts vers les répliques")
			return false
		}
		in.Key = tsig.CanonicalName(in.Key)
		return true
	}
	if in.FailoverMinutes < 0 || in.FailoverMinutes > 24*60 || (in.FailoverMinutes > 0 && in.FailoverMinutes < 2) {
		jsonError(w, http.StatusBadRequest, "délai de bascule : 2 minutes à 24 heures")
		return
	}
	in.Epoch = st.Replication.Epoch
	in.Acting = false
	switch in.Role {
	case "":
		in = state.Replication{Replicas: []string{}, Epoch: st.Replication.Epoch}
	case "primary":
		if !checkPrimary() {
			return
		}
		if in.Failover {
			if !checkPeer() {
				return
			}
		} else {
			in.PrimaryURL, in.PrimaryDNS, in.Token, in.CABundle = "", "", "", ""
		}
		in.Preferred = in.Failover
	case "replica":
		if !checkPeer() {
			return
		}
		if in.Failover {
			// Pour la bascule : adresses autorisées une fois principale
			// (l'autre instance) et clé TSIG de réplication.
			if len(in.Replicas) == 0 {
				in.Replicas = []string{in.PrimaryDNS}
			}
			for _, ip := range in.Replicas {
				if !validHostPort(ip) {
					jsonError(w, http.StatusBadRequest, "adresse "+ip+" : IP attendue")
					return
				}
			}
			if in.Key != "" {
				in.Key = tsig.CanonicalName(in.Key)
			}
		} else {
			in.Replicas, in.Key = []string{}, ""
		}
		in.Preferred = false
	default:
		jsonError(w, http.StatusBadRequest, "rôle : vide, primary ou replica")
		return
	}
	if err := a.Store.Update(func(s *state.State) error {
		s.Replication = in
		if in.Role != "replica" { // les éléments reçus redeviennent locaux
			for i := range s.TSIGKeys {
				s.TSIGKeys[i].Managed = false
			}
			s.Secondaries = slices.DeleteFunc(s.Secondaries, func(z state.SecondaryZone) bool { return z.Managed })
		}
		return nil
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	detail := "aucune"
	switch in.Role {
	case "primary":
		detail = "instance principale, répliques " + strings.Join(in.Replicas, ", ")
	case "replica":
		detail = "réplique de " + in.PrimaryURL
	}
	if in.Failover {
		detail += fmt.Sprintf(", bascule automatique après %d min", max(in.FailoverMinutes, replica.DefaultFailoverMinutes))
	}
	a.record(user, "réplication.configuration", detail)
	a.getReplication(w, r, user)
}

// syncRole : rôle de cette instance, lu par l'autre (bascule automatique).
func (a *API) syncRole(w http.ResponseWriter, r *http.Request, _ string) {
	rep := a.Store.Get().Replication
	writeJSON(w, replica.RoleInfo{Role: rep.Role, Epoch: rep.Epoch, Acting: rep.Acting})
}

// syncExport : configuration publiée aux répliques (jeton « sync »).
func (a *API) syncExport(w http.ResponseWriter, r *http.Request, user string) {
	st := a.Store.Get()
	if st.Replication.Role != "primary" {
		jsonError(w, http.StatusConflict, "cette instance n'est pas une instance principale")
		return
	}
	if len(st.Replication.Replicas) > 0 {
		ip := a.clientIP(r)
		if !slices.ContainsFunc(st.Replication.Replicas, func(s string) bool {
			h := s
			if hh, _, err := net.SplitHostPort(s); err == nil {
				h = hh
			}
			a, err := netip.ParseAddr(h)
			return err == nil && a.Unmap() == ip
		}) {
			jsonError(w, http.StatusForbidden, "adresse non déclarée comme réplique")
			return
		}
	}
	p := replica.Export(st)
	etag := replica.ETag(p)
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	a.record(user, "réplication.export", "vers "+a.clientIP(r).String())
	writeJSON(w, map[string]any{"payload": p, "replication_key": st.Replication.Key, "epoch": st.Replication.Epoch, "acting": st.Replication.Acting})
}

// replicaGuard : sur une réplique, la configuration recopiée ne se modifie
// pas localement (elle serait écrasée à la synchronisation suivante).
func (a *API) replicaGuard(next http.Handler) http.Handler {
	prefixes := []string{"/api/lists", "/api/rules", "/api/groups", "/api/devices", "/api/settings", "/api/resolvers", "/api/rpz", "/api/suggestions/dismiss"}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && a.Store.Get().Replication.Role == "replica" {
			for _, p := range prefixes {
				if strings.HasPrefix(r.URL.Path, p) {
					jsonError(w, http.StatusConflict, "instance réplique : modifiez cette configuration sur l'instance principale")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
