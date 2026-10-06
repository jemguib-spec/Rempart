// groups.go - API des groupes d'appareils, des services, des catégories et
// des appareils identifiés par jeton (profils DoH/DoT).
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rempart-dns/rempart/internal/cms"
	"github.com/rempart-dns/rempart/internal/filter"
	"github.com/rempart-dns/rempart/internal/policy"
	"github.com/rempart-dns/rempart/internal/state"
)

// categoryListID : liste créée à la demande pour une catégorie.
func categoryListID(id string) string { return "cat-" + id }

type groupsView struct {
	Groups     []state.Group         `json:"groups"`
	Services   []policy.Service      `json:"services"`
	SvcGroups  []policy.ServiceGroup `json:"service_groups"`
	Categories []policy.Category     `json:"categories"`
	Lists      []listRef             `json:"lists"`
	Devices    []deviceView          `json:"devices"`
	TimeZone   string                `json:"time_zone"`
}

type listRef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Allow   bool   `json:"allow"`
}

type deviceView struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"last_seen"`
}

func (a *API) getGroups(w http.ResponseWriter, r *http.Request, _ string) {
	st := a.Store.Get()
	v := groupsView{Groups: st.Groups, Services: policy.Services, SvcGroups: policy.ServiceGroups, Categories: policy.Categories,
		Lists: []listRef{}, Devices: a.deviceViews(st), TimeZone: st.Settings.TimeZone}
	for _, l := range st.Lists {
		v.Lists = append(v.Lists, listRef{l.ID, l.Name, l.Enabled, l.Allow})
	}
	if v.TimeZone == "" {
		v.TimeZone = time.Local.String()
	}
	writeJSON(w, v)
}

func (a *API) deviceViews(st state.State) []deviceView {
	out := []deviceView{}
	for _, d := range st.Devices {
		out = append(out, deviceView{d.ID, d.Name, d.Created, a.Server.DeviceSeen(d.ID)})
	}
	return out
}

// cleanGroup normalise un groupe saisi dans l'interface.
func cleanGroup(g *state.Group) error {
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" || len(g.Name) > 64 {
		return errors.New("nom du groupe requis (64 caractères au plus)")
	}
	var clients []string
	for _, c := range g.Clients {
		if strings.TrimSpace(c) == "" {
			continue
		}
		kind, v, err := policy.ParseClient(c)
		if err != nil {
			return err
		}
		if kind == "device" {
			v = "device:" + v
		}
		if !slices.Contains(clients, v) {
			clients = append(clients, v)
		}
	}
	g.Clients = clients
	switch g.YouTube {
	case "", "moderate", "strict":
	default:
		return errors.New("mode YouTube : moderate, strict ou vide")
	}
	var rules []state.Rule
	for _, r := range g.Rules {
		d, ok := filter.NormalizeDomain(strings.TrimPrefix(strings.TrimPrefix(r.Domain, "*."), "||"))
		if !ok {
			return fmt.Errorf("nom de domaine invalide %q", r.Domain)
		}
		r.Domain = d
		if r.Created.IsZero() {
			r.Created = time.Now().UTC()
		}
		rules = slices.DeleteFunc(rules, func(x state.Rule) bool { return x.Domain == d })
		rules = append(rules, r)
	}
	g.Rules = rules
	slices.Sort(g.Services)
	g.Services = slices.Compact(g.Services)
	for i := range g.Schedules {
		s := &g.Schedules[i]
		s.Name = strings.TrimSpace(s.Name)
		if s.Name == "" {
			s.Name = fmt.Sprintf("plage %d", i+1)
		}
		slices.Sort(s.Days)
		s.Days = slices.Compact(s.Days)
	}
	return nil
}

// saveGroups applique fn, crée les listes des catégories demandées, puis
// vérifie que la politique complète se compile avant d'enregistrer.
func (a *API) saveGroups(fn func(*state.State) error) ([]string, error) {
	var created []string
	err := a.Store.Update(func(s *state.State) error {
		if err := fn(s); err != nil {
			return err
		}
		for _, g := range s.Groups {
			for _, id := range g.Lists {
				cid, ok := strings.CutPrefix(id, "cat-")
				if !ok || slices.ContainsFunc(s.Lists, func(l state.List) bool { return l.ID == id }) {
					continue
				}
				i := slices.IndexFunc(policy.Categories, func(c policy.Category) bool { return c.ID == cid })
				if i < 0 {
					return fmt.Errorf("catégorie inconnue %q", cid)
				}
				c := policy.Categories[i]
				// Désactivée dans la politique générale : seuls les groupes
				// qui la choisissent l'appliquent.
				s.Lists = append(s.Lists, state.List{ID: id, Name: c.Name, URL: c.URL})
				created = append(created, id)
			}
		}
		_, err := policy.Compile(*s)
		return err
	})
	return created, err
}

func (a *API) afterGroups(created []string) {
	a.Cache.Flush()
	for _, id := range created {
		go func() { _ = a.Blocker.Refresh(context.Background(), id) }()
	}
}

func (a *API) addGroup(w http.ResponseWriter, r *http.Request, user string) {
	var g state.Group
	if err := decode(r, &g); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := cleanGroup(&g); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	g.ID, g.PausedUntil = newID(), time.Time{}
	var moved []string
	created, err := a.saveGroups(func(s *state.State) error {
		s.Groups = append(s.Groups, g)
		moved = exclusive(s, g.ID)
		return nil
	})
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.afterGroups(created)
	a.record(user, "groupe.création", g.Name+" ("+strings.Join(g.Clients, ", ")+")")
	writeJSON(w, groupSaved{g, moved})
}

func (a *API) putGroup(w http.ResponseWriter, r *http.Request, user string) {
	id := r.PathValue("id")
	var g state.Group
	if err := decode(r, &g); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := cleanGroup(&g); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	var before state.Group
	var moved []string
	created, err := a.saveGroups(func(s *state.State) error {
		for i := range s.Groups {
			if s.Groups[i].ID == id {
				before = s.Groups[i]
				g.ID, g.PausedUntil = id, s.Groups[i].PausedUntil
				s.Groups[i] = g
				moved = exclusive(s, id)
				return nil
			}
		}
		return errors.New("groupe introuvable")
	})
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.afterGroups(created)
	a.record(user, "groupe.modification", g.Name+" : "+diffGroup(before, g))
	writeJSON(w, groupSaved{g, moved})
}

// groupSaved : le groupe enregistré, et les appareils retirés d'autres groupes.
type groupSaved struct {
	state.Group
	Moved []string `json:"moved,omitempty"`
}

// exclusive retire des autres groupes les appareils que le groupe gid désigne
// exactement (IP, MAC, profil) : sinon le dernier groupe compilé l'emporterait
// sans que rien ne le signale. Les réseaux (CIDR) peuvent se recouvrir : le
// plus précis s'applique. Renvoie « appareil (ancien groupe) ».
func exclusive(s *state.State, gid string) []string {
	i := slices.IndexFunc(s.Groups, func(g state.Group) bool { return g.ID == gid })
	if i < 0 {
		return nil
	}
	var moved []string
	for _, c := range s.Groups[i].Clients {
		if kind, _, err := policy.ParseClient(c); err != nil || kind == "cidr" {
			continue
		}
		for j := range s.Groups {
			if j != i && slices.Contains(s.Groups[j].Clients, c) {
				s.Groups[j].Clients = slices.DeleteFunc(s.Groups[j].Clients, func(x string) bool { return x == c })
				moved = append(moved, c+" ("+s.Groups[j].Name+")")
			}
		}
	}
	return moved
}

// diffGroup résume les changements pour l'audit.
func diffGroup(a, b state.Group) string {
	var parts []string
	add := func(k string, x, y any) {
		if fmt.Sprint(x) != fmt.Sprint(y) {
			parts = append(parts, fmt.Sprintf("%s: %v → %v", k, x, y))
		}
	}
	add("nom", a.Name, b.Name)
	add("clients", a.Clients, b.Clients)
	add("filtrage", a.Blocking, b.Blocking)
	add("listes générales", a.InheritLists, b.InheritLists)
	add("listes", a.Lists, b.Lists)
	add("ma liste", a.InheritRules, b.InheritRules)
	rules := func(rs []state.Rule) []string {
		var out []string
		for _, r := range rs {
			if r.Allow {
				out = append(out, "@@"+r.Domain)
			} else {
				out = append(out, r.Domain)
			}
		}
		return out
	}
	scheds := func(ss []state.Schedule) []string {
		var out []string
		for _, s := range ss {
			what := "coupure"
			if !s.BlockAll {
				what = strings.Join(s.Services, "+")
			}
			out = append(out, fmt.Sprintf("%s %v %s-%s %s", s.Name, s.Days, s.Start, s.End, what))
		}
		return out
	}
	add("règles", rules(a.Rules), rules(b.Rules))
	add("services", a.Services, b.Services)
	add("plages", scheds(a.Schedules), scheds(b.Schedules))
	add("safesearch", a.SafeSearch, b.SafeSearch)
	add("youtube", a.YouTube, b.YouTube)
	if len(parts) == 0 {
		return "aucun changement"
	}
	return strings.Join(parts, ", ")
}

func (a *API) deleteGroup(w http.ResponseWriter, r *http.Request, user string) {
	id := r.PathValue("id")
	name := ""
	if _, err := a.saveGroups(func(s *state.State) error {
		for i, g := range s.Groups {
			if g.ID == id {
				name = g.Name
				s.Groups = slices.Delete(s.Groups, i, i+1)
				return nil
			}
		}
		return errors.New("groupe introuvable")
	}); err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	a.Cache.Flush()
	a.record(user, "groupe.suppression", name)
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) pauseGroup(w http.ResponseWriter, r *http.Request, user string) {
	id := r.PathValue("id")
	var in struct{ Minutes int }
	if err := decode(r, &in); err != nil || in.Minutes < 0 || in.Minutes > 24*60 {
		jsonError(w, http.StatusBadRequest, "durée invalide")
		return
	}
	until := time.Time{}
	if in.Minutes > 0 {
		until = time.Now().Add(time.Duration(in.Minutes) * time.Minute).UTC()
	}
	name := ""
	if _, err := a.saveGroups(func(s *state.State) error {
		for i := range s.Groups {
			if s.Groups[i].ID == id {
				s.Groups[i].PausedUntil, name = until, s.Groups[i].Name
				return nil
			}
		}
		return errors.New("groupe introuvable")
	}); err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	if in.Minutes > 0 {
		a.record(user, "groupe.pause", name+" "+strconv.Itoa(in.Minutes)+" minutes")
	} else {
		a.record(user, "groupe.reprise", name)
	}
	writeJSON(w, map[string]any{"paused_until": until})
}

// checkClient : verdict pour un domaine et un client donné (aide au réglage).
func (a *API) checkClient(w http.ResponseWriter, r *http.Request, _ string) {
	q := r.URL.Query()
	pol := a.Server.Policy()
	ip, err := netip.ParseAddr(q.Get("client"))
	if err != nil || pol == nil {
		jsonError(w, http.StatusBadRequest, "adresse du client invalide")
		return
	}
	d, ok := filter.NormalizeDomain(q.Get("domain"))
	if !ok {
		jsonError(w, http.StatusBadRequest, "nom de domaine invalide")
		return
	}
	ip = ip.Unmap()
	mac := ""
	if a.Server.Neighbors != nil {
		mac = a.Server.Neighbors.MAC(ip)
	}
	out := map[string]any{"domain": d, "client": ip.String(), "mac": mac, "group": nil}
	g := pol.Identify(ip, "", mac)
	set := a.Store.Get().Settings
	now := time.Now()
	filtering := set.BlockingEnabled && now.After(a.Store.Get().PausedUntil)
	m := a.Blocker.Matcher()
	if g != nil {
		out["group"] = g.Name
		filtering = filtering && g.FilteringActive(now)
		if gm := a.Blocker.MatcherFor(g.ListsKey); gm != nil {
			m = gm
		}
		if v := g.Check(d+".", now.In(pol.Loc), filtering); v.Blocked || v.Allowed {
			out["result"] = filter.Result{Blocked: v.Blocked, Allowed: v.Allowed, Rule: v.Rule, Source: v.Source}
			writeJSON(w, out)
			return
		}
		if t := policy.SafeTarget(d+".", g.SafeSearch, g.YouTube); t != "" {
			out["rewrite"] = strings.TrimSuffix(t, ".")
		}
	}
	res := filter.Result{}
	if filtering {
		res = m.Match(d)
	}
	out["result"] = res
	writeJSON(w, out)
}

// ---- appareils (jetons DoH/DoT) ----

// deviceToken : 160 bits aléatoires en base32 minuscule (32 caractères),
// utilisable comme segment d'URL et comme label DNS.
func newDeviceToken() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

type profileRequest struct {
	Name   string
	Group  string // groupe auquel rattacher l'appareil (facultatif)
	Host   string // nom public du serveur (doit figurer dans le certificat)
	CAPEM  string `json:"ca_pem"` // AC à faire approuver par l'appareil (facultatif)
	Rotate string // id d'un appareil existant : nouveau jeton
}

// createDevice crée un appareil (ou renouvelle son jeton) et renvoie, une
// seule fois, le jeton et les profils de configuration.
func (a *API) createDevice(w http.ResponseWriter, r *http.Request, user string) {
	var in profileRequest
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	in.Name, in.Host = strings.TrimSpace(in.Name), strings.ToLower(strings.TrimSpace(in.Host))
	if in.Rotate == "" && (in.Name == "" || len(in.Name) > 64) {
		jsonError(w, http.StatusBadRequest, "nom de l'appareil requis (64 caractères au plus)")
		return
	}
	if _, ok := filter.NormalizeDomain(in.Host); !ok || net.ParseIP(in.Host) != nil {
		jsonError(w, http.StatusBadRequest, "nom du serveur invalide : un nom DNS présent dans le certificat est requis")
		return
	}
	var ca []byte
	caFP := ""
	if strings.TrimSpace(in.CAPEM) != "" {
		blk, _ := pem.Decode([]byte(in.CAPEM))
		if blk == nil || blk.Type != "CERTIFICATE" {
			jsonError(w, http.StatusBadRequest, "AC : certificat PEM attendu")
			return
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil || !cert.BasicConstraintsValid || !cert.IsCA {
			jsonError(w, http.StatusBadRequest, "AC : le certificat doit être une autorité de certification (basicConstraints CA:TRUE)")
			return
		}
		ca = blk.Bytes
		sum := sha256.Sum256(ca)
		caFP = hex.EncodeToString(sum[:])
	}
	tok, err := newDeviceToken()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	dev := state.Device{ID: newID(), Name: in.Name, TokenHash: policy.HashToken(tok), Created: time.Now().UTC()}
	_, err = a.saveGroups(func(s *state.State) error {
		if in.Rotate != "" {
			i := slices.IndexFunc(s.Devices, func(d state.Device) bool { return d.ID == in.Rotate })
			if i < 0 {
				return errors.New("appareil introuvable")
			}
			s.Devices[i].TokenHash = dev.TokenHash
			dev = s.Devices[i]
			return nil
		}
		s.Devices = append(s.Devices, dev)
		if in.Group != "" {
			i := slices.IndexFunc(s.Groups, func(g state.Group) bool { return g.ID == in.Group })
			if i < 0 {
				return errors.New("groupe introuvable")
			}
			s.Groups[i].Clients = append(s.Groups[i].Clients, "device:"+dev.ID)
		}
		return nil
	})
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	doh := a.dohURL(in.Host, tok)
	action, detail := "appareil.création", dev.Name
	if in.Rotate != "" {
		action = "appareil.nouveau-jeton"
	} else if in.Group != "" {
		detail += ", groupe " + in.Group
	}
	if caFP != "" {
		detail += ", AC jointe SHA-256 " + caFP
	}
	a.record(user, action, detail)
	// Le jeton n'est renvoyé qu'ici ; seul son SHA-256 est conservé.
	profile := mobileConfig(dev, doh, ca)
	out := map[string]any{"device": deviceView{dev.ID, dev.Name, dev.Created, time.Time{}}, "doh_url": doh,
		"mobileconfig": profile, "ca_sha256": caFP}
	// Profil signé (CMS) par le certificat de l'interface : l'appareil
	// l'affiche « vérifié » si ce certificat vient d'une AC qu'il reconnaît.
	if profile != "" && a.TLS != nil {
		if chain, signer, err := a.TLS.SigningIdentity(); err == nil {
			if der, err := cms.Sign([]byte(profile), chain, signer, time.Now()); err == nil {
				info := a.TLS.Info()
				out["mobileconfig_signed"] = base64.StdEncoding.EncodeToString(der)
				out["mobileconfig_signer"] = info.Subject
				out["mobileconfig_self_signed"] = info.SelfSigned
			} else {
				a.record(user, "appareil.profil-non-signé", err.Error())
			}
		}
	}
	if a.encStatus().DoT.Enabled {
		out["dot_host"] = tok + "." + in.Host
		out["dot_plain_host"] = in.Host
	}
	writeJSON(w, out)
}

func (a *API) dohURL(host, token string) string {
	doh := a.encStatus().DoH
	if !doh.Enabled {
		return ""
	}
	u := "https://" + host
	if _, port, err := net.SplitHostPort(doh.Listen); err == nil && port != "443" {
		u += ":" + port
	}
	return u + strings.TrimSuffix(doh.Path, "/") + "/" + token
}

func (a *API) deleteDevice(w http.ResponseWriter, r *http.Request, user string) {
	id := r.PathValue("id")
	name := ""
	if _, err := a.saveGroups(func(s *state.State) error {
		i := slices.IndexFunc(s.Devices, func(d state.Device) bool { return d.ID == id })
		if i < 0 {
			return errors.New("appareil introuvable")
		}
		name = s.Devices[i].Name
		s.Devices = slices.Delete(s.Devices, i, i+1)
		for j := range s.Groups {
			s.Groups[j].Clients = slices.DeleteFunc(s.Groups[j].Clients, func(c string) bool { return c == "device:"+id })
		}
		return nil
	}); err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	a.record(user, "appareil.révocation", name)
	writeJSON(w, map[string]bool{"ok": true})
}
