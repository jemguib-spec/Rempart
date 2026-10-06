// inventory.go - inventaire des appareils du réseau (Appareils → Tous les
// appareils). Il réunit ce que Rempart sait déjà : baux DHCP, table de
// voisinage du noyau, membres des groupes et profils mobiles. Rien n'y vient
// du journal des requêtes : l'inventaire ne dit pas ce qu'un appareil
// consulte, ni même s'il interroge Rempart.
package api

import (
	"cmp"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/rempart-dns/rempart/internal/dhcp"
	"github.com/rempart-dns/rempart/internal/policy"
	"github.com/rempart-dns/rempart/internal/state"
)

// deviceKinds : types proposés dans l'interface (icône seulement).
var deviceKinds = []string{"", "phone", "tablet", "computer", "tv", "console", "speaker", "camera", "printer", "iot", "server", "network"}

type invEntry struct {
	Key       string    `json:"key"` // MAC si connue, sinon adresse IP, sinon device:<id>
	MAC       string    `json:"mac,omitempty"`
	IPs       []string  `json:"ips"`
	Name      string    `json:"name,omitempty"`     // nom donné dans Rempart
	Hostname  string    `json:"hostname,omitempty"` // nom annoncé au DHCP
	Kind      string    `json:"kind,omitempty"`
	Sources   []string  `json:"sources"` // dhcp, voisinage, groupe, profil
	Online    bool      `json:"online"`  // bail actif ou présent dans la table de voisinage
	Static    bool      `json:"static,omitempty"`
	Lease     bool      `json:"lease,omitempty"` // bail dynamique du DHCP de Rempart
	Expires   time.Time `json:"expires,omitzero"`
	RandomMAC bool      `json:"random_mac,omitempty"` // adresse privée (bit « administrée localement »)
	Group     string    `json:"group,omitempty"`      // identifiant du groupe appliqué
	GroupName string    `json:"group_name,omitempty"`
	Match     string    `json:"match,omitempty"` // ip, mac, cidr, device : comment le groupe le reconnaît
	Device    string    `json:"device,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitzero"` // profils seulement
}

type groupRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type inventoryView struct {
	Entries     []invEntry `json:"entries"`
	Groups      []groupRef `json:"groups"`
	Kinds       []string   `json:"kinds"`
	DHCPEnabled bool       `json:"dhcp_enabled"`
	DHCPDomain  string     `json:"dhcp_domain"`
	Neighbors   int        `json:"neighbors"` // taille de la table de voisinage (0 : réseau isolé)
}

func randomMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	return err == nil && len(hw) == 6 && hw[0]&0x02 != 0
}

// normKey : clé canonique d'un appareil (MAC en minuscules ou IP).
func normKey(k string) (string, bool) {
	k = strings.TrimSpace(k)
	if hw, err := net.ParseMAC(k); err == nil && len(hw) == 6 {
		return hw.String(), true
	}
	if ip, err := netip.ParseAddr(k); err == nil {
		return ip.Unmap().String(), true
	}
	return "", false
}

func (a *API) inventory() inventoryView {
	st := a.Store.Get()
	now := time.Now()
	v := inventoryView{Entries: []invEntry{}, Groups: []groupRef{}, Kinds: deviceKinds, DHCPEnabled: st.DHCP.Enabled, DHCPDomain: st.DHCP.Domain}
	for _, g := range st.Groups {
		v.Groups = append(v.Groups, groupRef{g.ID, g.Name})
	}
	byKey := map[string]*invEntry{}
	var order []string
	get := func(mac, ip string) *invEntry {
		k := mac
		if k == "" {
			k = ip
		}
		if e := byKey[k]; e != nil {
			return e
		}
		// une IP vue d'abord sans MAC, puis avec : on fusionne
		if mac != "" && ip != "" {
			if e := byKey[ip]; e != nil && e.MAC == "" {
				delete(byKey, ip)
				e.Key, e.MAC = mac, mac
				byKey[mac] = e
				order[slices.Index(order, ip)] = mac
				return e
			}
		}
		e := &invEntry{Key: k, MAC: mac, IPs: []string{}, Sources: []string{}}
		byKey[k] = e
		order = append(order, k)
		return e
	}
	addIP := func(e *invEntry, ip string) {
		if ip != "" && !slices.Contains(e.IPs, ip) {
			e.IPs = append(e.IPs, ip)
		}
	}
	addSrc := func(e *invEntry, s string) {
		if !slices.Contains(e.Sources, s) {
			e.Sources = append(e.Sources, s)
		}
	}
	var leases []dhcp.Lease
	var neigh map[netip.Addr]string
	if a.DHCP != nil {
		leases = a.DHCP.Leases()
		neigh = a.DHCP.Neighbors()
	}
	v.Neighbors = len(neigh)
	for _, l := range leases {
		active := l.Static || now.Before(l.Expires)
		ip := ""
		if l.IP.IsValid() {
			ip = l.IP.String()
		}
		e := get(l.MAC, ip)
		addIP(e, ip)
		addSrc(e, "dhcp")
		e.Hostname = cmp.Or(e.Hostname, l.Hostname)
		e.Static = e.Static || l.Static
		e.Lease = e.Lease || (!l.Static && active)
		if !l.Static {
			e.Expires = l.Expires
		}
		e.Online = e.Online || (!l.Static && active)
	}
	ips := make([]netip.Addr, 0, len(neigh))
	for ip := range neigh {
		ips = append(ips, ip)
	}
	slices.SortFunc(ips, netip.Addr.Compare)
	for _, ip := range ips {
		e := get(neigh[ip], ip.String())
		addIP(e, ip.String())
		addSrc(e, "voisinage")
		e.Online = true
	}
	// Membres désignés précisément (IP ou MAC) mais jamais vus.
	for _, g := range st.Groups {
		for _, c := range g.Clients {
			kind, val, err := policy.ParseClient(c)
			if err != nil {
				continue
			}
			switch kind {
			case "mac":
				addSrc(get(val, ""), "groupe")
			case "ip":
				e := get("", val)
				addIP(e, val)
				addSrc(e, "groupe")
			}
		}
	}
	names := map[string]state.DeviceName{}
	for _, n := range st.DeviceNames {
		names[n.Key] = n
	}
	// Appareils nommés à la main, jamais vus ni rangés dans un groupe.
	seen := map[string]bool{}
	for _, k := range order {
		if e := byKey[k]; e != nil {
			seen[e.MAC] = true
			for _, ip := range e.IPs {
				seen[ip] = true
			}
		}
	}
	for _, n := range st.DeviceNames {
		if seen[n.Key] {
			continue
		}
		if hw, err := net.ParseMAC(n.Key); err == nil && len(hw) == 6 {
			addSrc(get(n.Key, ""), "nom")
		} else {
			e := get("", n.Key)
			addIP(e, n.Key)
			addSrc(e, "nom")
		}
	}
	pol := a.Server.Policy()
	for _, k := range order {
		e := byKey[k]
		if e == nil {
			continue
		}
		e.RandomMAC = e.MAC != "" && randomMAC(e.MAC)
		n, ok := names[e.MAC]
		for _, ip := range e.IPs {
			if !ok {
				n, ok = names[ip]
			}
		}
		if ok {
			e.Name, e.Kind = n.Name, n.Kind
		}
		if pol != nil {
			var ip netip.Addr
			if len(e.IPs) > 0 {
				ip, _ = netip.ParseAddr(e.IPs[0])
			}
			if g := pol.Identify(ip, "", e.MAC); g != nil {
				e.Group, e.GroupName = g.ID, g.Name
				e.Match = "cidr"
				if i := slices.IndexFunc(st.Groups, func(x state.Group) bool { return x.ID == g.ID }); i >= 0 {
					cl := st.Groups[i].Clients
					if slices.ContainsFunc(e.IPs, func(x string) bool { return slices.Contains(cl, x) }) {
						e.Match = "ip"
					} else if e.MAC != "" && slices.Contains(cl, e.MAC) {
						e.Match = "mac"
					}
				}
			}
		}
		v.Entries = append(v.Entries, *e)
	}
	for _, d := range st.Devices {
		e := invEntry{Key: "device:" + d.ID, IPs: []string{}, Name: d.Name, Kind: "phone", Sources: []string{"profil"}, Device: d.ID, Match: "device", LastSeen: a.Server.DeviceSeen(d.ID)}
		e.Online = !e.LastSeen.IsZero() && now.Sub(e.LastSeen) < 15*time.Minute
		for _, g := range st.Groups {
			if slices.Contains(g.Clients, "device:"+d.ID) {
				e.Group, e.GroupName = g.ID, g.Name
				break
			}
		}
		if e.Group == "" {
			e.Match = ""
		}
		v.Entries = append(v.Entries, e)
	}
	return v
}

func (a *API) getInventory(w http.ResponseWriter, r *http.Request, _ string) {
	writeJSON(w, a.inventory())
}

// nameDevice donne un nom et un type à un appareil ; un nom vide l'efface.
func (a *API) nameDevice(w http.ResponseWriter, r *http.Request, user string) {
	var in state.DeviceName
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	key, ok := normKey(in.Key)
	if !ok {
		jsonError(w, http.StatusBadRequest, "appareil désigné par une adresse MAC ou IP")
		return
	}
	in.Key, in.Name = key, strings.TrimSpace(in.Name)
	if len([]rune(in.Name)) > 64 || strings.ContainsFunc(in.Name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		jsonError(w, http.StatusBadRequest, "nom : 64 caractères au plus, sans caractère de contrôle")
		return
	}
	if !slices.Contains(deviceKinds, in.Kind) {
		jsonError(w, http.StatusBadRequest, "type d'appareil inconnu")
		return
	}
	err := a.Store.Update(func(s *state.State) error {
		s.DeviceNames = slices.DeleteFunc(s.DeviceNames, func(n state.DeviceName) bool { return n.Key == key })
		if in.Name != "" || in.Kind != "" {
			if len(s.DeviceNames) >= 4096 {
				return errors.New("4096 appareils nommés au plus")
			}
			s.DeviceNames = append(s.DeviceNames, in)
		}
		return nil
	})
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.record(user, "appareil.nom", key+" : "+cmp.Or(in.Name, "(effacé)"))
	writeJSON(w, in)
}

// assignGroup range un ou plusieurs appareils dans un groupe (ou les en
// retire, groupe vide) : chacun est désigné par sa MAC si elle est connue,
// sinon par son IP, et ses désignations exactes dans les autres groupes sont
// retirées pour qu'il n'appartienne qu'à un seul.
func (a *API) assignGroup(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		Clients []struct{ MAC, IP, Device string }
		Group   string
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(in.Clients) == 0 || len(in.Clients) > 512 {
		jsonError(w, http.StatusBadRequest, "de 1 à 512 appareils")
		return
	}
	type target struct {
		key  string
		also []string
	}
	var ts []target
	for _, c := range in.Clients {
		var t target
		if c.Device != "" {
			if _, id, err := policy.ParseClient("device:" + c.Device); err == nil {
				t.key = "device:" + id
			}
		}
		if hw, err := net.ParseMAC(strings.TrimSpace(c.MAC)); t.key == "" && err == nil && len(hw) == 6 {
			t.key = hw.String()
		}
		if ip, err := netip.ParseAddr(strings.TrimSpace(c.IP)); err == nil {
			if t.key == "" {
				t.key = ip.Unmap().String()
			} else {
				t.also = append(t.also, ip.Unmap().String())
			}
		}
		if t.key == "" {
			jsonError(w, http.StatusBadRequest, "appareil sans adresse MAC ni IP valable")
			return
		}
		ts = append(ts, t)
	}
	name := "politique générale"
	created, err := a.saveGroups(func(s *state.State) error {
		gi := -1
		if in.Group != "" {
			gi = slices.IndexFunc(s.Groups, func(g state.Group) bool { return g.ID == in.Group })
			if gi < 0 {
				return errors.New("groupe introuvable")
			}
			name = s.Groups[gi].Name
		}
		for _, t := range ts {
			drop := append([]string{t.key}, t.also...)
			for i := range s.Groups {
				s.Groups[i].Clients = slices.DeleteFunc(s.Groups[i].Clients, func(c string) bool { return slices.Contains(drop, c) })
			}
			if gi >= 0 {
				s.Groups[gi].Clients = append(s.Groups[gi].Clients, t.key)
			}
		}
		return nil
	})
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.afterGroups(created)
	keys := make([]string, len(ts))
	for i, t := range ts {
		keys[i] = t.key
	}
	a.record(user, "appareil.groupe", strings.Join(keys, ", ")+" → "+name)
	writeJSON(w, a.inventory())
}

// reserveLease transforme le bail dynamique d'un appareil en bail statique :
// il garde la même adresse et le même nom.
func (a *API) reserveLease(w http.ResponseWriter, r *http.Request, user string) {
	var in struct{ MAC, Hostname string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	hw, err := net.ParseMAC(in.MAC)
	if err != nil || len(hw) != 6 || a.DHCP == nil {
		jsonError(w, http.StatusBadRequest, "adresse MAC invalide")
		return
	}
	mac := hw.String()
	i := slices.IndexFunc(a.DHCP.Leases(), func(l dhcp.Lease) bool { return l.MAC == mac && !l.Static })
	if i < 0 {
		jsonError(w, http.StatusNotFound, "aucun bail dynamique pour cet appareil")
		return
	}
	l := a.DHCP.Leases()[i]
	host := dhcpLabel(cmp.Or(in.Hostname, l.Hostname))
	st := a.Store.Get()
	cfg := st.DHCP
	cfg.Static = append(slices.Clone(cfg.Static), state.StaticLease{MAC: mac, IP: l.IP.String(), Hostname: host})
	var zones []string
	for _, z := range st.Zones {
		zones = append(zones, z.Name)
	}
	if _, err := dhcp.Compile(cfg, zones); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.Store.Update(func(s *state.State) error {
		if slices.ContainsFunc(s.DHCP.Static, func(x state.StaticLease) bool { return x.MAC == mac }) {
			return errors.New("cet appareil a déjà un bail statique")
		}
		s.DHCP.Static = append(s.DHCP.Static, state.StaticLease{MAC: mac, IP: l.IP.String(), Hostname: host})
		return nil
	}); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.record(user, "dhcp.bail-réservé", mac+" "+l.IP.String()+" "+host)
	a.Cache.Flush()
	writeJSON(w, map[string]string{"mac": mac, "ip": l.IP.String(), "hostname": host})
}

// dhcpLabel réduit un nom à un label DNS (lettres, chiffres, tirets).
func dhcpLabel(s string) string {
	var b strings.Builder
	s = strings.NewReplacer("à", "a", "â", "a", "ä", "a", "é", "e", "è", "e", "ê", "e", "ë", "e", "î", "i", "ï", "i", "ô", "o", "ö", "o", "ù", "u", "û", "u", "ü", "u", "ç", "c", "ñ", "n").Replace(strings.ToLower(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == ' ' || r == '_' || r == '.':
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	if len(out) > 63 {
		out = strings.TrimRight(out[:63], "-")
	}
	return out
}
