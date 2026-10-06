// dhcp.go - API du serveur DHCP facultatif.
package api

import (
	"errors"
	"net"
	"net/http"
	"net/netip"

	"github.com/rempart-dns/rempart/internal/dhcp"
	"github.com/rempart-dns/rempart/internal/state"
)

type ifaceView struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
}

func interfaces() []ifaceView {
	out := []ifaceView{}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		v := ifaceView{Name: i.Name, Addrs: []string{}}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() {
				v.Addrs = append(v.Addrs, p.String())
			}
		}
		out = append(out, v)
	}
	return out
}

func (a *API) getDHCP(w http.ResponseWriter, r *http.Request, _ string) {
	out := map[string]any{"config": a.Store.Get().DHCP, "interfaces": interfaces(), "leases": []dhcp.Lease{}, "running": false, "error": ""}
	if a.DHCP != nil {
		out["leases"], out["running"], out["error"] = a.DHCP.Leases(), a.DHCP.Running(), a.DHCP.Status()
	}
	writeJSON(w, out)
}

// checkServerIP : l'adresse annoncée doit appartenir à l'interface choisie,
// sinon les clients recevraient un DNS et un identifiant de serveur faux.
func checkServerIP(iface, ip string) error {
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return errors.New("interface " + iface + " introuvable sur ce serveur")
	}
	addrs, _ := i.Addrs()
	for _, ad := range addrs {
		if p, err := netip.ParsePrefix(ad.String()); err == nil && p.Addr().String() == ip {
			return nil
		}
	}
	return errors.New("l'adresse " + ip + " n'est pas portée par l'interface " + iface)
}

func (a *API) putDHCP(w http.ResponseWriter, r *http.Request, user string) {
	if a.DHCP == nil {
		jsonError(w, http.StatusServiceUnavailable, "serveur DHCP indisponible")
		return
	}
	var in state.DHCPConfig
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Static == nil {
		in.Static = []state.StaticLease{}
	}
	st := a.Store.Get()
	var zones []string
	for _, z := range st.Zones {
		zones = append(zones, z.Name)
	}
	// Même désactivée, une configuration enregistrée doit être valide.
	if in.Enabled || in.Interface != "" {
		if _, err := dhcp.Compile(in, zones); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if in.Enabled {
		if err := checkServerIP(in.Interface, in.ServerIP); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := a.Store.Update(func(s *state.State) error { s.DHCP = in; return nil }); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	detail := "désactivé"
	if in.Enabled {
		detail = "actif sur " + in.Interface + ", plage " + in.RangeStart + "–" + in.RangeEnd
	}
	a.record(user, "dhcp.configuration", detail)
	a.Cache.Flush()
	a.getDHCP(w, r, user)
}

func (a *API) deleteLease(w http.ResponseWriter, r *http.Request, user string) {
	hw, err := net.ParseMAC(r.PathValue("mac"))
	if err != nil || a.DHCP == nil || !a.DHCP.Forget(hw.String()) {
		jsonError(w, http.StatusNotFound, "bail introuvable")
		return
	}
	a.record(user, "dhcp.bail-supprimé", hw.String())
	writeJSON(w, map[string]bool{"ok": true})
}
