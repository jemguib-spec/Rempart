package api

import (
	"slices"
	"testing"

	"github.com/rempart-dns/rempart/internal/blocker"
	"github.com/rempart-dns/rempart/internal/cache"
	"github.com/rempart-dns/rempart/internal/policy"
	"github.com/rempart-dns/rempart/internal/server"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

func TestInventory(t *testing.T) {
	e := newIDEnv(t)
	eng, _ := blocker.New(e.a.Store, t.TempDir(), nil, testutil.Logger())
	srv := &server.Server{}
	e.a.Blocker, e.a.Cache, e.a.Server = eng, cache.New(10, 0, 0), srv
	e.a.Store.Subscribe(func(st state.State) {
		if p, err := policy.Compile(st); err == nil {
			srv.SetPolicy(p)
		}
	})
	adm := e.localAdmin()
	mk := func(name string, clients ...string) string {
		r, out := e.do(adm, "POST", "/api/groups", map[string]any{"name": name, "clients": clients, "blocking": true})
		if r.StatusCode != 200 {
			t.Fatal(r.StatusCode, out)
		}
		return out["id"].(string)
	}
	ga := mk("Enfants", "192.168.1.10", "AA-BB-CC-DD-EE-01")
	gb := mk("Invités", "192.168.50.0/24")

	entry := func(key string) map[string]any {
		_, out := e.do(adm, "GET", "/api/inventory", nil)
		for _, x := range out["entries"].([]any) {
			if m := x.(map[string]any); m["key"] == key {
				return m
			}
		}
		return nil
	}
	if x := entry("192.168.1.10"); x == nil || x["group"] != ga || x["match"] != "ip" {
		t.Fatalf("membre IP absent de l'inventaire : %v", x)
	}
	if x := entry("aa:bb:cc:dd:ee:01"); x == nil || x["match"] != "mac" || x["random_mac"] != true {
		t.Fatalf("membre MAC : %v (0xaa a le bit « administrée localement »)", x)
	}

	// Noms : validés, puis visibles même pour un appareil jamais vu.
	for _, bad := range []map[string]any{{"key": "pas-une-adresse", "name": "x"}, {"key": "192.168.1.20", "name": "x", "kind": "fusée"}, {"key": "192.168.1.20", "name": "a\x00b"}} {
		if r, _ := e.do(adm, "PUT", "/api/inventory/name", bad); r.StatusCode != 400 {
			t.Fatalf("nom invalide accepté : %v", bad)
		}
	}
	if r, out := e.do(adm, "PUT", "/api/inventory/name", map[string]any{"key": "192.168.1.20", "name": "Télé du salon", "kind": "tv"}); r.StatusCode != 200 {
		t.Fatal(out)
	}
	if x := entry("192.168.1.20"); x == nil || x["name"] != "Télé du salon" || x["kind"] != "tv" || x["group"] != nil {
		t.Fatalf("appareil nommé : %v", x)
	}
	// Un appareil du réseau Invités est reconnu par le préfixe.
	e.do(adm, "PUT", "/api/inventory/name", map[string]any{"key": "192.168.50.7", "name": "Portable invité"})
	if x := entry("192.168.50.7"); x == nil || x["group"] != gb || x["match"] != "cidr" {
		t.Fatalf("appartenance par réseau : %v", x)
	}

	// Ranger : l'appareil quitte son ancien groupe.
	if r, out := e.do(adm, "POST", "/api/groups/assign", map[string]any{"clients": []map[string]string{{"ip": "192.168.1.10"}, {"ip": "192.168.1.20"}}, "group": gb}); r.StatusCode != 200 {
		t.Fatal(out)
	}
	st := e.a.Store.Get()
	if slices.Contains(st.Groups[0].Clients, "192.168.1.10") || !slices.Contains(st.Groups[1].Clients, "192.168.1.10") || !slices.Contains(st.Groups[1].Clients, "192.168.1.20") {
		t.Fatalf("rangement : %+v", st.Groups)
	}
	// La MAC l'emporte sur l'IP comme clé, et l'IP exacte est retirée ailleurs.
	e.do(adm, "POST", "/api/groups/assign", map[string]any{"clients": []map[string]string{{"mac": "aa:bb:cc:dd:ee:02", "ip": "192.168.1.20"}}, "group": ga})
	st = e.a.Store.Get()
	if !slices.Contains(st.Groups[0].Clients, "aa:bb:cc:dd:ee:02") || slices.Contains(st.Groups[1].Clients, "192.168.1.20") {
		t.Fatalf("clé MAC : %+v", st.Groups)
	}
	// Retour à la politique générale.
	e.do(adm, "POST", "/api/groups/assign", map[string]any{"clients": []map[string]string{{"mac": "aa:bb:cc:dd:ee:02"}}, "group": ""})
	if slices.Contains(e.a.Store.Get().Groups[0].Clients, "aa:bb:cc:dd:ee:02") {
		t.Fatal("l'appareil devait quitter tout groupe")
	}
	for _, bad := range []map[string]any{{"clients": []map[string]string{{"ip": "x"}}, "group": ga}, {"clients": []map[string]string{{"ip": "192.168.1.30"}}, "group": "inconnu"}, {"clients": []any{}, "group": ga}} {
		if r, _ := e.do(adm, "POST", "/api/groups/assign", bad); r.StatusCode != 400 {
			t.Fatalf("rangement invalide accepté : %v", bad)
		}
	}

	// Enregistrer un groupe retire ses appareils exacts des autres groupes.
	r, out := e.do(adm, "PUT", "/api/groups/"+ga, map[string]any{"name": "Enfants", "clients": []string{"192.168.1.10", "192.168.50.0/24"}, "blocking": true})
	if r.StatusCode != 200 || len(out["moved"].([]any)) != 1 {
		t.Fatalf("appartenance exclusive : %v", out)
	}
	st = e.a.Store.Get()
	if slices.Contains(st.Groups[1].Clients, "192.168.1.10") || !slices.Contains(st.Groups[1].Clients, "192.168.50.0/24") {
		t.Fatalf("seules les désignations exactes sont exclusives : %+v", st.Groups)
	}

	if r, _ := e.do(adm, "POST", "/api/dhcp/reserve", map[string]any{"mac": "aa:bb:cc:dd:ee:01"}); r.StatusCode != 400 {
		t.Fatal("réservation sans serveur DHCP acceptée")
	}
}

func TestDHCPLabel(t *testing.T) {
	for in, want := range map[string]string{"iPhone de Léa": "iphone-de-lea", "Galaxy_S24": "galaxy-s24", "--nas--": "nas", "a..b": "a-b", "": ""} {
		if got := dhcpLabel(in); got != want {
			t.Errorf("dhcpLabel(%q) = %q, attendu %q", in, got, want)
		}
	}
}
