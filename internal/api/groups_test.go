package api

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rempart-dns/rempart/internal/blocker"
	"github.com/rempart-dns/rempart/internal/cache"
	"github.com/rempart-dns/rempart/internal/policy"
	"github.com/rempart-dns/rempart/internal/server"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
	"github.com/rempart-dns/rempart/internal/tlsutil"
)

func TestGroupsAndDevices(t *testing.T) {
	e := newIDEnv(t)
	eng, _ := blocker.New(e.a.Store, t.TempDir(), nil, testutil.Logger())
	srv := &server.Server{}
	e.a.Blocker, e.a.Cache, e.a.Server = eng, cache.New(10, 0, 0), srv
	e.a.Encrypted = server.NewEncrypted(srv, nil, "", ":443", "/dns-query", "")
	tm, err := tlsutil.New(e.a.KS, tlsutil.Options{KeyLabel: "rempart-tls", SelfSignedNames: []string{"dns.maison.example"}, DataDir: t.TempDir()}, "", nil, testutil.Logger())
	if err != nil {
		t.Fatal(err)
	}
	e.a.TLS = tm
	e.a.Store.Subscribe(func(st state.State) {
		if p, err := policy.Compile(st); err == nil {
			srv.SetPolicy(p)
		}
	})
	adm := e.localAdmin()
	// Interrupteur général actif, comme dans tout état créé au premier démarrage.
	if err := e.a.Store.Update(func(s *state.State) error { s.Settings.BlockingEnabled = true; return nil }); err != nil {
		t.Fatal(err)
	}

	bad := []map[string]any{
		{"name": "x", "clients": []string{"pas-une-ip"}},
		{"name": "x", "services": []string{"inconnu"}},
		{"name": "x", "schedules": []map[string]any{{"name": "s", "days": []int{1}, "start": "25:00", "end": "07:00", "block_all": true}}},
		{"name": "x", "lists": []string{"cat-inconnue"}},
		{"name": ""},
	}
	for _, b := range bad {
		if r, out := e.do(adm, "POST", "/api/groups", b); r.StatusCode != 400 {
			t.Fatalf("groupe invalide accepté : %v → %d %v", b, r.StatusCode, out)
		}
	}
	g := map[string]any{"name": "Enfants", "clients": []string{"192.168.1.0/24", "aa-bb-cc-dd-ee-ff"}, "blocking": true,
		"inherit_lists": true, "lists": []string{"cat-adult"}, "services": []string{"tiktok", "tiktok"}, "safe_search": true,
		"schedules": []map[string]any{{"name": "nuit", "days": []int{0, 1, 2, 3, 4, 5, 6}, "start": "21:30", "end": "07:00", "block_all": true}}}
	r, out := e.do(adm, "POST", "/api/groups", g)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, out)
	}
	id := out["id"].(string)
	st := e.a.Store.Get()
	if len(st.Groups) != 1 || st.Groups[0].Clients[1] != "aa:bb:cc:dd:ee:ff" || len(st.Groups[0].Services) != 1 {
		t.Fatalf("groupe mal normalisé : %+v", st.Groups)
	}
	if len(st.Lists) != 1 || st.Lists[0].ID != "cat-adult" || st.Lists[0].Enabled {
		t.Fatalf("la catégorie doit créer une liste inactive dans la politique générale : %+v", st.Lists)
	}
	if srv.Policy() == nil {
		t.Fatal("politique non appliquée")
	}
	if r, out := e.do(adm, "GET", "/api/check/client?client=192.168.1.5&domain=www.tiktok.com", nil); r.StatusCode != 200 || out["group"] != "Enfants" || out["result"].(map[string]any)["blocked"] != true {
		t.Fatalf("vérification par client : %v", out)
	}

	// Appareil : le jeton n'est rendu qu'une fois, seul son SHA-256 est gardé.
	r, out = e.do(adm, "POST", "/api/devices", map[string]any{"name": "iPhone de Léa", "group": id, "host": "dns.maison.example"})
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, out)
	}
	doh := out["doh_url"].(string)
	tok := strings.TrimPrefix(doh, "https://dns.maison.example/dns-query/")
	if len(tok) != 32 || !strings.Contains(out["mobileconfig"].(string), doh) {
		t.Fatalf("profil inattendu : %v", out)
	}
	signed, _ := base64.StdEncoding.DecodeString(out["mobileconfig_signed"].(string))
	if !strings.Contains(string(signed), doh) || out["mobileconfig_self_signed"] != true {
		t.Fatalf("profil signé absent : %v", out["mobileconfig_signer"])
	}
	raw, _ := json.Marshal(e.a.Store.Get())
	if strings.Contains(string(raw), tok) || !strings.Contains(string(raw), policy.HashToken(tok)) {
		t.Fatal("le jeton d'appareil ne doit pas être conservé en clair")
	}
	if srv.Policy().Device(tok) == "" {
		t.Fatal("jeton non reconnu par la politique")
	}
	if !strings.Contains(strings.Join(e.a.Store.Get().Groups[0].Clients, " "), "device:") {
		t.Fatal("appareil non rattaché au groupe")
	}
	devID := out["device"].(map[string]any)["id"].(string)
	if r, _ := e.do(adm, "DELETE", "/api/devices/"+devID, nil); r.StatusCode != 200 || srv.Policy().Device(tok) != "" {
		t.Fatal("révocation de l'appareil")
	}
	if r, _ := e.do(adm, "POST", "/api/groups/"+id+"/pause", map[string]any{"minutes": 5}); r.StatusCode != 200 {
		t.Fatal("pause du groupe")
	}
	if r, _ := e.do(adm, "DELETE", "/api/groups/"+id, nil); r.StatusCode != 200 || len(e.a.Store.Get().Groups) != 0 {
		t.Fatal("suppression du groupe")
	}
}
