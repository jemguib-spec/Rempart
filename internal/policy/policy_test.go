package policy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rempart-dns/rempart/internal/state"
)

func TestScheduleActive(t *testing.T) {
	// Plage du soir qui passe minuit, définie le mardi (2).
	s, err := compileSchedule(state.Schedule{Name: "soir", Days: []int{2}, Start: "22:00", End: "07:00", BlockAll: true})
	if err != nil {
		t.Fatal(err)
	}
	at := func(day, h, m int) time.Time { return time.Date(2026, 10, 4+day, h, m, 0, 0, time.UTC) } // 4 oct. 2026 = dimanche
	cases := []struct {
		t    time.Time
		want bool
	}{
		{at(2, 21, 59), false}, {at(2, 22, 0), true}, {at(3, 6, 59), true}, {at(3, 7, 0), false},
		{at(3, 22, 30), false}, // mercredi soir : non choisi
		{at(1, 23, 0), false},  // lundi soir
	}
	for _, c := range cases {
		if got := s.active(c.t); got != c.want {
			t.Errorf("%s : %v, attendu %v", c.t.Format("Mon 15:04"), got, c.want)
		}
	}
	day, _ := compileSchedule(state.Schedule{Name: "journée", Days: []int{6}, Start: "09:00", End: "12:00", Services: []string{"tiktok"}})
	if !day.active(at(6, 9, 0)) || day.active(at(6, 12, 0)) {
		t.Fatal("plage de journée mal évaluée")
	}
	if _, err := compileSchedule(state.Schedule{Name: "vide", Days: []int{1}, Start: "09:00", End: "10:00"}); err == nil {
		t.Fatal("une plage sans service ni coupure doit être refusée")
	}
}

func TestIdentifyAndCheck(t *testing.T) {
	st := state.State{
		Lists:   []state.List{{ID: "a", Enabled: true}, {ID: "cat-adult"}},
		Devices: []state.Device{{ID: "d1", Name: "iPhone", TokenHash: HashToken("tok")}},
		Groups: []state.Group{
			{ID: "kids", Name: "Enfants", Blocking: true, InheritLists: true, Lists: []string{"cat-adult", "inconnue"},
				Clients:  []string{"192.168.1.0/24", "AA:BB:CC:DD:EE:FF", "device:d1"},
				Rules:    []state.Rule{{Domain: "ecole.example", Allow: true}, {Domain: "jeu.example"}},
				Services: []string{"tiktok"}, SafeSearch: true, YouTube: "strict",
				Schedules: []state.Schedule{{Name: "nuit", Days: []int{0, 1, 2, 3, 4, 5, 6}, Start: "22:00", End: "07:00", BlockAll: true}}},
			{ID: "pc", Name: "PC", Clients: []string{"192.168.1.10", "10.0.0.0/8"}},
		},
	}
	p, err := Compile(st)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr
	if g := p.Identify(ip("192.168.1.10"), "", ""); g == nil || g.ID != "pc" {
		t.Fatal("l'IP exacte doit l'emporter sur le préfixe")
	}
	if g := p.Identify(ip("192.168.1.20"), "", ""); g == nil || g.ID != "kids" {
		t.Fatal("préfixe attendu")
	}
	if g := p.Identify(ip("10.1.1.1"), "", "aa:bb:cc:dd:ee:ff"); g == nil || g.ID != "kids" {
		t.Fatal("la MAC doit l'emporter sur le préfixe")
	}
	if g := p.Identify(ip("203.0.113.5"), p.Device("tok"), ""); g == nil || g.ID != "kids" {
		t.Fatal("appareil identifié par jeton attendu")
	}
	if p.Device("autre") != "" || p.Identify(ip("203.0.113.5"), "", "") != nil {
		t.Fatal("client inconnu : politique générale attendue")
	}
	g := p.Identify(ip("192.168.1.20"), "", "")
	if g.ListsKey != "r0|a" || g.CatsKey != "r0|cat-adult" {
		t.Fatalf("listes du groupe : %s", g.ListsKey)
	}
	noon := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	night := time.Date(2026, 10, 6, 23, 0, 0, 0, time.UTC)
	if v := g.Check("www.tiktok.com.", noon, true); !v.Blocked {
		t.Fatal("service bloqué attendu")
	}
	if v := g.Check("www.tiktok.com.", noon, false); v.Blocked {
		t.Fatal("en pause, un service permanent n'est pas bloqué")
	}
	if v := g.Check("jeu.example.", noon, true); !v.Blocked {
		t.Fatal("règle du groupe attendue")
	}
	if v := g.Check("cours.ecole.example.", night, true); !v.Allowed {
		t.Fatal("l'exception du groupe passe même la nuit")
	}
	if v := g.Check("normal.example.", night, false); !v.Blocked {
		t.Fatal("la coupure de nuit s'applique même en pause")
	}
	if SafeTarget("www.google.fr.", true, "") != googleSafe || SafeTarget("google.co.uk.", true, "") != googleSafe ||
		SafeTarget("www.google.com.evil.example.", true, "") != "" || SafeTarget("www.youtube.com.", false, "strict") != youtubeStrict {
		t.Fatal("cibles SafeSearch")
	}
}

func TestCompileRejects(t *testing.T) {
	for _, g := range []state.Group{
		{Name: "x", Clients: []string{"pas-une-adresse"}},
		{Name: "x", Services: []string{"inexistant"}},
		{Name: "x", Schedules: []state.Schedule{{Name: "s", Days: []int{9}, Start: "10:00", End: "11:00", BlockAll: true}}},
	} {
		if _, err := Compile(state.State{Groups: []state.Group{g}}); err == nil {
			t.Fatalf("groupe invalide accepté : %+v", g)
		}
	}
	if _, err := Compile(state.State{Settings: state.Settings{TimeZone: "Mars/Olympus"}}); err == nil {
		t.Fatal("fuseau inconnu accepté")
	}
}

// Catalogue : identifiants uniques, famille connue, aucun domaine dans deux
// services (la table domaine → service n'en garderait qu'un).
func TestServiceCatalog(t *testing.T) {
	groups := map[string]bool{}
	for _, g := range ServiceGroups {
		groups[g.ID] = true
	}
	ids, owner := map[string]bool{}, map[string]string{}
	for _, s := range Services {
		if ids[s.ID] {
			t.Errorf("service %q en double", s.ID)
		}
		ids[s.ID] = true
		if !groups[s.Category] {
			t.Errorf("service %q : famille inconnue %q", s.ID, s.Category)
		}
		if len(s.Domains) == 0 {
			t.Errorf("service %q sans domaine", s.ID)
		}
		for _, d := range s.Domains {
			if o, ok := owner[d]; ok {
				t.Errorf("domaine %q dans %q et %q", d, o, s.ID)
			}
			owner[d] = s.ID
		}
	}
	for _, id := range []string{"youtube", "tiktok", "instagram", "facebook", "snapchat", "twitter", "reddit", "pinterest", "twitch", "netflix", "disneyplus", "primevideo", "whatsapp", "telegram", "discord", "roblox", "fortnite", "minecraft", "steam", "playstation", "xbox", "nintendo", "riot"} {
		if !ids[id] {
			t.Errorf("identifiant historique %q disparu : les groupes enregistrés ne se chargeraient plus", id)
		}
	}
}
