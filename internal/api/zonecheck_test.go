package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
	"github.com/rempart-dns/rempart/internal/zones"
)

func TestZoneCheckAndLookup(t *testing.T) {
	ks := testutil.Keystore(t)
	zs := []state.Zone{{Name: "maison.lan.", Records: []string{"nas IN A 192.168.1.10"}}}
	store, _, err := state.Open(ks, filepath.Join(t.TempDir(), "s"), state.State{Zones: zs})
	if err != nil {
		t.Fatal(err)
	}
	m := zones.NewManager(ks, nil)
	if err := m.Load(zs); err != nil {
		t.Fatal(err)
	}
	a := &API{Store: store, KS: ks, Zones: m}

	w := httptest.NewRecorder()
	a.checkZone(w, httptest.NewRequest("POST", "/api/zones/check", strings.NewReader(`{"zone":"maison.lan","records":["nas IN A 999.1.1.1"]}`)), "admin")
	var rep zones.CheckReport
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil || rep.OK || !strings.Contains(rep.Lines[0].Error, "IPv4") {
		t.Fatalf("vérification : %d %s", w.Code, w.Body)
	}

	r := httptest.NewRequest("GET", "/api/zones/maison.lan/lookup?q=nas", nil)
	r.SetPathValue("name", "maison.lan")
	w = httptest.NewRecorder()
	a.lookupZone(w, r, "admin")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "192.168.1.10") {
		t.Fatalf("test du nom : %d %s", w.Code, w.Body)
	}
	r = httptest.NewRequest("GET", "/api/zones/maison.lan/lookup?q=pasmaison.lan", nil)
	r.SetPathValue("name", "maison.lan")
	w = httptest.NewRecorder()
	a.lookupZone(w, r, "admin")
	if !strings.Contains(w.Body.String(), "pasmaison.lan.maison.lan") {
		t.Fatalf("un nom voisin doit être lu comme relatif : %s", w.Body)
	}
}

func TestAddZoneRefusesTLDAndDHCPOverlap(t *testing.T) {
	ks := testutil.Keystore(t)
	st := state.State{}
	st.DHCP.Domain = "home.arpa"
	store, _, err := state.Open(ks, filepath.Join(t.TempDir(), "s"), st)
	if err != nil {
		t.Fatal(err)
	}
	a := &API{Store: store, KS: ks, Zones: zones.NewManager(ks, nil)}
	for _, body := range []string{`{"name":"fr"}`, `{"name":"com."}`, `{"name":"home.arpa"}`, `{"name":"nas.home.arpa"}`} {
		w := httptest.NewRecorder()
		a.addZone(w, httptest.NewRequest("POST", "/api/zones", strings.NewReader(body)), "admin")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s accepté : %d %s", body, w.Code, w.Body)
		}
	}
}
