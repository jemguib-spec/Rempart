package api

import (
	"net/http"
	"testing"
)

func TestAlgorithmRolloverAPI(t *testing.T) {
	e := opsEnv(t)
	adm := e.localAdmin()
	r, _ := e.do(adm, "POST", "/api/zones", map[string]any{"name": "maison.lan", "dnssec": true, "algorithm": "ECDSAP256SHA256", "records": []string{"nas IN A 192.168.1.10"}})
	if r.StatusCode != http.StatusOK {
		t.Fatalf("création : %d", r.StatusCode)
	}
	z := e.a.Store.Get().Zones[0]
	if !z.Policy.NSEC3 {
		t.Fatal("une nouvelle zone doit utiliser NSEC3")
	}
	if r, _ := e.do(adm, "POST", "/api/zones/maison.lan./algorithm", map[string]any{"algorithm": "RSA"}); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("algorithme inconnu : %d", r.StatusCode)
	}
	if r, _ := e.do(adm, "POST", "/api/zones/maison.lan./algorithm", map[string]any{"algorithm": "ED25519"}); r.StatusCode != http.StatusOK {
		t.Fatalf("démarrage : %d", r.StatusCode)
	}
	z = e.a.Store.Get().Zones[0]
	if z.NextAlgorithm != "ED25519" || len(z.Keys) != 4 {
		t.Fatalf("%+v", z)
	}
	// La zone servie est toujours signée et chargée.
	if zz := e.a.Zones.Get("maison.lan."); zz == nil || len(zz.Keys) != 4 {
		t.Fatal("zone non re-signée avec les nouvelles clés")
	}
	if r, _ := e.do(adm, "POST", "/api/zones/maison.lan./rollover", map[string]any{"role": "zsk"}); r.StatusCode != http.StatusBadRequest {
		t.Fatal("rotation de ZSK acceptée pendant le changement d'algorithme")
	}
}
