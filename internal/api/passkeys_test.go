package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/rempart-dns/rempart/internal/webauthn/softkey"
)

// doHost : comme do, en se présentant sous le nom « localhost » (WebAuthn
// refuse une adresse IP comme identifiant de site).
func (e *idEnv) doHost(c *http.Client, method, path string, body any) (*http.Response, map[string]any) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(string(b)))
	req.Host = "localhost"
	req.Header.Set("X-Rempart", "1")
	res, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return res, out
}

const origin = "http://localhost"

func registerKey(t *testing.T, e *idEnv, adm *http.Client, k *softkey.Key, name string) {
	t.Helper()
	r, opts := e.doHost(adm, "POST", "/api/passkeys/begin", map[string]string{"password": testPW})
	if r.StatusCode != 200 {
		t.Fatalf("début d'inscription : %d %v", r.StatusCode, opts)
	}
	if rp := opts["rp"].(map[string]any)["id"]; rp != "localhost" {
		t.Fatalf("rpId %v", rp)
	}
	k.Handle, _ = b64u.DecodeString(opts["user"].(map[string]any)["id"].(string))
	resp := k.Create(opts["challenge"].(string), "localhost", origin)
	resp["name"], resp["challenge"] = name, opts["challenge"].(string)
	if r, out := e.doHost(adm, "POST", "/api/passkeys/finish", resp); r.StatusCode != 200 {
		t.Fatalf("inscription : %d %v", r.StatusCode, out)
	}
}

func TestPasskeyFlows(t *testing.T) {
	e := newIDEnv(t)
	adm := e.localAdmin()
	k := softkey.New()

	if r, _ := e.doHost(adm, "POST", "/api/passkeys/begin", map[string]string{"password": "faux"}); r.StatusCode != 403 {
		t.Fatal("inscription sans mot de passe")
	}
	// Une adresse IP ne peut pas servir d'identifiant de site.
	if r, _ := e.do(adm, "POST", "/api/passkeys/begin", map[string]string{"password": testPW}); r.StatusCode != 400 {
		t.Fatal("identifiant de site IP accepté")
	}
	registerKey(t, e, adm, k, "YubiKey")
	if len(e.a.Store.Get().Admin.Passkeys) != 1 {
		t.Fatal("clé non enregistrée")
	}

	// Mot de passe puis clé d'accès en second facteur.
	c := e.client()
	r, out := e.doHost(c, "POST", "/api/login", map[string]string{"username": "admin", "password": testPW})
	if r.StatusCode != 200 || out["passkey"] != true || out["second_factor"] != true {
		t.Fatalf("second facteur non demandé : %v", out)
	}
	if r, _ := e.doHost(c, "GET", "/api/me", nil); r.StatusCode == 200 {
		t.Fatal("session ouverte sans second facteur")
	}
	_, opts := e.doHost(c, "POST", "/api/login/passkey/begin", map[string]string{"challenge": out["challenge"].(string)})
	if len(opts["allowCredentials"].([]any)) != 1 {
		t.Fatalf("clés autorisées : %v", opts)
	}
	as := k.Get(opts["challenge"].(string), "localhost", origin)
	if r, out := e.doHost(c, "POST", "/api/login/passkey/finish", as); r.StatusCode != 200 {
		t.Fatalf("second facteur : %d %v", r.StatusCode, out)
	}
	if r, _ := e.doHost(c, "GET", "/api/me", nil); r.StatusCode != 200 {
		t.Fatal("session non ouverte")
	}
	// Rejeu de la même assertion : défi déjà consommé.
	if r, _ := e.doHost(e.client(), "POST", "/api/login/passkey/finish", as); r.StatusCode == 200 {
		t.Fatal("assertion rejouée acceptée")
	}

	// Sans mot de passe : utilisateur vérifié exigé.
	c2 := e.client()
	_, opts = e.doHost(c2, "POST", "/api/login/passkey/begin", map[string]string{})
	if opts["userVerification"] != "required" {
		t.Fatalf("UV non exigé : %v", opts)
	}
	k.UV = false
	if r, _ := e.doHost(c2, "POST", "/api/login/passkey/finish", k.Get(opts["challenge"].(string), "localhost", origin)); r.StatusCode == 200 {
		t.Fatal("connexion sans mot de passe ni vérification de l'utilisateur")
	}
	k.UV = true
	_, opts = e.doHost(c2, "POST", "/api/login/passkey/begin", map[string]string{})
	if r, out := e.doHost(c2, "POST", "/api/login/passkey/finish", k.Get(opts["challenge"].(string), "localhost", origin)); r.StatusCode != 200 {
		t.Fatalf("connexion sans mot de passe : %v", out)
	}
	if r, _ := e.doHost(c2, "GET", "/api/me", nil); r.StatusCode != 200 {
		t.Fatal("session non ouverte")
	}

	// Une autre clé, inconnue, est refusée.
	other := softkey.New()
	_, opts = e.doHost(e.client(), "POST", "/api/login/passkey/begin", map[string]string{})
	if r, _ := e.doHost(e.client(), "POST", "/api/login/passkey/finish", other.Get(opts["challenge"].(string), "localhost", origin)); r.StatusCode == 200 {
		t.Fatal("clé inconnue acceptée")
	}

	// Suppression : mot de passe exigé.
	id := e.a.Store.Get().Admin.Passkeys[0].ID
	if r, _ := e.doHost(adm, "POST", "/api/passkeys/"+id+"/delete", map[string]string{"password": "faux"}); r.StatusCode != 403 {
		t.Fatal("suppression sans mot de passe")
	}
	if r, _ := e.doHost(adm, "POST", "/api/passkeys/"+id+"/delete", map[string]string{"password": testPW}); r.StatusCode != 200 {
		t.Fatal("suppression")
	}
	if r, out := e.doHost(e.client(), "POST", "/api/login", map[string]string{"username": "admin", "password": testPW}); out["second_factor"] == true || r.StatusCode != 200 {
		t.Fatal("second facteur demandé sans clé ni TOTP")
	}
}
