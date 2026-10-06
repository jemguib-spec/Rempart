// ext_test.go - tests de l'API : tableaux vides, jetons, CSR/import, import de règles, résolveurs.
// Serveur httptest, keystore logiciel temporaire.
// Rempart ; go test ./internal/api.

package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/rempart-dns/rempart/internal/audit"
	"github.com/rempart-dns/rempart/internal/blocker"
	"github.com/rempart-dns/rempart/internal/cache"
	"github.com/rempart-dns/rempart/internal/querylog"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/suggest"
	"github.com/rempart-dns/rempart/internal/testutil"
	"github.com/rempart-dns/rempart/internal/tlsutil"
	"github.com/rempart-dns/rempart/internal/upstream"
	"github.com/rempart-dns/rempart/internal/zones"
)

type client struct {
	t      *testing.T
	url    string
	cookie *http.Cookie
	bearer string
}

func (c *client) do(method, path, body string) (int, string) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.url+path, strings.NewReader(body))
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	} else {
		req.Header.Set("X-Rempart", "1")
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.Request != nil {
		for _, ck := range res.Cookies() {
			if ck.Name == cookieName {
				c.cookie = ck
			}
		}
	}
	return res.StatusCode, string(b)
}

func newTestAPI(t *testing.T) (*client, *API) {
	ks := testutil.Keystore(t)
	dir := t.TempDir()
	store, _, _ := state.Open(ks, filepath.Join(dir, "s"), state.State{Admin: state.Admin{Username: "admin", PasswordHash: HashPassword("un-mot-de-passe-solide")}})
	al, _ := audit.Open(ks, dir)
	eng, _ := blocker.New(store, dir, nil, testutil.Logger())
	ql, _ := querylog.New(ks, dir, testutil.Logger())
	router, _ := upstream.NewRouter([]string{"127.0.0.1:1"}, nil, upstream.Options{})
	tm, err := tlsutil.New(ks, tlsutil.Options{KeyLabel: "rempart-tls", SelfSignedNames: []string{"rempart.lan"}, DataDir: dir}, "selfsigned", nil, testutil.Logger())
	if err != nil {
		t.Fatal(err)
	}
	a := &API{Store: store, Audit: al, KS: ks, Blocker: eng, QLog: ql, Zones: zones.NewManager(ks, testutil.Logger()),
		Cache: cache.New(10, 0, time.Hour), Upstreams: router, TLS: tm, Suggest: suggest.New(), DataDir: dir,
		Web: fstest.MapFS{"index.html": {Data: []byte("ok")}},
		ApplyResolvers: func(r state.Resolvers) error {
			var fwd []upstream.Forward
			for _, f := range r.Forwards {
				fwd = append(fwd, upstream.Forward{Domain: f.Domain, Servers: f.Servers})
			}
			return router.Set(r.Upstreams, fwd, upstream.Options{})
		}}
	srv := httptest.NewServer(a.Handler(time.Hour))
	t.Cleanup(srv.Close)
	c := &client{t: t, url: srv.URL}
	if code, _ := c.do("POST", "/api/login", `{"username":"admin","password":"un-mot-de-passe-solide"}`); code != 200 {
		t.Fatal("login")
	}
	return c, a
}

// Les listes vides doivent être encodées [] et non null : l'interface
// plantait sur « Cannot read properties of null (reading 'length') ».
func TestEmptyCollectionsAreArrays(t *testing.T) {
	c, _ := newTestAPI(t)
	for _, p := range []string{"/api/security", "/api/lists", "/api/rules", "/api/zones", "/api/querylog/days", "/api/tokens", "/api/suggestions", "/api/resolvers", "/api/hsm"} {
		code, body := c.do("GET", p, "")
		if code != 200 {
			t.Fatalf("%s : %d %s", p, code, body)
		}
		// Seuls des objets facultatifs (bascule HSM) peuvent valoir null.
		body = strings.NewReplacer(`"override":null`, "", `"failed":null`, "").Replace(body)
		if strings.Contains(body, ":null") || strings.TrimSpace(body) == "null" {
			t.Fatalf("%s renvoie null : %s", p, body)
		}
	}
}

func TestAPITokens(t *testing.T) {
	c, _ := newTestAPI(t)
	code, body := c.do("POST", "/api/tokens", `{"name":"ansible","scopes":["tls"],"days":30}`)
	if code != 200 {
		t.Fatal(body)
	}
	var created struct{ Token string }
	json.Unmarshal([]byte(body), &created)
	if !strings.HasPrefix(created.Token, "rmp_") {
		t.Fatalf("jeton : %q", created.Token)
	}
	if _, list := c.do("GET", "/api/tokens", ""); strings.Contains(list, created.Token) || strings.Contains(list, `"hash"`) {
		t.Fatal("le jeton ou son empreinte ne doivent jamais être relus")
	}
	tc := &client{t: t, url: c.url, bearer: created.Token}
	if code, _ := tc.do("POST", "/api/tls/csr", `{"names":["rempart.example.fr"]}`); code != 200 {
		t.Fatalf("portée tls : %d", code)
	}
	if code, _ := tc.do("PUT", "/api/settings", `{}`); code != 401 {
		t.Fatalf("portée admin refusée attendue, obtenu %d", code)
	}
	if code, _ := tc.do("POST", "/api/tokens", `{"name":"x","scopes":["admin"]}`); code != 401 {
		t.Fatalf("un jeton ne doit pas créer de jeton : %d", code)
	}
	if code, _ := tc.do("GET", "/api/status", ""); code == 401 {
		t.Fatal("la lecture doit être permise à tout jeton")
	}
	bad := &client{t: t, url: c.url, bearer: "rmp_faux"}
	if code, _ := bad.do("GET", "/api/status", ""); code != 401 {
		t.Fatal("jeton inconnu accepté")
	}
}

func TestCSRAndManualCertificate(t *testing.T) {
	c, a := newTestAPI(t)
	code, body := c.do("POST", "/api/tls/csr", `{"names":["rempart.example.fr","dns.example.fr"]}`)
	if code != 200 {
		t.Fatal(body)
	}
	var out struct{ CSR string }
	json.Unmarshal([]byte(body), &out)
	blk, _ := pem.Decode([]byte(out.CSR))
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil || len(csr.DNSNames) != 2 {
		t.Fatalf("CSR invalide : %v", err)
	}

	// Une AC de test signe la CSR, comme le ferait EJBCA ou Horizon.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "AC test"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: csr.Subject, DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(0, 3, 0), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, ca, csr.PublicKey, caKey)
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))

	reversed := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	if code, _ := c.do("POST", "/api/tls/certificate", jsonString("chain", reversed)); code != 400 {
		t.Fatal("une chaîne dans le désordre doit être refusée")
	}
	if code, body := c.do("POST", "/api/tls/certificate", jsonString("chain", chain)); code != 200 {
		t.Fatal(body)
	}
	if info := a.TLS.Info(); info.Mode != "manual" || info.SelfSigned || info.ChainLength != 2 {
		t.Fatalf("certificat non installé : %+v", info)
	}
	withKey := chain + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	if code, _ := c.do("POST", "/api/tls/certificate", jsonString("chain", withKey)); code != 400 {
		t.Fatal("un PEM contenant une clé privée doit être refusé")
	}
}

func TestRulesBulkExportAndResolvers(t *testing.T) {
	c, a := newTestAPI(t)
	text := "# commentaire\nads.example.com\n0.0.0.0 tracker.example.net\n||pub.example.org^\n@@||ok.example.org^\nn'importe quoi !\n"
	code, body := c.do("POST", "/api/rules/bulk", jsonString("text", text))
	if code != 200 || !strings.Contains(body, `"added":4`) {
		t.Fatalf("import : %d %s", code, body)
	}
	_, exp := c.do("GET", "/api/rules/export?format=adblock", "")
	for _, want := range []string{"||ads.example.com^", "||tracker.example.net^", "@@||ok.example.org^"} {
		if !strings.Contains(exp, want) {
			t.Fatalf("export sans %s : %s", want, exp)
		}
	}
	code, body = c.do("PUT", "/api/resolvers", `{"profile":"entreprise","upstreams":["https://dns.quad9.net/dns-query"],"forwards":[{"domain":"corp.local","servers":["10.0.0.10","10.0.0.11"]}],"bootstrap":[]}`)
	if code != 200 {
		t.Fatal(body)
	}
	if !a.Upstreams.Forwarded("dc01.corp.local.") || a.Upstreams.Forwarded("example.com.") {
		t.Fatal("transfert conditionnel non appliqué")
	}
	if code, _ := c.do("PUT", "/api/resolvers", `{"profile":"perso","upstreams":["dns.google"],"forwards":[],"bootstrap":[]}`); code != 400 {
		t.Fatal("un résolveur en clair désigné par un nom doit être refusé")
	}
}

func jsonString(k, v string) string {
	b, _ := json.Marshal(map[string]string{k: v})
	return string(b)
}
