package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rempart-dns/rempart/internal/authority"
	"github.com/rempart-dns/rempart/internal/backup"
	"github.com/rempart-dns/rempart/internal/blocker"
	"github.com/rempart-dns/rempart/internal/cache"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/querylog"
	"github.com/rempart-dns/rempart/internal/replica"
	"github.com/rempart-dns/rempart/internal/server"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
	"github.com/rempart-dns/rempart/internal/tsig"
	"github.com/rempart-dns/rempart/internal/upstream"
	"github.com/rempart-dns/rempart/internal/zones"
)

func opsEnv(t *testing.T) *idEnv {
	e := newIDEnv(t)
	dir := t.TempDir()
	eng, _ := blocker.New(e.a.Store, dir, nil, testutil.Logger())
	ql, _ := querylog.New(e.a.KS, dir, testutil.Logger())
	t.Cleanup(ql.Flush)
	zm := zones.NewManager(e.a.KS, testutil.Logger())
	prov := tsig.NewProvider()
	e.a.Store.Subscribe(func(st state.State) { prov.Set(st.TSIGKeys) })
	e.a.Blocker, e.a.Cache, e.a.QLog, e.a.Zones = eng, cache.New(10, 0, 0), ql, zm
	e.a.Server = &server.Server{}
	e.a.Upstreams = &upstream.Router{}
	if err := e.a.Upstreams.Set([]string{"udp://192.0.2.53:53"}, nil, upstream.Options{}); err != nil {
		t.Fatal(err)
	}
	e.a.Authority = &authority.Authority{Store: e.a.Store, Zones: zm, Prov: prov, KS: e.a.KS, DataDir: dir, Log: testutil.Logger(), Record: func(string, string, string) {}}
	e.a.Started, e.a.Version = time.Now(), "1.0.0"
	return e
}

func (e *idEnv) token(c *http.Client, scopes ...string) string {
	_, out := e.do(c, "POST", "/api/tokens", map[string]any{"name": strings.Join(scopes, "+"), "scopes": scopes})
	tok, _ := out["token"].(string)
	if tok == "" {
		e.t.Fatalf("jeton : %v", out)
	}
	return tok
}

func (e *idEnv) bearer(tok, method, path string) (*http.Response, []byte) {
	req, _ := http.NewRequest(method, e.srv.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, b
}

func TestTSIGSyslogScopes(t *testing.T) {
	e := opsEnv(t)
	adm := e.localAdmin()
	r, out := e.do(adm, "POST", "/api/tsig", map[string]any{"name": "xfr.maison.lan", "algorithm": "hmac-sha1"})
	if r.StatusCode != 400 {
		t.Fatal("HMAC-SHA1 accepté")
	}
	r, out = e.do(adm, "POST", "/api/tsig", map[string]any{"name": "xfr.maison.lan", "algorithm": "hmac-sha256"})
	secret, _ := out["secret"].(string)
	if r.StatusCode != 200 || len(secret) < 40 || !strings.Contains(out["bind"].(string), secret) {
		t.Fatalf("création de clé : %v", out)
	}
	res, _ := e.do(adm, "GET", "/api/tsig", nil)
	raw, _ := json.Marshal(e.a.Store.Get().TSIGKeys)
	if res.StatusCode != 200 || !strings.Contains(string(raw), secret) {
		t.Fatal("clé non conservée")
	}
	req, _ := http.NewRequest("GET", e.srv.URL+"/api/tsig", nil)
	req.Header.Set("X-Rempart", "1")
	lst, _ := adm.Do(req)
	body, _ := io.ReadAll(lst.Body)
	if strings.Contains(string(body), secret) {
		t.Fatal("le secret TSIG ne doit jamais être relu par l'API")
	}
	if r, _ := e.do(adm, "PUT", "/api/syslog", map[string]any{"enabled": true, "network": "tls", "address": "siem"}); r.StatusCode != 400 {
		t.Fatal("adresse syslog invalide acceptée")
	}

	// Portées : un jeton admin n'ouvre ni la sauvegarde ni la synchronisation ;
	// un jeton « backup » ne lit pas la configuration.
	admTok := e.token(adm, "admin")
	if r, _ := e.bearer(admTok, "GET", "/api/backup"); r.StatusCode != 401 {
		t.Fatalf("sauvegarde avec un jeton admin : %d", r.StatusCode)
	}
	bk := e.token(adm, "backup")
	if r, _ := e.bearer(bk, "GET", "/api/settings"); r.StatusCode != 401 {
		t.Fatalf("jeton de sauvegarde utilisé pour lire la configuration : %d", r.StatusCode)
	}
	mt := e.token(adm, "metrics")
	r2, body2 := e.bearer(mt, "GET", "/metrics")
	if r2.StatusCode != 200 || !strings.Contains(string(body2), `rempart_build_info{version="1.0.0"`) || !strings.Contains(string(body2), "rempart_audit_chain_ok 1") {
		t.Fatalf("métriques : %d %s", r2.StatusCode, body2)
	}
	if strings.Contains(string(body2), "127.0.0.1") {
		t.Fatal("une adresse de client apparaît dans les métriques")
	}

	// Sauvegarde : archive vérifiable.
	_ = e.a.Store.Update(func(s *state.State) error { return nil })
	e.a.DataDir = filepath.Dir(e.a.KS.(*keystore.Software).Dir())
	r3, arch := e.bearer(bk, "GET", "/api/backup")
	if r3.StatusCode != 200 {
		t.Fatalf("sauvegarde : %d %s", r3.StatusCode, arch)
	}
	m, err := backup.Extract(bytes.NewReader(arch), t.TempDir())
	if err != nil || m.Backend != "software" || len(m.Files) == 0 {
		t.Fatalf("archive : %v %+v", err, m)
	}
}

func TestReplicationExport(t *testing.T) {
	e := opsEnv(t)
	adm := e.localAdmin()
	e.do(adm, "POST", "/api/tsig", map[string]any{"name": "repl.maison.lan"})
	e.do(adm, "POST", "/api/rules", map[string]any{"domain": "ads.example"})
	if r, out := e.do(adm, "PUT", "/api/replication", map[string]any{"role": "primary", "replicas": []string{"127.0.0.1"}, "key": "repl.maison.lan"}); r.StatusCode != 200 {
		t.Fatal(out)
	}
	tok := e.token(adm, "sync")
	r, body := e.bearer(tok, "GET", "/api/sync")
	if r.StatusCode != 200 {
		t.Fatalf("export : %d %s", r.StatusCode, body)
	}
	var out struct {
		Payload replica.Payload `json:"payload"`
		Key     string          `json:"replication_key"`
	}
	_ = json.Unmarshal(body, &out)
	if len(out.Payload.Rules) != 1 || len(out.Payload.Keys) != 1 || out.Key != "repl.maison.lan." {
		t.Fatalf("charge : %+v", out)
	}
	if strings.Contains(string(body), "password_hash") || strings.Contains(string(body), "api_tokens") {
		t.Fatal("l'export ne doit contenir ni compte ni jetons d'API")
	}
	// Côté réplique : configuration appliquée, zones en secondaires, et
	// modification locale refusée.
	rep := newIDEnv(t)
	_ = rep.a.Store.Update(func(s *state.State) error {
		s.Replication = state.Replication{Role: "replica", PrimaryURL: "https://p:8080", PrimaryDNS: "192.0.2.1"}
		out.Payload.Zones = []string{"maison.lan."}
		replica.Apply(s, out.Payload, out.Key)
		return nil
	})
	st := rep.a.Store.Get()
	if len(st.Rules) != 1 || len(st.Secondaries) != 1 || !st.Secondaries[0].Managed || !st.TSIGKeys[0].Managed {
		t.Fatalf("réplique : %+v %+v", st.Secondaries, st.TSIGKeys)
	}
	radm := rep.localAdmin()
	if r, _ := rep.do(radm, "POST", "/api/rules", map[string]any{"domain": "x.example"}); r.StatusCode != 409 {
		t.Fatalf("modification locale sur une réplique : %d", r.StatusCode)
	}
}
