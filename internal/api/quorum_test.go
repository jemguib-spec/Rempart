// quorum_test.go - parcours HTTP du quorum : cérémonie, rotation, approbations, destruction.
// Exécution : go test ./internal/api/ -run Quorum (Argon2id réel, quelques secondes).
// Rempart ; phrases de passe de test seulement.

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/rempart-dns/rempart/internal/audit"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/state"
)

func TestQuorumHTTP(t *testing.T) {
	data := t.TempDir()
	ks, _, err := keystore.OpenSoftware(filepath.Join(data, "keystore"), "phrase-serveur")
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()
	const pw = "un-mot-de-passe-solide"
	store, _, _ := state.Open(ks, filepath.Join(data, "state.sealed"), state.State{Admin: state.Admin{Username: "admin", PasswordHash: HashPassword(pw)}})
	al, _ := audit.Open(ks, data)
	a := &API{Store: store, Audit: al, KS: ks, DataDir: data, Web: fstest.MapFS{"index.html": {Data: []byte("ok")}},
		ServerPassphrase: func() (string, error) { return "phrase-serveur", nil }}
	srv := httptest.NewServer(a.Handler(time.Hour))
	defer srv.Close()
	var ck *http.Cookie
	do := func(method, path, body string, out any) int {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("X-Rempart", "1")
		if ck != nil {
			req.AddCookie(ck)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		for _, c := range res.Cookies() {
			if c.Name == cookieName {
				ck = c
			}
		}
		if out != nil {
			_ = json.NewDecoder(res.Body).Decode(out)
		}
		return res.StatusCode
	}
	do("POST", "/api/login", `{"username":"admin","password":"`+pw+`"}`, nil)

	team := `[{"name":"Alice","passphrase":"alice-phrase-de-passe"},{"name":"Bruno","passphrase":"bruno-phrase-de-passe"},{"name":"Chloé","passphrase":"chloe-phrase-de-passe"}]`
	if c := do("POST", "/api/quorum/reconfigure", `{"password":"`+pw+`","mode":"auto","threshold":2,"add":`+team+`}`, nil); c != 200 {
		t.Fatalf("cérémonie initiale : %d", c)
	}
	// Rotation : nouvelle génération, l'ancienne est retirée une fois les données réchiffrées.
	var rep rotationReport
	if c := do("POST", "/api/kek/rotate", `{"password":"`+pw+`","rotate":true}`, &rep); c != 200 || rep.Gen != 3 {
		t.Fatalf("rotation : %d %+v", c, rep)
	}
	// La cérémonie a mis en service la génération 2 et détruit la 1 ; la rotation retire la 2.
	if len(rep.Retired) != 1 || rep.Retired[0] != 2 || len(rep.Pending) != 0 {
		t.Fatalf("génération 2 non retirée : %+v", rep)
	}
	// Destruction : refusée sans approbation, acceptée avec 2 dépositaires.
	if c := do("POST", "/api/kek/destroy", `{"password":"`+pw+`","gen":2}`, nil); c != 403 {
		t.Fatalf("destruction sans quorum : %d", c)
	}
	do("POST", "/api/quorum/ops", `{"kind":"destroy","gen":2}`, nil)
	var st struct {
		Op struct{ ID string }
	}
	do("GET", "/api/quorum", "", &st)
	if c := do("POST", "/api/quorum/ops/approve", `{"id":"`+st.Op.ID+`","name":"Alice","passphrase":"fausse-phrase-xx"}`, nil); c != 403 {
		t.Fatalf("fausse phrase : %d", c)
	}
	do("POST", "/api/quorum/ops/approve", `{"id":"`+st.Op.ID+`","name":"Alice","passphrase":"alice-phrase-de-passe"}`, nil)
	if c := do("POST", "/api/kek/destroy", `{"op_id":"`+st.Op.ID+`","password":"`+pw+`","gen":2}`, nil); c != 403 {
		t.Fatalf("destruction avec une seule approbation : %d", c)
	}
	for _, who := range []string{`"Bruno","passphrase":"bruno-phrase-de-passe"`, `"chloé","passphrase":"chloe-phrase-de-passe"`} {
		if c := do("POST", "/api/quorum/ops/approve", `{"id":"`+st.Op.ID+`","name":`+who+`}`, nil); c != 200 {
			t.Fatalf("approbation : %d", c)
		}
	}
	if c := do("POST", "/api/kek/destroy", `{"op_id":"`+st.Op.ID+`","password":"`+pw+`","gen":3}`, nil); c != 403 {
		t.Fatalf("approbation détournée vers une autre génération : %d", c)
	}
	do("POST", "/api/quorum/ops", `{"kind":"destroy","gen":2}`, nil)
	do("GET", "/api/quorum", "", &st)
	for _, who := range []string{`"Bruno","passphrase":"bruno-phrase-de-passe"`, `"Alice","passphrase":"alice-phrase-de-passe"`} {
		do("POST", "/api/quorum/ops/approve", `{"id":"`+st.Op.ID+`","name":`+who+`}`, nil)
	}
	if c := do("POST", "/api/kek/destroy", `{"op_id":"`+st.Op.ID+`","password":"`+pw+`","gen":2}`, nil); c != 200 {
		t.Fatalf("destruction approuvée : %d", c)
	}
	// Les données restent lisibles : l'état se rouvre avec la génération 3.
	if _, _, err := state.Open(ks, filepath.Join(data, "state.sealed"), state.State{}); err != nil {
		t.Fatal("état illisible après destruction de l'ancienne KEK", err)
	}
	raw, _ := os.ReadFile(filepath.Join(data, "audit.jsonl"))
	for _, secret := range []string{"alice-phrase", "bruno-phrase", "chloe-phrase", "phrase-serveur"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("phrase de passe dans l'audit : %s", secret)
		}
	}
	if !strings.Contains(string(raw), "kek.détruite") || !strings.Contains(string(raw), "quorum.approbation-échec") {
		t.Fatal("opérations du quorum absentes de l'audit")
	}

	// Reconfiguration sous quorum : le plan approuvé lie l'exécution.
	var qs struct {
		Status keystore.QuorumStatus
		Op     struct{ ID string }
	}
	do("GET", "/api/quorum", "", &qs)
	ids := map[string]string{}
	for _, c := range qs.Status.Custodians {
		ids[c.Name] = c.ID
	}
	plan := `{"mode":"auto","threshold":2,"keep":["` + ids["Alice"] + `","` + ids["Bruno"] + `"],"add":["Damien"]}`
	do("POST", "/api/quorum/ops", `{"kind":"reconfigure","plan":`+plan+`}`, nil)
	do("GET", "/api/quorum", "", &qs)
	for _, who := range []string{`"Alice","passphrase":"alice-phrase-de-passe"`, `"Chloé","passphrase":"chloe-phrase-de-passe"`} {
		if c := do("POST", "/api/quorum/ops/approve", `{"id":"`+qs.Op.ID+`","name":`+who+`}`, nil); c != 200 {
			t.Fatalf("approbation du plan : %d", c)
		}
	}
	// Un nom piégé (NUL) est refusé dès la demande.
	if c := do("POST", "/api/quorum/ops", `{"kind":"reconfigure","plan":{"mode":"auto","threshold":2,"keep":["`+ids["Alice"]+`"],"add":["Damien\u0000Eve"]}}`, nil); c != 400 {
		t.Fatalf("nom avec NUL accepté : %d", c)
	}
	do("POST", "/api/quorum/ops", `{"kind":"reconfigure","plan":`+plan+`}`, nil)
	do("GET", "/api/quorum", "", &qs)
	for _, who := range []string{`"Alice","passphrase":"alice-phrase-de-passe"`, `"Chloé","passphrase":"chloe-phrase-de-passe"`} {
		do("POST", "/api/quorum/ops/approve", `{"id":"`+qs.Op.ID+`","name":`+who+`}`, nil)
	}
	keepA := `{"id":"` + ids["Alice"] + `"}`
	// L'administrateur tente d'ajouter son propre dépositaire : refusé.
	bad := `{"op_id":"` + qs.Op.ID + `","password":"` + pw + `","mode":"auto","threshold":2,"keep":[` + keepA + `,{"id":"` + ids["Bruno"] + `","passphrase":"bruno-phrase-de-passe"}],"add":[{"name":"Damien","passphrase":"damien-phrase-xx"},{"name":"Eve","passphrase":"eve-phrase-admin"}]}`
	if c := do("POST", "/api/quorum/reconfigure", bad, nil); c != 400 && c != 403 {
		t.Fatalf("plan modifié après approbation accepté : %d", c)
	}
	// Bruno (conservé, non approbateur) avec une phrase choisie par l'administrateur : refusé.
	forged := `{"op_id":"` + qs.Op.ID + `","password":"` + pw + `","mode":"auto","threshold":2,"keep":[` + keepA + `,{"id":"` + ids["Bruno"] + `","passphrase":"phrase-de-l-admin"}],"add":[{"name":"Damien","passphrase":"damien-phrase-xx"}]}`
	if c := do("POST", "/api/quorum/reconfigure", forged, nil); c != 400 {
		t.Fatalf("phrase substituée à un dépositaire conservé : %d", c)
	}
	// L'essai refusé a consommé la demande : nouvelle demande, nouvelles approbations.
	do("POST", "/api/quorum/ops", `{"kind":"reconfigure","plan":`+plan+`}`, nil)
	do("GET", "/api/quorum", "", &qs)
	for _, who := range []string{`"Alice","passphrase":"alice-phrase-de-passe"`, `"Chloé","passphrase":"chloe-phrase-de-passe"`} {
		do("POST", "/api/quorum/ops/approve", `{"id":"`+qs.Op.ID+`","name":`+who+`}`, nil)
	}
	good := `{"op_id":"` + qs.Op.ID + `","password":"` + pw + `","mode":"auto","threshold":2,"keep":[` + keepA + `,{"id":"` + ids["Bruno"] + `","passphrase":"bruno-phrase-de-passe"}],"add":[{"name":"Damien","passphrase":"damien-phrase-xx"}]}`
	if c := do("POST", "/api/quorum/reconfigure", good, &qs); c != 200 || len(qs.Status.Custodians) != 3 {
		t.Fatalf("reconfiguration approuvée : %d %+v", c, qs.Status)
	}
	// Alice garde sa phrase ; Chloé, retirée, ne compte plus.
	sw := ks
	if _, _, err := sw.OpenShare("Alice", "alice-phrase-de-passe"); err != nil {
		t.Fatal("phrase d'un dépositaire conservé perdue", err)
	}
	if _, _, err := sw.OpenShare("Chloé", "chloe-phrase-de-passe"); err == nil {
		t.Fatal("dépositaire retiré encore accepté")
	}

	// Passage en « terminal seulement » : l'interface ne reçoit plus d'approbation.
	do("GET", "/api/quorum", "", &qs)
	ids = map[string]string{}
	for _, c := range qs.Status.Custodians {
		ids[c.Name] = c.ID
	}
	plan2 := `{"mode":"auto","threshold":2,"keep":["` + ids["Alice"] + `","` + ids["Bruno"] + `","` + ids["Damien"] + `"],"add":[],"terminal_only":true}`
	do("POST", "/api/quorum/ops", `{"kind":"reconfigure","plan":`+plan2+`}`, nil)
	do("GET", "/api/quorum", "", &qs)
	if _, err := a.TerminalApprove("autre-op", "Alice", "alice-phrase-de-passe"); err == nil {
		t.Fatal("approbation au terminal d'une autre opération que celle affichée")
	}
	if _, err := a.TerminalApprove(qs.Op.ID, "Alice", "alice-phrase-de-passe"); err != nil {
		t.Fatal("approbation au terminal", err)
	}
	if _, err := a.TerminalApprove(qs.Op.ID, "Damien", "damien-phrase-xx"); err != nil {
		t.Fatal(err)
	}
	keep3 := `[{"id":"` + ids["Alice"] + `"},{"id":"` + ids["Bruno"] + `","passphrase":"bruno-phrase-de-passe"},{"id":"` + ids["Damien"] + `"}]`
	if c := do("POST", "/api/quorum/reconfigure", `{"op_id":"`+qs.Op.ID+`","password":"`+pw+`","mode":"auto","threshold":2,"terminal_only":true,"keep":`+keep3+`,"add":[]}`, &qs); c != 200 || !qs.Status.TerminalOnly {
		t.Fatalf("passage en terminal seulement : %d", c)
	}
	do("POST", "/api/quorum/ops", `{"kind":"policy","days":90}`, nil)
	do("GET", "/api/quorum", "", &qs)
	if c := do("POST", "/api/quorum/ops/approve", `{"id":"`+qs.Op.ID+`","name":"Alice","passphrase":"alice-phrase-de-passe"}`, nil); c != 403 {
		t.Fatalf("approbation par l'interface acceptée en mode terminal : %d", c)
	}

	// En mode terminal, une phrase passée par la session admin ne compte pas
	// tant que le dépositaire ne l'a pas changée lui-même.
	if _, err := a.TerminalApprove(qs.Op.ID, "Alice", "alice-phrase-de-passe"); err == nil || !strings.Contains(err.Error(), "passwd") {
		t.Fatalf("phrase non fixée au terminal acceptée : %v", err)
	}
	if err := a.TerminalPasswd("Alice", "alice-phrase-de-passe", "alice-phrase-a-elle"); err != nil {
		t.Fatal(err)
	}
	if err := a.TerminalPasswd("Damien", "damien-phrase-xx", "damien-phrase-a-lui"); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{"Alice", "alice-phrase-a-elle"}, {"damien", "damien-phrase-a-lui"}} {
		if _, err := a.TerminalApprove(qs.Op.ID, c[0], c[1]); err != nil {
			t.Fatal("approbation après passwd", err)
		}
	}
	if c := do("POST", "/api/kek/policy", `{"op_id":"`+qs.Op.ID+`","password":"`+pw+`","days":90}`, nil); c != 200 {
		t.Fatalf("politique approuvée au terminal : %d", c)
	}
}
