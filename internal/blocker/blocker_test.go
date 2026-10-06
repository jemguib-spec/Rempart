package blocker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

func newEngine(t *testing.T, st state.State) (*Engine, *state.Store, string) {
	t.Helper()
	dir := t.TempDir()
	store, _, err := state.Open(testutil.Keystore(t), filepath.Join(dir, "state"), st)
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(store, dir, nil, testutil.Logger())
	if err != nil {
		t.Fatal(err)
	}
	return e, store, dir
}

func serve(t *testing.T, body string, status int) (*httptest.Server, *atomic.Int32) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if r.Header.Get("User-Agent") != "Rempart-DNS" {
			t.Errorf("User-Agent %q", r.Header.Get("User-Agent"))
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func TestRefreshAndMatch(t *testing.T) {
	srv, _ := serve(t, "0.0.0.0 pub.example\n||track.example^\n", 200)
	e, store, _ := newEngine(t, state.State{
		Lists: []state.List{{ID: "l1", Name: "Pub", URL: srv.URL + "/l.txt", Enabled: true}},
		Rules: []state.Rule{{Domain: "perso.example"}, {Domain: "ok.pub.example", Allow: true}},
	})
	if err := e.Refresh(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	m := e.Matcher()
	for name, blocked := range map[string]bool{"pub.example": true, "a.track.example": true, "perso.example": true, "ok.pub.example": false, "propre.example": false} {
		if got := m.Match(name).Blocked; got != blocked {
			t.Errorf("%s : bloqué=%v", name, got)
		}
	}
	if e.Count("l1") != 2 {
		t.Fatalf("compte %d", e.Count("l1"))
	}
	l := store.Get().Lists[0]
	if l.LastError != "" || l.LastUpdate.IsZero() {
		t.Fatalf("%+v", l)
	}
}

func TestRefreshKeepsPreviousCopyOnFailure(t *testing.T) {
	good, _ := serve(t, "pub.example\n", 200)
	e, store, _ := newEngine(t, state.State{Lists: []state.List{{ID: "l1", URL: good.URL, Enabled: true}}})
	_ = e.Refresh(context.Background(), "")
	for _, c := range []struct {
		body   string
		status int
	}{{"", 500}, {"<html>pas une liste</html>", 200}, {"", 200}} {
		bad, _ := serve(t, c.body, c.status)
		_ = store.Update(func(s *state.State) error { s.Lists[0].URL = bad.URL; return nil })
		_ = e.Refresh(context.Background(), "")
		if store.Get().Lists[0].LastError == "" {
			t.Fatalf("erreur non signalée pour %d %q", c.status, c.body)
		}
		if !e.Matcher().Match("pub.example").Blocked {
			t.Fatal("ancienne copie perdue après un échec")
		}
	}
}

func TestSHA256Pin(t *testing.T) {
	body := "pub.example\n"
	srv, _ := serve(t, body, 200)
	sum := sha256.Sum256([]byte(body))
	e, store, _ := newEngine(t, state.State{Lists: []state.List{
		{ID: "ok", URL: srv.URL, Enabled: true, SHA256: strings.ToUpper(hex.EncodeToString(sum[:]))},
		{ID: "ko", URL: srv.URL + "/x", Enabled: true, SHA256: strings.Repeat("0", 64)},
	}})
	_ = e.Refresh(context.Background(), "")
	ls := store.Get().Lists
	if ls[0].LastError != "" || !strings.Contains(ls[1].LastError, "SHA-256") {
		t.Fatalf("%q / %q", ls[0].LastError, ls[1].LastError)
	}
}

func TestOnlyUsedListsDownloaded(t *testing.T) {
	srv, n := serve(t, "pub.example\n", 200)
	e, _, _ := newEngine(t, state.State{
		Lists: []state.List{
			{ID: "off", URL: srv.URL, Enabled: false},
			{ID: "grp", URL: srv.URL, Enabled: false},
		},
		Groups: []state.Group{{Name: "g", Lists: []string{"grp"}}},
	})
	_ = e.Refresh(context.Background(), "")
	if n.Load() != 1 {
		t.Fatalf("%d téléchargements, 1 attendu (liste d'un groupe seulement)", n.Load())
	}
	_ = e.Refresh(context.Background(), "off")
	if n.Load() != 1 {
		t.Fatal("liste inutilisée téléchargée")
	}
}

func TestGroupSets(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	c := filepath.Join(dir, "c.txt")
	_ = os.WriteFile(a, []byte("a.example\n"), 0o600)
	_ = os.WriteFile(c, []byte("casino.example\n"), 0o600)
	e, _, _ := newEngine(t, state.State{
		Lists: []state.List{{ID: "a", URL: a, Enabled: true}, {ID: "cat-jeux", URL: c}},
		Rules: []state.Rule{{Domain: "perso.example"}},
		Groups: []state.Group{
			{Name: "enfants", InheritLists: true, Lists: []string{"cat-jeux", "inconnue"}},
			{Name: "invités", Lists: []string{"a"}, InheritRules: true},
		},
	})
	e.Rebuild()
	st := e.store.Get()
	ids, rules, cats := GroupLists(st, st.Groups[0])
	if len(ids) != 1 || ids[0] != "a" || rules || len(cats) != 1 || cats[0] != "cat-jeux" {
		t.Fatalf("enfants : %v %v %v", ids, rules, cats)
	}
	if m := e.MatcherFor(SetKey(cats, false)); m == nil || !m.Match("casino.example").Blocked {
		t.Fatal("catégorie non compilée")
	}
	if m := e.MatcherFor(SetKey(ids, false)); m == nil || m.Match("perso.example").Blocked || !m.Match("a.example").Blocked {
		t.Fatal("combinaison sans « Ma liste » incorrecte")
	}
	if m := e.MatcherFor(SetKey([]string{"a"}, true)); m == nil || !m.Match("perso.example").Blocked {
		t.Fatal("combinaison avec « Ma liste » absente")
	}
}

func TestSetKey(t *testing.T) {
	if SetKey([]string{"b", "a", "a"}, true) != SetKey([]string{"a", "b"}, true) {
		t.Fatal("ordre ou doublons changent la clé")
	}
	if SetKey([]string{"a"}, true) == SetKey([]string{"a"}, false) {
		t.Fatal("« Ma liste » ignorée")
	}
}

func TestCachePathStaysInDir(t *testing.T) {
	e, _, dir := newEngine(t, state.State{})
	for _, id := range []string{"../../keystore/master", "/etc/passwd", "a/b", "..", "", strings.Repeat("x", 300), "é"} {
		p := e.cachePath(id)
		if filepath.Dir(p) != filepath.Join(dir, "lists") {
			t.Fatalf("%q → %s hors du dossier des listes", id, p)
		}
	}
	if e.cachePath("abc-12_x") != filepath.Join(dir, "lists", "abc-12_x.txt") {
		t.Fatal("identifiant ordinaire modifié (copies existantes perdues)")
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	e, _, _ := newEngine(t, state.State{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx, time.Hour); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run ne s'arrête pas")
	}
}
