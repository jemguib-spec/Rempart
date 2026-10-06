package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rempart-dns/rempart/internal/testutil"
)

func TestOpenCreatesSealedState(t *testing.T) {
	ks := testutil.Keystore(t)
	p := filepath.Join(t.TempDir(), "state.json")
	s, created, err := Open(ks, p, State{Rules: []Rule{{Domain: "pub.example"}}})
	if err != nil || !created {
		t.Fatalf("%v %v", created, err)
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), "pub.example") {
		t.Fatal("état écrit en clair")
	}
	s2, created, err := Open(ks, p, State{})
	if err != nil || created {
		t.Fatalf("réouverture : %v %v", created, err)
	}
	if got := s2.Get().Rules; len(got) != 1 || got[0].Domain != "pub.example" {
		t.Fatalf("%+v", got)
	}
	_ = s
}

func TestOpenWrongKeystore(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	if _, _, err := Open(testutil.Keystore(t), p, State{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(testutil.Keystore(t), p, State{}); err == nil {
		t.Fatal("état ouvert par un autre keystore")
	}
}

func TestNormalizeNoNullSlices(t *testing.T) {
	st := State{Groups: []Group{{Schedules: []Schedule{{}}}}, Zones: []Zone{{}}, Identity: Identity{}}
	normalize(&st)
	raw, _ := json.Marshal(st)
	if strings.Contains(string(raw), "null") {
		t.Fatalf("null dans l'état normalisé : %s", raw)
	}
}

func TestGetIsDeepCopy(t *testing.T) {
	s, _, _ := Open(testutil.Keystore(t), filepath.Join(t.TempDir(), "s"), State{Groups: []Group{{Name: "enfants", Clients: []string{"10.0.0.2"}}}})
	g := s.Get()
	g.Groups[0].Clients[0] = "modifié"
	g.Groups[0].Name = "x"
	if s.Get().Groups[0].Clients[0] != "10.0.0.2" || s.Get().Groups[0].Name != "enfants" {
		t.Fatal("Get partage la mémoire de l'état")
	}
}

func TestUpdatePersistsAndNotifies(t *testing.T) {
	ks := testutil.Keystore(t)
	p := filepath.Join(t.TempDir(), "s")
	s, _, _ := Open(ks, p, State{})
	var mu sync.Mutex
	var seen []int
	s.Subscribe(func(st State) { mu.Lock(); seen = append(seen, len(st.Rules)); mu.Unlock() })
	for i := 0; i < 3; i++ {
		if err := s.Update(func(st *State) error { st.Rules = append(st.Rules, Rule{Domain: "x.example"}); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 3 || seen[2] != 3 {
		t.Fatalf("notifications %v", seen)
	}
	s2, _, _ := Open(ks, p, State{})
	if len(s2.Get().Rules) != 3 {
		t.Fatal("mise à jour non persistée")
	}
}

func TestUpdateErrorRollsBack(t *testing.T) {
	s, _, _ := Open(testutil.Keystore(t), filepath.Join(t.TempDir(), "s"), State{})
	called := false
	s.Subscribe(func(State) { called = true })
	err := s.Update(func(st *State) error {
		st.Rules = append(st.Rules, Rule{Domain: "x"})
		return errors.New("refus")
	})
	if err == nil || len(s.Get().Rules) != 0 || called {
		t.Fatal("une mise à jour refusée a laissé une trace")
	}
}

func TestUpdateSaveFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "s")
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	s, _, err := Open(testutil.Keystore(t), p, State{})
	if err != nil {
		t.Fatal(err)
	}
	_ = os.RemoveAll(filepath.Dir(p)) // l'écriture va échouer
	if err := s.Update(func(st *State) error { st.Rules = []Rule{{Domain: "x"}}; return nil }); err == nil {
		t.Fatal("échec d'écriture non signalé")
	}
	if len(s.Get().Rules) != 0 {
		t.Fatal("état en mémoire différent du disque après un échec d'écriture")
	}
}

func TestConcurrentUpdates(t *testing.T) {
	s, _, _ := Open(testutil.Keystore(t), filepath.Join(t.TempDir(), "s"), State{})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Update(func(st *State) error { st.Rules = append(st.Rules, Rule{Domain: "c"}); return nil })
			_ = s.Get()
		}()
	}
	wg.Wait()
	if n := len(s.Get().Rules); n != 20 {
		t.Fatalf("%d mises à jour sur 20 (perte d'écriture)", n)
	}
}
