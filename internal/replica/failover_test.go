package replica

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

// instance : état, client de réplication et mini-API de synchronisation.
type instance struct {
	name  string
	store *state.Store
	cli   *Client
	srv   *httptest.Server
	down  atomic.Bool
	ctx   context.Context
	stop  context.CancelFunc
}

func newInstance(t *testing.T, name string, st state.State) *instance {
	store, _, err := state.Open(testutil.Keystore(t), filepath.Join(t.TempDir(), "s"), st)
	if err != nil {
		t.Fatal(err)
	}
	in := &instance{name: name, store: store}
	in.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if in.down.Load() {
			http.Error(w, "panne", http.StatusServiceUnavailable)
			return
		}
		if r.Header.Get("Authorization") != "Bearer rmp_sync" {
			http.Error(w, "jeton", http.StatusUnauthorized)
			return
		}
		cur := in.store.Get()
		switch r.URL.Path {
		case "/api/sync/role":
			_ = json.NewEncoder(w).Encode(RoleInfo{Role: cur.Replication.Role, Epoch: cur.Replication.Epoch, Acting: cur.Replication.Acting})
		case "/api/sync":
			if cur.Replication.Role != "primary" {
				http.Error(w, "pas principale", http.StatusConflict)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"payload": Export(cur), "replication_key": cur.Replication.Key})
		}
	}))
	t.Cleanup(in.srv.Close)
	in.cli = &Client{Store: store, Log: testutil.Logger(), Event: func(a, d string) { t.Logf("%s : %s — %s", name, a, d) }}
	in.start()
	store.Subscribe(func(st state.State) { in.cli.Reconcile(in.ctx, st) })
	t.Cleanup(func() { in.stop() })
	return in
}

func (in *instance) start() {
	in.ctx, in.stop = context.WithCancel(context.Background())
	in.cli.mu.Lock()
	in.cli.conf = "" // relance la boucle
	in.cli.mu.Unlock()
	in.cli.Reconcile(in.ctx, in.store.Get())
}

func caOf(s *httptest.Server) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
}

func waitUntil(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("délai dépassé : %s", what)
}

func TestFailoverAndFailback(t *testing.T) {
	syncInterval, failoverUnit = 20*time.Millisecond, 15*time.Millisecond
	defer func() { syncInterval, failoverUnit = 30*time.Second, time.Minute }()

	key := state.TSIGKey{Name: "repl.", Algorithm: "hmac-sha256", Secret: "c2VjcmV0LWRlLXJlcGxpY2F0aW9uLTMyLW9jdGV0cw=="}
	a := newInstance(t, "A", state.State{TSIGKeys: []state.TSIGKey{key}, Rules: []state.Rule{{Domain: "a.example"}}})
	b := newInstance(t, "B", state.State{})
	setRepl := func(in *instance, r state.Replication) {
		_ = in.store.Update(func(s *state.State) error { s.Replication = r; return nil })
	}
	setRepl(a, state.Replication{Role: "primary", Replicas: []string{"127.0.0.1"}, Key: "repl.", Failover: true, FailoverMinutes: 2, Preferred: true,
		PrimaryURL: b.srv.URL, PrimaryDNS: "127.0.0.1", Token: "rmp_sync", CABundle: caOf(b.srv)})
	setRepl(b, state.Replication{Role: "replica", Failover: true, FailoverMinutes: 2,
		PrimaryURL: a.srv.URL, PrimaryDNS: "127.0.0.1", Token: "rmp_sync", CABundle: caOf(a.srv)})

	// 1. Réplication ordinaire.
	waitUntil(t, "B recopie A", func() bool { return len(b.store.Get().Rules) == 1 })
	if b.store.Get().Replication.Key != "repl." {
		t.Fatal("clé de réplication non retenue pour la bascule")
	}

	// 2. Panne de A : B devient principale par intérim.
	a.down.Store(true)
	a.stop()
	waitUntil(t, "B principale", func() bool { return b.store.Get().Replication.Role == "primary" })
	rb := b.store.Get().Replication
	if !rb.Acting || rb.Epoch != 1 || len(rb.Replicas) == 0 {
		t.Fatalf("B après la bascule : %+v", rb)
	}
	for _, k := range b.store.Get().TSIGKeys {
		if k.Name == "repl." && k.Managed {
			t.Fatal("clé de réplication restée « reçue » sur la nouvelle principale")
		}
	}
	// Modification pendant la panne.
	_ = b.store.Update(func(s *state.State) error { s.Rules = append(s.Rules, state.Rule{Domain: "b.example"}); return nil })

	// 3. Retour de A : elle cède, recopie, puis reprend le rôle principal.
	a.down.Store(false)
	a.start()
	waitUntil(t, "A reprend le rôle principal", func() bool {
		ra := a.store.Get().Replication
		return ra.Role == "primary" && ra.Epoch == 2 && !ra.Acting
	})
	if n := len(a.store.Get().Rules); n != 2 {
		t.Fatalf("modification faite pendant la panne perdue : %d règles", n)
	}
	waitUntil(t, "B redevient réplique", func() bool {
		rb := b.store.Get().Replication
		return rb.Role == "replica" && rb.Epoch == 2
	})
}

func TestShouldYield(t *testing.T) {
	me := state.Replication{Role: "primary", Epoch: 3, Acting: true}
	for _, c := range []struct {
		peer RoleInfo
		want bool
	}{
		{RoleInfo{Role: "replica", Epoch: 9}, false},
		{RoleInfo{Role: "primary", Epoch: 4}, true},
		{RoleInfo{Role: "primary", Epoch: 2}, false},
		{RoleInfo{Role: "primary", Epoch: 3, Acting: false}, true},
		{RoleInfo{Role: "primary", Epoch: 3, Acting: true}, false},
	} {
		if got := shouldYield(me, c.peer); got != c.want {
			t.Errorf("%+v : %v", c.peer, got)
		}
	}
}
