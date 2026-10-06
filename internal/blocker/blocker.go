// Package blocker keeps the filter lists up to date and exposes the current
// compiled matcher.
package blocker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rempart-dns/rempart/internal/filter"
	"github.com/rempart-dns/rempart/internal/state"
)

const maxListSize = 64 << 20

type Engine struct {
	store   *state.Store
	dir     string
	client  *http.Client
	log     *slog.Logger
	matcher atomic.Pointer[filter.Matcher] // politique générale
	// sets : un matcher par combinaison de listes utilisée par un groupe,
	// partagé entre les groupes qui ont la même combinaison.
	sets    atomic.Pointer[map[string]*filter.Matcher]
	buildMu sync.Mutex
	counts  sync.Map // list id -> int
}

func New(store *state.Store, dataDir string, client *http.Client, log *slog.Logger) (*Engine, error) {
	dir := filepath.Join(dataDir, "lists")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}
	e := &Engine{store: store, dir: dir, client: client, log: log}
	e.matcher.Store(filter.NewBuilder().Build())
	e.sets.Store(&map[string]*filter.Matcher{})
	store.Subscribe(func(state.State) { go e.Rebuild() })
	return e, nil
}

// Matcher returns the current compiled rules of the general policy.
func (e *Engine) Matcher() *filter.Matcher { return e.matcher.Load() }

// MatcherFor renvoie le matcher d'une combinaison de listes (clé SetKey), ou
// nil si elle n'a pas encore été compilée.
func (e *Engine) MatcherFor(key string) *filter.Matcher { return (*e.sets.Load())[key] }

// SetKey identifie une combinaison de listes et la présence de « Ma liste ».
func SetKey(lists []string, rules bool) string {
	ids := slices.Clone(lists)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	k := "r0|"
	if rules {
		k = "r1|"
	}
	return k + strings.Join(ids, ",")
}

// CategoryPrefix : listes créées par le choix d'une catégorie (contrôle
// parental). Pour un groupe, elles s'appliquent même filtrage en pause.
const CategoryPrefix = "cat-"

// GroupLists renvoie les listes de filtrage d'un groupe, s'il reprend « Ma
// liste » générale, et ses listes de catégories. Seules les listes
// existantes sont retenues.
func GroupLists(st state.State, g state.Group) (lists []string, rules bool, cats []string) {
	known := map[string]bool{}
	for _, l := range st.Lists {
		known[l.ID] = true
		if g.InheritLists && l.Enabled {
			lists = append(lists, l.ID)
		}
	}
	for _, id := range g.Lists {
		switch {
		case !known[id]:
		case strings.HasPrefix(id, CategoryPrefix):
			cats = append(cats, id)
		default:
			lists = append(lists, id)
		}
	}
	return lists, g.InheritRules, cats
}

// used : listes à télécharger, actives globalement ou utilisées par un groupe.
func used(st state.State) map[string]bool {
	u := map[string]bool{}
	for _, l := range st.Lists {
		if l.Enabled {
			u[l.ID] = true
		}
	}
	for _, g := range st.Groups {
		for _, id := range g.Lists {
			u[id] = true
		}
	}
	return u
}

// cachePath : copie téléchargée d'une liste. L'identifiant peut venir d'une
// instance principale (réplication) : il n'est jamais utilisé tel quel s'il
// pourrait sortir du dossier des listes.
func (e *Engine) cachePath(id string) string { return filepath.Join(e.dir, safeID(id)+".txt") }

func safeID(id string) string {
	ok := id != "" && len(id) <= 64
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			ok = false
			break
		}
	}
	if ok {
		return id
	}
	sum := sha256.Sum256([]byte(id))
	return "id-" + hex.EncodeToString(sum[:16])
}

// Rebuild compiles lists already on disk plus custom rules, for the general
// policy and for each distinct list combination used by a group.
func (e *Engine) Rebuild() {
	e.buildMu.Lock()
	defer e.buildMu.Unlock()
	start := time.Now()
	st := e.store.Get()
	var general []string
	for _, l := range st.Lists {
		if l.Enabled {
			general = append(general, l.ID)
		}
	}
	m := e.build(st, general, true)
	sets := map[string]*filter.Matcher{SetKey(general, true): m}
	for _, g := range st.Groups {
		ids, rules, cats := GroupLists(st, g)
		if k := SetKey(ids, rules); sets[k] == nil {
			sets[k] = e.build(st, ids, rules)
		}
		if k := SetKey(cats, false); len(cats) > 0 && sets[k] == nil {
			sets[k] = e.build(st, cats, false)
		}
	}
	e.matcher.Store(m)
	e.sets.Store(&sets)
	bl, al := m.Len()
	e.log.Info("règles de filtrage compilées", "blocage", bl, "exceptions", al, "combinaisons", len(sets), "durée", time.Since(start).Round(time.Millisecond))
}

func (e *Engine) build(st state.State, ids []string, rules bool) *filter.Matcher {
	b := filter.NewBuilder()
	for _, l := range st.Lists {
		if !slices.Contains(ids, l.ID) {
			continue
		}
		path := l.URL
		if isRemote(l.URL) {
			path = e.cachePath(l.ID)
		}
		f, err := os.Open(path)
		if err != nil {
			continue // not downloaded yet
		}
		src := b.AddSource(filter.Source{ID: l.ID, Name: l.Name})
		ps, _ := filter.Parse(f, b, src, l.Allow)
		f.Close()
		e.counts.Store(l.ID, ps.Block+ps.Allow)
	}
	if rules {
		custom := b.AddSource(filter.Source{ID: "custom", Name: "Règles personnalisées"})
		for _, r := range st.Rules {
			if r.Allow {
				b.Allow(r.Domain, custom)
			} else {
				b.Block(r.Domain, custom)
			}
		}
	}
	return b.Build()
}

// Count returns the number of rules loaded from a list.
func (e *Engine) Count(id string) int {
	if v, ok := e.counts.Load(id); ok {
		return v.(int)
	}
	return 0
}

func isRemote(u string) bool {
	return strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")
}

// Refresh downloads every enabled remote list (or only the given id).
func (e *Engine) Refresh(ctx context.Context, onlyID string) error {
	st := e.store.Get()
	type res struct {
		id    string
		count int
		err   error
	}
	var results []res
	need := used(st)
	for _, l := range st.Lists {
		if (onlyID != "" && l.ID != onlyID) || !need[l.ID] {
			continue
		}
		if !isRemote(l.URL) {
			results = append(results, res{id: l.ID})
			continue
		}
		n, err := e.download(ctx, l)
		if err != nil {
			e.log.Warn("échec de mise à jour de liste", "liste", l.Name, "err", err)
		}
		results = append(results, res{l.ID, n, err})
	}
	err := e.store.Update(func(s *state.State) error {
		for _, r := range results {
			for i := range s.Lists {
				if s.Lists[i].ID != r.id {
					continue
				}
				if r.err != nil {
					s.Lists[i].LastError = r.err.Error()
				} else {
					s.Lists[i].LastError = ""
					s.Lists[i].LastUpdate = time.Now().UTC()
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	// The store update triggers an asynchronous rebuild; make it synchronous
	// for callers waiting on the refresh.
	e.Rebuild()
	return nil
}

func (e *Engine) download(ctx context.Context, l state.List) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.URL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Rempart-DNS")
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxListSize+1))
	if err != nil {
		return 0, err
	}
	if len(data) > maxListSize {
		return 0, errors.New("liste trop volumineuse (> 64 Mo)")
	}
	if l.SHA256 != "" {
		sum := sha256.Sum256(data)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), l.SHA256) {
			return 0, errors.New("empreinte SHA-256 différente de celle épinglée : liste refusée")
		}
	}
	// Validate before replacing the cached copy.
	b := filter.NewBuilder()
	ps, err := filter.Parse(bytes.NewReader(data), b, b.AddSource(filter.Source{}), l.Allow)
	if err != nil {
		return 0, err
	}
	if ps.Block+ps.Allow == 0 {
		return 0, errors.New("aucune règle valide trouvée")
	}
	tmp := e.cachePath(l.ID) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return 0, err
	}
	return ps.Block + ps.Allow, os.Rename(tmp, e.cachePath(l.ID))
}

// RemoveCache deletes the downloaded copy of a list.
func (e *Engine) RemoveCache(id string) { _ = os.Remove(e.cachePath(id)) }

// Run refreshes lists periodically until ctx is cancelled.
func (e *Engine) Run(ctx context.Context, every time.Duration) {
	e.Rebuild()
	_ = e.Refresh(ctx, "")
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = e.Refresh(ctx, "")
		}
	}
}
