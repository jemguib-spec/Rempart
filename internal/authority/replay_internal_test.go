package authority

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/rempart-dns/rempart/internal/testutil"
)

func TestReplaySurvivesRestart(t *testing.T) {
	ks := testutil.Keystore(t)
	dir := t.TempDir()
	now := time.Now()
	a := &Authority{KS: ks, DataDir: dir, Log: testutil.Logger()}
	a.replayOnce.Do(a.loadReplay)
	if !a.replay.Fresh("AABB", now, now.Add(5*time.Minute)) {
		t.Fatal("première requête refusée")
	}
	if !a.replay.Fresh("old", now, now.Add(time.Second)) {
		t.Fatal("seconde requête refusée")
	}
	raw, _ := os.ReadFile(a.replayPath())
	if len(raw) == 0 || string(raw[:5]) != "RMPS1" {
		t.Fatal("mémoire anti-rejeu non scellée sur disque")
	}

	// Redémarrage : la mémoire est relue, la casse du MAC n'y change rien.
	b := &Authority{KS: ks, DataDir: dir, Log: testutil.Logger()}
	b.replayOnce.Do(b.loadReplay)
	if b.replay.Fresh("aabb", now.Add(time.Minute), now.Add(6*time.Minute)) {
		t.Fatal("rejeu accepté après un redémarrage")
	}
	// Une entrée expirée est oubliée.
	if !b.replay.Fresh("old", now.Add(time.Minute), now.Add(6*time.Minute)) {
		t.Fatal("entrée expirée encore retenue")
	}
	if err := b.Reseal(); err != nil {
		t.Fatal(err)
	}
	c := &Authority{KS: ks, DataDir: dir, Log: testutil.Logger()}
	c.replayOnce.Do(c.loadReplay)
	if c.replay.Fresh("AABB", now.Add(2*time.Minute), now.Add(7*time.Minute)) {
		t.Fatal("mémoire perdue après Reseal")
	}
}

func TestReplayUnreadableBlocksUpdates(t *testing.T) {
	ks := testutil.Keystore(t)
	dir := t.TempDir()
	a := &Authority{KS: ks, DataDir: dir, Log: testutil.Logger()}
	_ = os.WriteFile(a.replayPath(), []byte("RMPS1 altéré"), 0o600)
	a.replayOnce.Do(a.loadReplay)
	if !a.replayBlocked(time.Now()) {
		t.Fatal("mémoire illisible ignorée : la fenêtre de rejeu serait rouverte")
	}
	if a.replayBlocked(time.Now().Add((MaxFudge + 121) * time.Second)) {
		t.Fatal("blocage sans fin")
	}
}

func TestReplaySaveFailureRefuses(t *testing.T) {
	a := &Authority{KS: testutil.Keystore(t), DataDir: t.TempDir(), Log: testutil.Logger()}
	a.replayOnce.Do(a.loadReplay)
	a.replay.Save = func(map[string]time.Time) error { return errors.New("disque plein") }
	now := time.Now()
	if a.replay.Fresh("x", now, now.Add(time.Minute)) {
		t.Fatal("requête acceptée sans que son MAC soit enregistré")
	}
	a.replay.Save = nil
	if !a.replay.Fresh("x", now, now.Add(time.Minute)) {
		t.Fatal("MAC retenu malgré l'échec de l'enregistrement")
	}
}
