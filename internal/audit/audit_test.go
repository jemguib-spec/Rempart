package audit

import (
	"bytes"
	"os"
	"testing"

	"github.com/rempart-dns/rempart/internal/testutil"
)

func TestTamperDetection(t *testing.T) {
	dir := t.TempDir()
	ks := testutil.Keystore(t)
	l, err := Open(ks, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"connexion", "règle.ajout", "zone.création"} {
		if err := l.Add("admin", a, "détail"); err != nil {
			t.Fatal(err)
		}
	}
	if r := l.Verify(); !r.OK || r.Count != 3 {
		t.Fatalf("journal valide attendu: %+v", r)
	}
	raw, _ := os.ReadFile(l.path)

	// 1. modification d'un événement
	os.WriteFile(l.path, bytes.Replace(raw, []byte("règle.ajout"), []byte("règle.retrait"), 1), 0o600)
	if r := l.Verify(); r.OK {
		t.Fatal("modification non détectée")
	}
	// 2. troncature de la fin
	lines := bytes.SplitAfter(raw, []byte("\n"))
	os.WriteFile(l.path, bytes.Join(lines[:2], nil), 0o600)
	if r := l.Verify(); r.OK {
		t.Fatal("troncature non détectée")
	}
	// 3. restauration
	os.WriteFile(l.path, raw, 0o600)
	if r := l.Verify(); !r.OK {
		t.Fatalf("le journal restauré devrait être valide: %s", r.Problem)
	}
	// 4. survives a reopen
	l2, err := Open(ks, dir)
	if err != nil {
		t.Fatal(err)
	}
	l2.Add("admin", "x", "")
	if r := l2.Verify(); !r.OK || r.Count != 4 {
		t.Fatalf("%+v", r)
	}
}
