package keystore_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/rempart-dns/rempart/internal/keystore"
)

func TestSoftwarePassphrase(t *testing.T) {
	dir := t.TempDir()
	ks, _, err := keystore.OpenSoftware(dir, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	k, err := ks.Signer("k1", keystore.ECDSAP256, true)
	if err != nil {
		t.Fatal(err)
	}
	ks.Close()
	raw, _ := os.ReadFile(filepath.Join(dir, "keys", "k1.key"))
	if bytes.Contains(raw, []byte("PRIVATE")) {
		t.Fatal("clé privée stockée en clair")
	}
	if _, _, err := keystore.OpenSoftware(dir, "mauvaise"); err == nil {
		t.Fatal("une mauvaise phrase de passe doit être refusée")
	}
	ks2, _, err := keystore.OpenSoftware(dir, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ks2.Signer("k1", "", false)
	if err != nil || keystore.Fingerprint(k2.Public()) != keystore.Fingerprint(k.Public()) {
		t.Fatal("clé non retrouvée", err)
	}
}

func TestSoftwareSigningAlgorithms(t *testing.T) {
	for _, a := range keystore.SigningAlgorithms(nil) {
		if !a.Supported {
			t.Fatalf("%s doit être disponible en logiciel", a.ID)
		}
	}
}
