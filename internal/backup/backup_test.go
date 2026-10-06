package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rempart-dns/rempart/internal/audit"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/sealed"
)

func TestRoundTrip(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	ksDir := filepath.Join(data, "keystore")
	ks, _, err := keystore.OpenSoftware(ksDir, "phrase-de-passe-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := sealed.WriteFile(ks, filepath.Join(data, "state.sealed"), []byte(`{"lists":[]}`)); err != nil {
		t.Fatal(err)
	}
	al, _ := audit.Open(ks, data)
	_ = al.Add("admin", "connexion", "")
	os.MkdirAll(filepath.Join(data, "lists"), 0o700)
	os.WriteFile(filepath.Join(data, "lists", "a.txt"), []byte("ads.example\n"), 0o600)
	os.WriteFile(filepath.Join(data, "state.sealed.tmp"), []byte("x"), 0o600)
	ks.Close()

	var buf bytes.Buffer
	m, err := Create(&buf, Source{DataDir: data, KeystoreDir: ksDir, SkipLists: true}, Manifest{Version: "1.0.0", Backend: "software"})
	if err != nil {
		t.Fatal(err)
	}
	for name := range m.Files {
		if strings.Contains(name, "lists/") || strings.HasSuffix(name, ".tmp") || strings.HasPrefix(name, "data/keystore") {
			t.Fatalf("fichier qui ne devait pas être sauvegardé : %s", name)
		}
	}
	ex := filepath.Join(data, TempPrefix+"x")
	got, err := Extract(bytes.NewReader(buf.Bytes()), ex)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(ex, "phrase-de-passe-test", got)
	if err != nil || rep.Sealed < 2 || !strings.HasPrefix(rep.Audit, "intègre") {
		t.Fatalf("vérification : %+v %v", rep, err)
	}
	if _, err := Verify(ex, "mauvaise-phrase", got); err == nil {
		t.Fatal("mauvaise phrase acceptée")
	}
	// Installation : refus d'écraser, puis mise de côté avec force.
	if _, err := Install(ex, data, ksDir, false); err == nil {
		t.Fatal("dossier non vide écrasé sans -force")
	}
	moved, err := Install(ex, data, ksDir, true)
	if err != nil || len(moved) != 1 {
		t.Fatalf("installation : %v %v", moved, err)
	}
	if _, err := os.Stat(filepath.Join(ksDir, "master.json")); err != nil {
		t.Fatal("keystore non restauré")
	}
	if _, err := os.Stat(filepath.Join(moved[0], "keystore", "master.json")); err != nil {
		t.Fatal("ancien keystore non mis de côté")
	}
	if _, err := os.Stat(filepath.Join(data, "state.sealed")); err != nil {
		t.Fatal("état non restauré")
	}
	// La mise de côté n'entre pas dans les sauvegardes suivantes.
	var again bytes.Buffer
	m2, _ := Create(&again, Source{DataDir: data, KeystoreDir: ksDir}, Manifest{Backend: "software"})
	for name := range m2.Files {
		if strings.Contains(name, AsidePrefix) {
			t.Fatalf("dossier mis de côté sauvegardé : %s", name)
		}
	}

	// Archive altérée : empreinte différente.
	tampered := retar(t, buf.Bytes(), func(name string, b []byte) []byte {
		if name == "data/state.sealed" {
			b[len(b)-1] ^= 1
		}
		return b
	})
	if _, err := Extract(bytes.NewReader(tampered), filepath.Join(root, "ex2")); err == nil || !strings.Contains(err.Error(), "empreinte") {
		t.Fatalf("altération non détectée : %v", err)
	}
	// Traversée de chemin.
	evil := retar(t, buf.Bytes(), nil, "data/../../evil")
	if _, err := Extract(bytes.NewReader(evil), filepath.Join(root, "ex3")); err == nil {
		t.Fatal("chemin ../ accepté")
	}
}

// retar réécrit une archive en modifiant un contenu ou en ajoutant une entrée.
func retar(t *testing.T, in []byte, mod func(string, []byte) []byte, extra ...string) []byte {
	gz, _ := gzip.NewReader(bytes.NewReader(in))
	tr := tar.NewReader(gz)
	var out bytes.Buffer
	gw := gzip.NewWriter(&out)
	tw := tar.NewWriter(gw)
	for _, e := range extra {
		tw.WriteHeader(&tar.Header{Name: e, Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
		tw.Write([]byte("x"))
	}
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		b := new(bytes.Buffer)
		b.ReadFrom(tr)
		data := b.Bytes()
		if mod != nil {
			data = mod(h.Name, data)
		}
		h.Size = int64(len(data))
		tw.WriteHeader(h)
		tw.Write(data)
	}
	tw.Close()
	gw.Close()
	return out.Bytes()
}
