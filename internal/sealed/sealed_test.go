package sealed

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/rempart-dns/rempart/internal/testutil"
)

func TestSealOpenRoundTrip(t *testing.T) {
	ks := testutil.Keystore(t)
	for _, data := range [][]byte{nil, {}, []byte("x"), bytes.Repeat([]byte("état"), 10000)} {
		blob, err := Seal(ks, data, []byte("aad"))
		if err != nil {
			t.Fatal(err)
		}
		if !IsSealed(blob) {
			t.Fatal("en-tête absent")
		}
		if len(data) >= 8 && bytes.Contains(blob, data) {
			t.Fatal("clair présent dans le blob")
		}
		got, err := Open(ks, blob, []byte("aad"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("contenu différent")
		}
	}
}

func TestSealIsRandomized(t *testing.T) {
	ks := testutil.Keystore(t)
	a, _ := Seal(ks, []byte("même"), nil)
	b, _ := Seal(ks, []byte("même"), nil)
	if bytes.Equal(a, b) {
		t.Fatal("deux scellements identiques : clé ou nonce réutilisé")
	}
	ka, _ := WrappedKey(a)
	kb, _ := WrappedKey(b)
	if bytes.Equal(ka, kb) {
		t.Fatal("même clé de données enveloppée deux fois")
	}
}

func TestOpenRejectsWrongAAD(t *testing.T) {
	ks := testutil.Keystore(t)
	blob, _ := Seal(ks, []byte("secret"), []byte("rempart-file:state.json"))
	if _, err := Open(ks, blob, []byte("rempart-file:other.json")); err == nil {
		t.Fatal("un fichier scellé s'ouvre sous un autre nom")
	}
}

func TestOpenRejectsOtherKeystore(t *testing.T) {
	blob, _ := Seal(testutil.Keystore(t), []byte("secret"), nil)
	if _, err := Open(testutil.Keystore(t), blob, nil); err == nil {
		t.Fatal("ouvert par un autre keystore")
	}
}

func TestOpenDetectsTampering(t *testing.T) {
	ks := testutil.Keystore(t)
	blob, _ := Seal(ks, []byte("contenu à protéger"), nil)
	for i := len(magic); i < len(blob); i++ {
		c := bytes.Clone(blob)
		c[i] ^= 0x01
		if _, err := Open(ks, c, nil); err == nil {
			t.Fatalf("octet %d modifié sans détection", i)
		}
	}
}

func TestOpenMalformedNoPanic(t *testing.T) {
	ks := testutil.Keystore(t)
	good, _ := Seal(ks, []byte("abc"), nil)
	cases := [][]byte{
		nil, {}, []byte("RMPS"), []byte("RMPS1"), []byte("RMPS1\x00"),
		[]byte("RMPS1\xff\xff"), []byte("XXXXX\x00\x00" + string(make([]byte, 40))),
		append([]byte("RMPS1\x00\x02ab"), make([]byte, 12)...),
	}
	for i := 0; i < len(good); i++ {
		cases = append(cases, good[:i])
	}
	for i, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("cas %d : panique %v", i, r)
				}
			}()
			if _, err := Open(ks, c, nil); err == nil {
				t.Fatalf("cas %d accepté", i)
			}
		}()
	}
	if _, ok := WrappedKey([]byte("RMPS1\xff\xff")); ok {
		t.Fatal("WrappedKey accepte une longueur hors limites")
	}
}

func TestFileRoundTripAndBinding(t *testing.T) {
	ks := testutil.Keystore(t)
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	if err := WriteFile(ks, a, []byte("A")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(ks, b, []byte("B")); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(a)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("permissions %v", fi.Mode().Perm())
	}
	if _, err := os.Stat(a + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("fichier temporaire laissé")
	}
	got, err := ReadFile(ks, a)
	if err != nil || string(got) != "A" {
		t.Fatalf("%q %v", got, err)
	}
	// Échanger les deux fichiers sur le disque doit être détecté.
	ba, _ := os.ReadFile(a)
	bb, _ := os.ReadFile(b)
	_ = os.WriteFile(a, bb, 0o600)
	_ = os.WriteFile(b, ba, 0o600)
	if _, err := ReadFile(ks, a); err == nil {
		t.Fatal("échange de fichiers non détecté")
	}
}

func TestShred(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x")
	_ = os.WriteFile(p, []byte("secret"), 0o600)
	if err := Shred(p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("fichier non supprimé")
	}
	// Un lien symbolique est supprimé, sa cible n'est jamais écrasée.
	target := filepath.Join(dir, "cible")
	_ = os.WriteFile(target, []byte("intact"), 0o600)
	link := filepath.Join(dir, "lien")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("liens symboliques indisponibles")
	}
	if err := Shred(link); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "intact" {
		t.Fatalf("cible modifiée : %q", b)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatal("lien non supprimé")
	}
}

func TestNewDataKey(t *testing.T) {
	a, b := NewDataKey(), NewDataKey()
	if len(a) != 32 || bytes.Equal(a, b) || bytes.Equal(a, make([]byte, 32)) {
		t.Fatal("clé de données invalide")
	}
}

func FuzzOpen(f *testing.F) {
	f.Add([]byte("RMPS1\x00\x10"))
	ks := testutil.Keystore(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Open(ks, b, nil)
		_, _ = WrappedKey(b)
	})
}
