//go:build cgo

package keystore_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rempart-dns/rempart/internal/keystore"
)

// cloneToken copie le token SoftHSM sur disque sous un autre label (même
// longueur), comme le ferait le clonage d'un constructeur.
func cloneToken(t *testing.T, label string) {
	t.Helper()
	conf, _ := os.ReadFile(os.Getenv("SOFTHSM2_CONF"))
	dir := strings.TrimSpace(strings.TrimPrefix(strings.Split(string(conf), "\n")[0], "directories.tokendir ="))
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || !entries[0].IsDir() {
		t.Skipf("%d tokens", len(entries))
	}
	src := filepath.Join(dir, entries[0].Name())
	dst := filepath.Join(dir, "clone-"+entries[0].Name())
	if out, err := exec.Command("cp", "-r", src, dst).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	p := filepath.Join(dst, "token.object")
	b, err := os.ReadFile(p)
	if err != nil || !bytes.Contains(b, []byte("rempart-test")) {
		t.Skip("format de token SoftHSM inattendu")
	}
	b = bytes.ReplaceAll(b, []byte("rempart-test"), []byte(label))
	// Numéro de série différent (SoftHSM en dérive le numéro de slot).
	if m := regexp.MustCompile(`[0-9a-f]{16}`).Find(b); m != nil {
		ns := append([]byte{}, m...)
		ns[15] = "0123456789abcdef"[(strings.IndexByte("0123456789abcdef", ns[15])+1)%16]
		b = bytes.ReplaceAll(b, m, ns)
	}
	_ = os.WriteFile(p, b, 0o600)
}

func TestVerifyClone(t *testing.T) {
	cfg := softHSM(t)
	ks, err := keystore.OpenPKCS11(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"rempart-tls", "rempart-audit"} {
		if _, err := ks.Signer(l, keystore.ECDSAP256, true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ks.Signer("zone-maison.lan-zsk", keystore.Ed25519, true); err != nil {
		t.Fatal(err)
	}
	aad := []byte("rempart-file:state.sealed")
	wrapped, err := ks.Wrap(bytes.Repeat([]byte{7}, 32), aad)
	if err != nil {
		t.Fatal(err)
	}
	samples := [][2][]byte{{wrapped, aad}}
	// Clonage hors ligne (SoftHSM ne relit ses tokens qu'au chargement),
	// puis un second token vide.
	ks.Close()
	cloneToken(t, "rempart-copy")
	out, err := exec.Command("softhsm2-util", "--init-token", "--free", "--label", "autre-token", "--pin", "1234", "--so-pin", "5678").CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if ks, err = keystore.OpenPKCS11(cfg); err != nil {
		t.Fatal(err)
	}
	defer ks.Close()

	// Le token en service lui-même : refusé.
	if _, err := keystore.VerifyClone(ks, cfg, samples); err == nil {
		t.Fatal("token en service accepté comme clone")
	}
	// Un clone exact : tout est vérifié, avec le contexte partagé.
	clone := cfg
	clone.TokenLabel = "rempart-copy"
	rep, err := keystore.VerifyClone(ks, clone, samples)
	if err != nil || !rep.OK || len(rep.Keys) != 3 || !rep.KEK.OK {
		t.Fatalf("clone refusé : %v %+v", err, rep)
	}
	// Le token en service fonctionne encore (pas de C_Finalize).
	if _, err := ks.Wrap([]byte("encore"), nil); err != nil {
		t.Fatalf("token en service coupé par la vérification : %v", err)
	}
	// Un token vide : clés et KEK absentes.
	other := cfg
	other.TokenLabel = "autre-token"
	rep, err = keystore.VerifyClone(ks, other, samples)
	if err != nil || rep.OK || rep.KEK.OK {
		t.Fatalf("token vide accepté : %v %+v", err, rep)
	}
	// Mauvais PIN : erreur, sans rien changer.
	other.PIN = "0000"
	if _, err := keystore.VerifyClone(ks, other, samples); err == nil {
		t.Fatal("mauvais PIN accepté")
	}
	// Données qui ne viennent pas de la KEK : refusées.
	rep, _ = keystore.VerifyClone(ks, clone, [][2][]byte{{wrapped, []byte("autre aad")}})
	if rep.OK || rep.KEK.OK {
		t.Fatal("KEK validée sur des données qu'elle n'ouvre pas")
	}
}
