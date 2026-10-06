// migrate_test.go - test de bout en bout de la migration vers SoftHSM2.
// Nécessite softhsm2-util ; sinon le test est ignoré.
// Rempart ; build cgo.

//go:build cgo

package migrate_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rempart-dns/rempart/internal/audit"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/migrate"
	"github.com/rempart-dns/rempart/internal/querylog"
	"github.com/rempart-dns/rempart/internal/sealed"
)

func softHSM(t *testing.T) (module string) {
	t.Helper()
	for _, p := range []string{"/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"} {
		if _, err := os.Stat(p); err == nil {
			module = p
		}
	}
	if _, err := exec.LookPath("softhsm2-util"); err != nil || module == "" {
		t.Skip("SoftHSM2 non installé")
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "softhsm2.conf")
	os.MkdirAll(filepath.Join(dir, "tokens"), 0o700)
	os.WriteFile(conf, []byte("directories.tokendir = "+filepath.Join(dir, "tokens")+"\nobjectstore.backend = file\nlog.level = ERROR\n"), 0o600)
	t.Setenv("SOFTHSM2_CONF", conf)
	if out, err := exec.Command("softhsm2-util", "--init-token", "--free", "--label", "migr", "--pin", "1234", "--so-pin", "5678").CombinedOutput(); err != nil {
		t.Fatalf("init token: %v %s", err, out)
	}
	return module
}

func TestMigrationToHSM(t *testing.T) {
	module := softHSM(t)

	// L'assistant teste le token avant la bascule.
	_, tokens, err := keystore.ProbeModule(module)
	if err != nil || len(tokens) == 0 {
		t.Fatalf("probe: %v %v", err, tokens)
	}
	if _, err := keystore.TestToken(module, "migr", []byte("0000"), false); err == nil {
		t.Fatal("un mauvais PIN doit être refusé")
	}
	rep, err := keystore.TestToken(module, "migr", []byte("1234"), false)
	if err != nil || !rep.Login || !rep.SelfTest {
		t.Fatalf("test du token : %v %+v", err, rep)
	}

	data := t.TempDir()
	sw, _, err := keystore.OpenSoftware(filepath.Join(data, "keystore"), "phrase-de-passe")
	if err != nil {
		t.Fatal(err)
	}
	pubs := map[string]string{}
	for label, alg := range map[string]keystore.Algorithm{"rempart-tls": keystore.ECDSAP256, "zone-x-ksk": keystore.ECDSAP384, "zone-x-zsk": keystore.Ed25519} {
		s, err := sw.Signer(label, alg, true)
		if err != nil {
			t.Fatal(err)
		}
		pubs[label] = keystore.Fingerprint(s.Public())
	}
	statePath := filepath.Join(data, "state.sealed")
	if err := sealed.WriteFile(sw, statePath, []byte(`{"secret":"état"}`)); err != nil {
		t.Fatal(err)
	}
	al, err := audit.Open(sw, data)
	if err != nil {
		t.Fatal(err)
	}
	al.Add("admin", "test", "avant migration")
	os.MkdirAll(filepath.Join(data, "querylog"), 0o700)
	dek := bytes.Repeat([]byte{7}, 32)
	wrapped, _ := sw.Wrap(dek, querylog.KeyAAD("2026-10-05"))
	os.WriteFile(filepath.Join(data, "querylog", "2026-10-05.key"), wrapped, 0o600)

	hsm, err := keystore.OpenPKCS11(keystore.PKCS11Config{Module: module, TokenLabel: "migr", PIN: "1234"})
	if err != nil {
		t.Fatal(err)
	}
	defer hsm.Close()
	res, err := migrate.Run(data, sw, hsm)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Keys) != 4 { // trois clés + clé d'audit
		t.Fatalf("clés migrées : %v", res.Keys)
	}
	// Reprise : une seconde exécution reconnaît les clés déjà importées.
	if _, err := keystore.MigrateKeys(sw, hsm); err != nil {
		t.Fatalf("reprise : %v", err)
	}

	// Tout est désormais lisible avec le HSM seul.
	if raw, err := sealed.ReadFile(hsm, statePath); err != nil || string(raw) != `{"secret":"état"}` {
		t.Fatalf("état : %v", err)
	}
	if _, err := sealed.ReadFile(sw, statePath); err == nil {
		t.Fatal("l'ancien keystore ne doit plus ouvrir l'état")
	}
	w2, _ := os.ReadFile(filepath.Join(data, "querylog", "2026-10-05.key"))
	if got, err := hsm.Unwrap(w2, querylog.KeyAAD("2026-10-05")); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("clé du journal : %v", err)
	}
	al2, err := audit.Open(hsm, data)
	if err != nil {
		t.Fatal(err)
	}
	if v := al2.Verify(); !v.OK {
		t.Fatalf("audit après migration : %s", v.Problem)
	}
	for _, k := range hsm.Keys() {
		if want, ok := pubs[k.Label]; ok && want != k.Fingerprint {
			t.Fatalf("%s : clé publique différente après import", k.Label)
		}
		if k.Origin != "importée" {
			t.Fatalf("%s : origine %q", k.Label, k.Origin)
		}
	}
	if _, err := os.Stat(res.BackupDir); err != nil {
		t.Fatal("sauvegarde absente")
	}
	retired, err := migrate.RetireSoftware(sw.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.DestroyRetired(retired); err != nil {
		t.Fatal(err)
	}
	if err := migrate.DestroyRetired(data); err == nil {
		t.Fatal("seul un keystore retiré peut être détruit")
	}
}
