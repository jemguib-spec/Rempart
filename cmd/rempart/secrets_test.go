// secrets_test.go - tests de setup-secrets : écriture atomique 0400 sans écrasement, génération, oubli du mot de passe initial.
// Les saisies au terminal ne sont pas testées ici : elles passent par readSecret, déjà utilisé par unseal et passwd.
// Contexte : Rempart, cmd/rempart.
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteSecretModeAndNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	if err := writeSecret(dir, "x", []byte("valeur-de-test")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "x"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o400 {
		t.Fatalf("mode %v, 0400 attendu", st.Mode().Perm())
	}
	if err := writeSecret(dir, "x", []byte("autre")); err == nil {
		t.Fatal("un secret existant a été écrasé")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "x")); string(b) != "valeur-de-test\n" {
		t.Fatal("contenu modifié")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("fichier temporaire resté : %d entrées", len(ents))
	}
}

func TestRandomSecret(t *testing.T) {
	a, err := randomSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := randomSecret()
	if len(a) != 43 || string(a) == string(b) {
		t.Fatalf("secret généré inattendu (longueur %d)", len(a))
	}
}

func TestForgetAdminNeedsState(t *testing.T) {
	sec, data := t.TempDir(), t.TempDir()
	if err := writeSecret(sec, secretAdmin, []byte("mot-de-passe-test")); err != nil {
		t.Fatal(err)
	}
	if rc := cmdSetupSecrets([]string{"-dir", sec, "-data", data, "-forget-admin"}); rc != 3 {
		t.Fatalf("sans état : code %d, 3 attendu", rc)
	}
	if !exists(filepath.Join(sec, secretAdmin)) {
		t.Fatal("mot de passe effacé avant la création de l'état")
	}
	if err := os.WriteFile(filepath.Join(data, "state.sealed"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := cmdSetupSecrets([]string{"-dir", sec, "-data", data, "-forget-admin"}); rc != 0 {
		t.Fatalf("code %d", rc)
	}
	if exists(filepath.Join(sec, secretAdmin)) {
		t.Fatal("mot de passe initial toujours présent")
	}
}

func TestImportRefusesAdminAndArgs(t *testing.T) {
	sec := t.TempDir()
	if rc := cmdSetupSecrets([]string{"-dir", sec, "-import", secretAdmin}); rc != 2 {
		t.Fatalf("import du mot de passe admin : code %d, 2 attendu", rc)
	}
	if rc := cmdSetupSecrets([]string{"-dir", sec, "valeur"}); rc != 2 {
		t.Fatalf("argument libre : code %d, 2 attendu", rc)
	}
}
