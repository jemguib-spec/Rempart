// backup.go - sous-commandes « backup verify » et « restore ».
// Entrées : archive produite par GET /api/backup, configuration (-config).
// La phrase de passe du keystore vient de REMPART_KEYSTORE_PASSPHRASE(_FILE),
// jamais de la ligne de commande.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rempart-dns/rempart/internal/backup"
	"github.com/rempart-dns/rempart/internal/config"
)

// cmdBackup : « rempart backup verify <archive> ».
func cmdBackup(args []string) int {
	if len(args) < 2 || args[0] != "verify" {
		fmt.Fprintln(os.Stderr, "usage : rempart backup verify [-config fichier] <archive.tar.gz>\n(les sauvegardes se créent par l'API : GET /api/backup, jeton de portée « backup »)")
		return 2
	}
	fs := flag.NewFlagSet("backup verify", flag.ContinueOnError)
	cfgPath := fs.String("config", envOr("REMPART_CONFIG", "rempart.yaml"), "fichier de configuration YAML")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 1 {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	tmp, err := os.MkdirTemp("", "rempart-verif-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(tmp)
	m, err := extract(fs.Arg(0), tmp)
	if err != nil {
		fmt.Fprintln(os.Stderr, "archive refusée :", err)
		return 1
	}
	pass, err := config.Secret("REMPART_KEYSTORE_PASSPHRASE", cfg.Keystore.Software.PassphraseFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	rep, err := backup.Verify(tmp, pass, m)
	pass = ""
	fmt.Printf("Sauvegarde du %s, Rempart %s, keystore %s (KEK génération %d), audit jusqu'à l'événement %d\n",
		m.Created.Local().Format(time.DateTime), m.Version, m.Backend, m.KEKGen, m.AuditSeq)
	fmt.Printf("Empreintes : %d fichier(s) conformes au manifeste\nKeystore : %s\n", rep.Files, rep.Keystore)
	if rep.State != "" {
		fmt.Printf("État : %s\nFichiers scellés déchiffrés : %d\nAudit : %s\n", rep.State, rep.Sealed, rep.Audit)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ÉCHEC :", err)
		return 1
	}
	return 0
}

// cmdRestore : « rempart restore [-force] <archive> », Rempart arrêté.
func cmdRestore(args []string) int {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	cfgPath := fs.String("config", envOr("REMPART_CONFIG", "rempart.yaml"), "fichier de configuration YAML")
	force := fs.Bool("force", false, "mettre de côté le dossier de données existant (jamais supprimé)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage : rempart restore [-config fichier] [-force] <archive.tar.gz>   (Rempart arrêté)")
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// Extraction dans le dossier de données lui-même : même système de
	// fichiers (souvent un volume), donc mise en place par renommage.
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	tmp, err := os.MkdirTemp(cfg.DataDir, backup.TempPrefix)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(tmp)
	m, err := extract(fs.Arg(0), tmp)
	if err != nil {
		fmt.Fprintln(os.Stderr, "archive refusée :", err)
		return 1
	}
	if m.Backend == "software" && cfg.Keystore.Backend != "software" {
		fmt.Fprintln(os.Stderr, "l'archive vient d'un keystore logiciel, la configuration désigne un HSM : corrigez keystore.backend")
		return 1
	}
	ksDir := ""
	if m.Backend == "software" {
		ksDir = cfg.Keystore.Software.Dir
	}
	moved, err := backup.Install(tmp, cfg.DataDir, ksDir, *force)
	for _, d := range moved {
		fmt.Println("contenu précédent mis de côté :", d)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "restauration impossible :", err)
		return 1
	}
	fmt.Printf("Sauvegarde du %s restaurée dans %s", m.Created.Local().Format(time.DateTime), cfg.DataDir)
	if ksDir != "" {
		fmt.Printf(" (keystore : %s)", ksDir)
	}
	fmt.Println(".\nRedémarrez Rempart avec la phrase de passe (ou le quorum) en vigueur À LA DATE DE LA SAUVEGARDE.")
	if m.Backend == "pkcs11" {
		fmt.Println("Keystore HSM : le token doit contenir les clés de cette date (sauvegarde du constructeur).")
	}
	return 0
}

func extract(archive, dir string) (backup.Manifest, error) {
	f, err := os.Open(archive)
	if err != nil {
		return backup.Manifest{}, err
	}
	defer f.Close()
	return backup.Extract(f, dir)
}
