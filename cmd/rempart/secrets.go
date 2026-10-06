// secrets.go - sous-commande « setup-secrets » : crée les secrets de Rempart dans le volume monté sur /run/secrets.
// Entrées : saisie au terminal sans écho, ou une valeur sur l'entrée standard (-import) ; sorties : fichiers 0400, un par secret.
// Contexte : lancée par scripts/install.sh et install.ps1 dans un conteneur jetable ; aucun secret ne passe par l'hôte ni par argv.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rempart-dns/rempart/internal/api"
)

const (
	secretKeystore = "keystore_passphrase"
	secretAdmin    = "admin_password"
	secretPIN      = "hsm_pin"
	secretSOPIN    = "hsm_so_pin"
)

// Secrets acceptés par -import : ceux d'une installation existante qu'il faut
// reprendre tels quels (le mot de passe administrateur, lui, est déjà haché dans l'état).
var importable = map[string]bool{secretKeystore: true, secretPIN: true, secretSOPIN: true}

func cmdSetupSecrets(args []string) int {
	fs := flag.NewFlagSet("setup-secrets", flag.ExitOnError)
	dir := fs.String("dir", "/run/secrets", "dossier des secrets (volume dédié)")
	data := fs.String("data", "", "dossier de données de Rempart s'il est monté : sans état existant, le mot de passe administrateur est demandé")
	softhsm := fs.Bool("softhsm", false, "démonstration SoftHSM : PIN et PIN SO générés, pas de phrase de keystore")
	hsmPIN := fs.Bool("hsm-pin", false, "demander aussi le PIN utilisateur du HSM du constructeur")
	imp := fs.String("import", "", "secret à lire sur l'entrée standard, une ligne (reprise d'une installation existante)")
	forget := fs.Bool("forget-admin", false, "effacer le mot de passe administrateur initial une fois l'état créé (-data requis)")
	_ = fs.Parse(args)
	if fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "setup-secrets n'accepte aucun argument libre : un secret ne passe jamais par la ligne de commande")
		return 2
	}
	umask(0o077)
	if err := prepareDir(*dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	stateExists := *data != "" && exists(filepath.Join(*data, "state.sealed"))

	switch {
	case *forget:
		if *data == "" {
			fmt.Fprintln(os.Stderr, "-forget-admin exige -data : sans état créé, le mot de passe initial est encore nécessaire")
			return 2
		}
		if !stateExists {
			fmt.Fprintln(os.Stderr, "état pas encore créé : le mot de passe initial est conservé")
			return 3
		}
		if err := os.Remove(filepath.Join(*dir, secretAdmin)); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("Mot de passe administrateur initial effacé du volume (il est haché dans l'état scellé).")
		return 0
	case *imp != "":
		return importSecret(*dir, *imp)
	}

	if !isTerminal(os.Stdin) {
		fmt.Fprintln(os.Stderr, "setup-secrets demande un terminal : lancez le conteneur avec -it")
		return 2
	}
	in := bufio.NewReader(os.Stdin)
	steps := []func() error{}
	if *softhsm {
		steps = append(steps,
			func() error { return ensureGenerated(*dir, secretPIN, "PIN du token SoftHSM") },
			func() error { return ensureGenerated(*dir, secretSOPIN, "PIN SO du token SoftHSM") })
	} else {
		steps = append(steps, func() error { return ensureKeystore(in, *dir, stateExists) })
	}
	if *hsmPIN {
		steps = append(steps, func() error { return ensureTyped(in, *dir, secretPIN, "PIN utilisateur du HSM", 4) })
	}
	if !stateExists {
		steps = append(steps, func() error { return ensureAdmin(in, *dir) })
	}
	for _, s := range steps {
		if err := s(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	return 0
}

// prepareDir refuse un dossier lisible par d'autres : le volume est créé 0700
// par l'image, un mode plus large signale un montage inattendu.
func prepareDir(dir string) error {
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("dossier des secrets : %w (montez le volume de secrets sur %s)", err, dir)
	}
	if !st.IsDir() {
		return fmt.Errorf("%s n'est pas un dossier", dir)
	}
	if st.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("%s est accessible à d'autres utilisateurs et ne peut pas être restreint : %w", dir, err)
		}
	}
	return nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func importSecret(dir, name string) int {
	if !importable[name] {
		fmt.Fprintf(os.Stderr, "-import accepte %s, %s ou %s\n", secretKeystore, secretPIN, secretSOPIN)
		return 2
	}
	if exists(filepath.Join(dir, name)) {
		fmt.Printf("%s déjà présent dans le volume : inchangé.\n", name)
		return 0
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// Une seule ligne : un fichier Windows peut finir par CRLF ou porter une BOM.
	val := strings.TrimPrefix(strings.TrimRight(string(raw), "\r\n"), "\uFEFF")
	clear(raw)
	if val == "" || strings.ContainsAny(val, "\r\n") {
		fmt.Fprintln(os.Stderr, "valeur vide ou sur plusieurs lignes : rien n'est écrit")
		return 1
	}
	if err := writeSecret(dir, name, []byte(val)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("%s repris dans le volume de secrets.\n", name)
	return 0
}

// randomSecret : 256 bits de crypto/rand, en base64url sans remplissage (43 caractères).
func randomSecret() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	out := make([]byte, base64.RawURLEncoding.EncodedLen(len(b)))
	base64.RawURLEncoding.Encode(out, b)
	clear(b)
	return out, nil
}

func ensureGenerated(dir, name, label string) error {
	if exists(filepath.Join(dir, name)) {
		fmt.Printf("%s : déjà présent.\n", label)
		return nil
	}
	v, err := randomSecret()
	if err != nil {
		return err
	}
	defer clear(v)
	if err := writeSecret(dir, name, v); err != nil {
		return err
	}
	fmt.Printf("%s : généré dans le volume (non affiché).\n", label)
	return nil
}

func ensureKeystore(in *bufio.Reader, dir string, stateExists bool) error {
	if exists(filepath.Join(dir, secretKeystore)) {
		fmt.Println("Phrase du keystore : déjà présente.")
		return nil
	}
	if stateExists {
		// Une phrase neuve n'ouvrirait pas le keystore déjà présent dans les données.
		fmt.Println("Des données Rempart existent déjà : saisissez la phrase du keystore de cette installation.")
		return ensureTyped(in, dir, secretKeystore, "Phrase du keystore", 12)
	}
	fmt.Println("Phrase du keystore : Entrée pour en générer une (recommandé),")
	fmt.Println("ou saisissez celle d'une installation existante (restauration, autre machine).")
	first, err := readSecret(in, "Phrase du keystore : ")
	if err != nil {
		return err
	}
	if first != "" {
		return confirmAndWrite(in, dir, secretKeystore, "Phrase du keystore", first, 12)
	}
	v, err := randomSecret()
	if err != nil {
		return err
	}
	defer clear(v)
	if err := writeSecret(dir, secretKeystore, v); err != nil {
		return err
	}
	showOnce(in, v)
	return nil
}

// showOnce affiche la phrase générée une seule fois, puis efface l'écran et
// l'historique de défilement du terminal (séquences ANSI, sans effet ailleurs).
func showOnce(in *bufio.Reader, v []byte) {
	if !isTerminal(os.Stdout) {
		fmt.Println("Phrase du keystore générée dans le volume. Sortie non interactive : elle n'est pas affichée.")
		return
	}
	fmt.Println()
	fmt.Println("Phrase du keystore générée (256 bits). Elle n'est affichée qu'une fois :")
	fmt.Println()
	fmt.Printf("    %s\n\n", v)
	fmt.Println("Rangez-la dans votre gestionnaire de mots de passe : elle sert à vérifier ou")
	fmt.Println("restaurer une sauvegarde et à réinstaller Rempart sur une autre machine.")
	fmt.Print("Appuyez sur Entrée une fois rangée : l'écran sera effacé. ")
	_, _ = in.ReadString('\n')
	fmt.Print("\033[H\033[2J\033[3J")
	fmt.Println("Phrase du keystore enregistrée dans le volume de secrets.")
}

func ensureAdmin(in *bufio.Reader, dir string) error {
	if exists(filepath.Join(dir, secretAdmin)) {
		fmt.Println("Mot de passe administrateur initial : déjà présent.")
		return nil
	}
	fmt.Println("Choisissez le mot de passe du compte « admin » de l'interface (12 caractères au moins).")
	return ensureTyped(in, dir, secretAdmin, "Mot de passe administrateur", 12)
}

func ensureTyped(in *bufio.Reader, dir, name, label string, minLen int) error {
	if exists(filepath.Join(dir, name)) {
		fmt.Printf("%s : déjà présent.\n", label)
		return nil
	}
	for {
		first, err := readSecret(in, label+" : ")
		if err != nil {
			return err
		}
		err = confirmAndWrite(in, dir, name, label, first, minLen)
		if err == nil || !errors.Is(err, errRetry) {
			return err
		}
		fmt.Fprintln(os.Stderr, err)
	}
}

var errRetry = errors.New("recommencez")

// confirmAndWrite redemande la valeur avant de l'écrire. Les chaînes Go ne
// peuvent pas être effacées : seule la copie en octets l'est.
func confirmAndWrite(in *bufio.Reader, dir, name, label, first string, minLen int) error {
	if len(first) < minLen {
		return fmt.Errorf("%s : %d caractères au moins (%w)", label, minLen, errRetry)
	}
	if name == secretAdmin {
		if err := api.ValidatePassword(first); err != nil {
			return fmt.Errorf("%v (%w)", err, errRetry)
		}
	}
	second, err := readSecret(in, label+", confirmation : ")
	if err != nil {
		return err
	}
	if first != second {
		return fmt.Errorf("les deux saisies diffèrent (%w)", errRetry)
	}
	b := []byte(first)
	defer clear(b)
	if err := writeSecret(dir, name, b); err != nil {
		return err
	}
	fmt.Printf("%s : enregistré dans le volume.\n", label)
	return nil
}

// writeSecret écrit de façon atomique et sans écraser : fichier temporaire
// 0600, contenu synchronisé, passage en 0400, puis lien vers le nom final
// (os.Link échoue si le secret existe déjà, contrairement à os.Rename).
func writeSecret(dir, name string, val []byte) error {
	f, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, err = f.Write(val)
	if err == nil {
		_, err = f.Write([]byte{'\n'})
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = f.Chmod(0o400)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("écriture de %s : %w", name, err)
	}
	if err := os.Link(tmp, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("écriture de %s : %w", name, err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
