// modules.go - découverte et validation des modules PKCS#11, fichier de bascule keystore.json.
// Seuls les modules des dossiers autorisés, root, non modifiables, hors pkcs11-spy.
// Rempart ; lu au démarrage avant l'ouverture du keystore.

package keystore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ModuleInfo décrit une bibliothèque PKCS#11 (C_GetInfo).
type ModuleInfo struct {
	Path         string `json:"path"`
	Manufacturer string `json:"manufacturer"`
	Description  string `json:"description"`
	Version      string `json:"version"`
	Cryptoki     string `json:"cryptoki"`
}

// TokenInfo décrit un token présent dans un slot (C_GetTokenInfo).
type TokenInfo struct {
	Slot          uint   `json:"slot"`
	Label         string `json:"label"`
	Manufacturer  string `json:"manufacturer"`
	Model         string `json:"model"`
	Serial        string `json:"serial"`
	Initialized   bool   `json:"initialized"`
	LoginRequired bool   `json:"login_required"`
	PINCountLow   bool   `json:"pin_count_low"`
	PINFinalTry   bool   `json:"pin_final_try"`
	PINLocked     bool   `json:"pin_locked"`
}

// Mechanism indique la présence d'un mécanisme nécessaire à Rempart.
type Mechanism struct {
	Name     string `json:"name"`
	Present  bool   `json:"present"`
	Required bool   `json:"required"`
}

// TestReport est le résultat du test d'un token avant bascule.
type TestReport struct {
	Token      TokenInfo   `json:"token"`
	Mechanisms []Mechanism `json:"mechanisms"`
	Login      bool        `json:"login"`
	SelfTest   bool        `json:"self_test"`
}

// DefaultModuleDirs : emplacements habituels des bibliothèques des
// constructeurs (SoftHSM, Thales Luna, Entrust nShield, YubiHSM, OpenSC).
var DefaultModuleDirs = []string{
	"/usr/lib/softhsm",
	"/usr/lib/x86_64-linux-gnu/softhsm",
	"/usr/lib/aarch64-linux-gnu/softhsm",
	"/usr/local/lib/softhsm",
	"/usr/safenet/lunaclient/lib",
	"/opt/nfast/toolkits/pkcs11",
	"/usr/lib/x86_64-linux-gnu/pkcs11",
	"/usr/lib/aarch64-linux-gnu/pkcs11",
	"/usr/lib/pkcs11",
	"/usr/lib/x86_64-linux-gnu",
	"/usr/lib/aarch64-linux-gnu",
}

// Noms de fichiers reconnus comme modules PKCS#11 lors de la découverte.
var moduleName = regexp.MustCompile(`(?i)(pkcs11|cryptoki|softhsm|cknfast)[^/]*\.so(\.[0-9]+)*$`)

// DiscoverModules liste les modules PKCS#11 présents dans les dossiers
// autorisés. L'interface ne peut proposer, et donc charger, que ceux-ci :
// charger une bibliothèque revient à exécuter son code dans le processus.
func DiscoverModules(dirs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			// pkcs11-spy (OpenSC) journalise les appels, PIN compris : exclu.
			if e.IsDir() || !moduleName.MatchString(e.Name()) || strings.Contains(strings.ToLower(e.Name()), "spy") {
				continue
			}
			p := filepath.Join(d, e.Name())
			real, err := filepath.EvalSymlinks(p)
			if err != nil || seen[real] || checkModuleFile(real) != nil {
				continue
			}
			seen[real] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// AllowedModule vérifie qu'un chemin désigne un module découvert dans les
// dossiers autorisés et que le fichier n'est modifiable que par son
// propriétaire.
func AllowedModule(path string, dirs []string) error {
	clean := filepath.Clean(path)
	for _, m := range DiscoverModules(dirs) {
		if m == clean {
			return nil
		}
	}
	return fmt.Errorf("module %q refusé : il doit se trouver dans un dossier autorisé (keystore.pkcs11.module_dirs)", path)
}

func checkModuleFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return errors.New("pas un fichier ordinaire")
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return errors.New("modifiable par le groupe ou par tous")
	}
	return ownedByRoot(fi)
}

// Override est la configuration de keystore choisie depuis l'interface. Elle
// est lue avant l'ouverture du keystore, donc ne peut pas être scellée : elle
// ne contient aucun secret (le PIN vient de REMPART_PKCS11_PIN ou _FILE).
type Override struct {
	Backend          string    `json:"backend"`
	Module           string    `json:"module"`
	TokenLabel       string    `json:"token_label"`
	KEKLabel         string    `json:"kek_label"`
	PendingMigration bool      `json:"pending_migration"`
	RequestedBy      string    `json:"requested_by,omitempty"`
	RequestedAt      time.Time `json:"requested_at,omitempty"`
	MigratedAt       time.Time `json:"migrated_at,omitempty"`
	MigratedKeys     []string  `json:"migrated_keys,omitempty"`
	RetiredDir       string    `json:"retired_dir,omitempty"`
	LastError        string    `json:"last_error,omitempty"`
}

// OverridePath est le chemin du fichier de bascule dans data_dir.
func OverridePath(dataDir string) string { return filepath.Join(dataDir, "keystore.json") }

// LoadOverride lit keystore.json ; (nil, nil) s'il n'existe pas.
func LoadOverride(dataDir string) (*Override, error) {
	raw, err := os.ReadFile(OverridePath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var o Override
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, fmt.Errorf("keystore.json illisible: %w", err)
	}
	if o.Backend != "pkcs11" || o.Module == "" || strings.TrimSpace(o.TokenLabel) == "" {
		return nil, errors.New("keystore.json : seul le backend pkcs11 avec un token nommé est accepté")
	}
	return &o, nil
}

// LoadFailed lit la dernière demande de bascule en échec, s'il y en a une.
func LoadFailed(dataDir string) *Override {
	raw, err := os.ReadFile(OverridePath(dataDir) + ".failed")
	if err != nil {
		return nil
	}
	var o Override
	if json.Unmarshal(raw, &o) != nil {
		return nil
	}
	return &o
}

// Save écrit keystore.json de façon atomique (0600).
func (o *Override) Save(dataDir string) error {
	raw, _ := json.MarshalIndent(o, "", "  ")
	tmp := OverridePath(dataDir) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, OverridePath(dataDir))
}
