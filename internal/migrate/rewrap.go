// rewrap.go - inventaire des générations de KEK utilisées et réchiffrement des clés du journal.
// Entrées : data_dir et le keystore logiciel ; sorties : générations encore utilisées, fichiers en retard.
// Rempart ; appelé après une rotation de KEK, service en marche (renommages atomiques).

package migrate

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/querylog"
	"github.com/rempart-dns/rempart/internal/sealed"
	"github.com/rempart-dns/rempart/internal/secmem"
)

// Inventory renvoie, pour chaque génération de KEK, les fichiers de
// dataDir qu'elle chiffre : fichiers scellés, clés quotidiennes du journal,
// clés de signature du keystore logiciel. Toute erreur de lecture fait
// échouer l'inventaire : un fichier ignoré ferait retirer, puis détruire,
// une génération encore utilisée.
func Inventory(dataDir, keystoreDir string) (map[uint32][]string, error) {
	out := map[uint32][]string{}
	add := func(path string, wrapped []byte) error {
		gen, _, ok := keystore.WrapGeneration(wrapped)
		if !ok {
			return fmt.Errorf("%s : en-tête chiffré illisible", path)
		}
		rel, _ := filepath.Rel(dataDir, path)
		out[gen] = append(out[gen], rel)
		return nil
	}
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		path := filepath.Join(dataDir, e.Name())
		blob, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if !sealed.IsSealed(blob) {
			continue
		}
		w, ok := sealed.WrappedKey(blob)
		if !ok {
			return nil, fmt.Errorf("%s : fichier scellé tronqué", path)
		}
		if err := add(path, w); err != nil {
			return nil, err
		}
	}
	for _, pattern := range []string{filepath.Join(dataDir, "querylog", "*.key"), filepath.Join(keystoreDir, "keys", "*.key")} {
		files, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		for _, path := range files {
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			if err := add(path, raw); err != nil {
				return nil, err
			}
		}
	}
	for g := range out {
		sort.Strings(out[g])
	}
	return out, nil
}

// RewrapQueryLogKeys rechiffre les clés quotidiennes du journal par la KEK
// courante. La clé de données ne change pas : un lecteur concurrent lit
// l'ancienne ou la nouvelle version, qui donnent la même clé.
func RewrapQueryLogKeys(dataDir string, ks *keystore.Software) (int, error) {
	files, _ := filepath.Glob(filepath.Join(dataDir, "querylog", "*.key"))
	n := 0
	for _, path := range files {
		day := strings.TrimSuffix(filepath.Base(path), ".key")
		wrapped, err := os.ReadFile(path)
		if err != nil {
			return n, err
		}
		if ks.IsCurrent(wrapped) {
			continue
		}
		dek, err := ks.Unwrap(wrapped, querylog.KeyAAD(day))
		if err != nil {
			return n, err
		}
		nw, err := ks.Wrap(dek, querylog.KeyAAD(day))
		secmem.Wipe(dek)
		if err != nil {
			return n, err
		}
		if err := writeSync(path+".tmp", nw); err != nil {
			return n, err
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
