// migrate.go - migration des données d'un keystore logiciel vers un HSM.
// Rechiffrement des clés de données, sauvegarde, bascule reprenable.
// Rempart ; appelé par main au démarrage.

// Package migrate fait passer les données de Rempart d'un keystore logiciel à
// un HSM PKCS#11. Il s'exécute au démarrage, avant tout autre composant, quand
// l'administrateur l'a demandé depuis l'interface (data_dir/keystore.json).
//
// Les clés de signature sont importées dans le HSM comme objets non
// extractibles ; les clés de données (état scellé, tête d'audit, clés
// quotidiennes du journal) sont déchiffrées par l'ancien keystore et
// rechiffrées par la KEK du HSM. Les fichiers d'origine sont copiés dans un
// dossier de sauvegarde avant d'être remplacés.
package migrate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/querylog"
	"github.com/rempart-dns/rempart/internal/sealed"
	"github.com/rempart-dns/rempart/internal/secmem"
)

// ErrPartial : une partie des fichiers est déjà chiffrée par le HSM. Revenir
// au keystore logiciel rendrait ces fichiers illisibles ; la migration doit
// être reprise (Run saute ce que le HSM sait déjà ouvrir).
var ErrPartial = errors.New("migration partielle")

// Report résume une migration réussie.
type Report struct {
	Keys      []string `json:"keys"`
	Files     []string `json:"files"`
	BackupDir string   `json:"backup_dir"`
}

type staged struct {
	path string
	blob []byte
}

// Run migre dataDir de src vers dst. En cas d'erreur avant le remplacement
// des fichiers, rien n'est modifié sur le disque (les clés éventuellement
// importées dans le HSM restent, une nouvelle tentative les reconnaît).
func Run(dataDir string, src *keystore.Software, dst keystore.Keystore) (Report, error) {
	var rep Report
	keys, err := keystore.MigrateKeys(src, dst)
	rep.Keys = keys
	if err != nil {
		return rep, err
	}
	var plan []staged

	// Fichiers scellés à la racine de data_dir (état, tête d'audit…).
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return rep, err
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".tmp") || strings.HasSuffix(e.Name(), ".migr") {
			continue
		}
		path := filepath.Join(dataDir, e.Name())
		blob, err := os.ReadFile(path)
		if err != nil || !sealed.IsSealed(blob) {
			continue
		}
		if done, err := sealed.Open(dst, blob, sealed.FileAAD(path)); err == nil {
			secmem.Wipe(done) // déjà migré lors d'une tentative interrompue
			continue
		}
		pt, err := sealed.Open(src, blob, sealed.FileAAD(path))
		if err != nil {
			return rep, fmt.Errorf("%s : %w", e.Name(), err)
		}
		nb, err := sealed.Seal(dst, pt, sealed.FileAAD(path))
		secmem.Wipe(pt)
		if err != nil {
			return rep, fmt.Errorf("%s : %w", e.Name(), err)
		}
		plan = append(plan, staged{path, nb})
	}

	// Clés quotidiennes du journal chiffré.
	keyFiles, _ := filepath.Glob(filepath.Join(dataDir, "querylog", "*.key"))
	for _, path := range keyFiles {
		day := strings.TrimSuffix(filepath.Base(path), ".key")
		wrapped, err := os.ReadFile(path)
		if err != nil {
			return rep, err
		}
		if done, err := dst.Unwrap(wrapped, querylog.KeyAAD(day)); err == nil {
			secmem.Wipe(done)
			continue
		}
		dek, err := src.Unwrap(wrapped, querylog.KeyAAD(day))
		if err != nil {
			return rep, fmt.Errorf("clé du journal %s : %w", day, err)
		}
		nw, err := dst.Wrap(dek, querylog.KeyAAD(day))
		secmem.Wipe(dek)
		if err != nil {
			return rep, fmt.Errorf("clé du journal %s : %w", day, err)
		}
		plan = append(plan, staged{path, nw})
	}

	// Écriture des nouvelles versions à côté des originaux.
	for _, s := range plan {
		if err := writeSync(s.path+".migr", s.blob); err != nil {
			cleanup(plan)
			return rep, err
		}
	}
	// Sauvegarde des originaux, chiffrés par l'ancien keystore.
	rep.BackupDir = filepath.Join(dataDir, "migration-backup-"+time.Now().UTC().Format("20060102-150405"))
	for _, s := range plan {
		rel, _ := filepath.Rel(dataDir, s.path)
		if err := copyFile(s.path, filepath.Join(rep.BackupDir, rel)); err != nil {
			cleanup(plan)
			return rep, fmt.Errorf("sauvegarde de %s : %w", rel, err)
		}
	}
	// Bascule : renommages atomiques un par un.
	for i, s := range plan {
		if err := os.Rename(s.path+".migr", s.path); err != nil {
			return rep, fmt.Errorf("%w après %d fichiers sur %d (originaux dans %s) : %v", ErrPartial, i, len(plan), rep.BackupDir, err)
		}
		rel, _ := filepath.Rel(dataDir, s.path)
		rep.Files = append(rep.Files, rel)
	}
	return rep, nil
}

// RetireSoftware renomme le keystore logiciel une fois la migration faite :
// il n'est plus utilisé mais reste disponible jusqu'à sa destruction
// explicite depuis l'interface.
func RetireSoftware(dir string) (string, error) {
	dst := strings.TrimRight(dir, "/") + ".retired-" + time.Now().UTC().Format("20060102-150405")
	return dst, os.Rename(dir, dst)
}

// DestroyRetired écrase puis supprime chaque fichier d'un keystore retiré
// (et d'une sauvegarde de migration). Sur SSD ou système de fichiers en
// copie sur écriture, l'écrasement est au mieux : la clé maître reste
// néanmoins dérivée d'une phrase de passe qui n'est plus fournie.
func DestroyRetired(dir string) error {
	if !strings.Contains(filepath.Base(dir), ".retired-") && !strings.HasPrefix(filepath.Base(dir), "migration-backup-") {
		return errors.New("seuls un keystore retiré ou une sauvegarde de migration peuvent être détruits")
	}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !d.Type().IsRegular() {
			return os.Remove(p) // lien symbolique : on retire le lien, jamais sa cible
		}
		return sealed.Shred(p)
	})
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

func writeSync(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func cleanup(plan []staged) {
	for _, s := range plan {
		_ = os.Remove(s.path + ".migr")
	}
}
