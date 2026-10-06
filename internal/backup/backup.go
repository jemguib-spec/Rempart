// Package backup crée, vérifie et restaure les sauvegardes de Rempart.
//
// Une sauvegarde est une archive tar.gz du dossier de données et du keystore
// logiciel, suivie d'un manifeste (MANIFEST.json) qui donne l'empreinte
// SHA-256 de chaque fichier. Rien n'y est en clair qui ne l'était déjà sur
// disque : l'état, les baux, la tête d'audit et les clés du journal sont
// scellés ; le keystore logiciel est protégé par la phrase de passe ou le
// quorum. L'archive n'ajoute aucun chiffrement : elle se range comme le
// dossier de données lui-même.
//
// Limites, à connaître avant de restaurer :
//   - les données chiffrées par une génération de KEK détruite depuis la
//     sauvegarde restent lisibles avec le master.json de l'archive, pas avec
//     celui d'aujourd'hui (et inversement) : on restaure toujours le couple
//     données + keystore de la même archive ;
//   - les jours du journal des requêtes dont la clé a été détruite (rétention)
//     sont illisibles, par construction (effacement cryptographique) ;
//   - avec un HSM, l'archive ne contient pas les clés : il faut aussi la
//     sauvegarde du token par le mécanisme du constructeur.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	manifestName = "MANIFEST.json"
	maxFile      = 1 << 30 // 1 Gio par fichier
)

// Manifest décrit une sauvegarde.
type Manifest struct {
	Format    int               `json:"format"`
	Version   string            `json:"version"` // version de Rempart
	Created   time.Time         `json:"created"`
	Backend   string            `json:"backend"` // software | pkcs11
	KeyDetail string            `json:"keystore"`
	KEKGen    uint32            `json:"kek_generation,omitempty"`
	AuditSeq  uint64            `json:"audit_seq"`
	Files     map[string]string `json:"files"` // chemin dans l'archive → SHA-256
}

// Source : ce qu'il faut sauvegarder.
type Source struct {
	DataDir     string
	KeystoreDir string // keystore logiciel ("" avec un HSM)
	SkipLists   bool   // copies des listes de blocage (retéléchargeables)
}

// skip : fichiers jamais sauvegardés.
func skip(rel string, isDir bool, src Source) bool {
	base := path.Base(rel)
	switch {
	case strings.HasPrefix(base, "migration-backup-"), strings.Contains(base, ".illisible-"),
		strings.HasPrefix(base, AsidePrefix), strings.HasPrefix(base, TempPrefix),
		strings.HasSuffix(base, ".tmp"), strings.HasSuffix(base, ".sock"):
		return true
	case src.SkipLists && isDir && rel == "data/lists":
		return true
	}
	return false
}

// Create écrit l'archive. L'appelant empêche les rotations de KEK pendant la
// copie (sinon données et keystore pourraient venir de générations différentes).
func Create(w io.Writer, src Source, m Manifest) (Manifest, error) {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	m.Format, m.Created, m.Files = 1, time.Now().UTC(), map[string]string{}
	add := func(root, prefix string, exclude string) error {
		return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if exclude != "" && p == exclude {
				return filepath.SkipDir
			}
			relp, _ := filepath.Rel(root, p)
			rel := path.Join(prefix, filepath.ToSlash(relp))
			if skip(rel, d.IsDir(), src) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil // dossiers recréés à la restauration ; ni liens ni sockets
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if info.Size() > maxFile {
				return fmt.Errorf("%s : fichier trop volumineux", rel)
			}
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			h := sha256.New()
			hdr := &tar.Header{Name: rel, Mode: 0o600, Size: info.Size(), ModTime: info.ModTime(), Typeflag: tar.TypeReg}
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			// Taille relevée à l'ouverture : un journal qui grandit pendant
			// la copie est sauvegardé jusqu'à ce point (ses ajouts sont des
			// lignes complètes, écrites d'un bloc).
			if n, err := io.CopyN(io.MultiWriter(tw, h), f, info.Size()); err != nil || n != info.Size() {
				return fmt.Errorf("%s : copie incomplète (fichier tronqué pendant la sauvegarde ?)", rel)
			}
			m.Files[rel] = hex.EncodeToString(h.Sum(nil))
			return nil
		})
	}
	ksAbs, _ := filepath.Abs(src.KeystoreDir)
	dataAbs, _ := filepath.Abs(src.DataDir)
	exclude := ""
	if src.KeystoreDir != "" && strings.HasPrefix(ksAbs, dataAbs+string(filepath.Separator)) {
		exclude = src.KeystoreDir // sauvegardé une seule fois, sous keystore/
	}
	if err := add(src.DataDir, "data", exclude); err != nil {
		return m, err
	}
	if src.KeystoreDir != "" {
		if err := add(src.KeystoreDir, "keystore", ""); err != nil {
			return m, err
		}
	}
	raw, _ := json.MarshalIndent(m, "", "  ")
	if err := tw.WriteHeader(&tar.Header{Name: manifestName, Mode: 0o600, Size: int64(len(raw)), ModTime: m.Created, Typeflag: tar.TypeReg}); err != nil {
		return m, err
	}
	if _, err := tw.Write(raw); err != nil {
		return m, err
	}
	if err := tw.Close(); err != nil {
		return m, err
	}
	return m, gz.Close()
}

// safeName refuse les chemins absolus, les remontées et les noms inattendus.
func safeName(name string) (string, error) {
	clean := path.Clean(name)
	if clean != name || path.IsAbs(clean) || strings.HasPrefix(clean, "..") || strings.Contains(clean, "\\") {
		return "", fmt.Errorf("chemin refusé dans l'archive : %q", name)
	}
	if clean != manifestName && !strings.HasPrefix(clean, "data/") && !strings.HasPrefix(clean, "keystore/") {
		return "", fmt.Errorf("entrée inattendue dans l'archive : %q", name)
	}
	return clean, nil
}

// Extract vérifie l'archive (empreintes du manifeste, chemins) et l'extrait
// dans dir, en data/ et keystore/. Rien n'est extrait hors de dir.
func Extract(r io.Reader, dir string) (Manifest, error) {
	var m Manifest
	gz, err := gzip.NewReader(r)
	if err != nil {
		return m, fmt.Errorf("archive illisible : %w", err)
	}
	tr := tar.NewReader(gz)
	sums := map[string]string{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, fmt.Errorf("archive illisible : %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			return m, fmt.Errorf("entrée non régulière refusée : %q", hdr.Name)
		}
		name, err := safeName(hdr.Name)
		if err != nil {
			return m, err
		}
		if hdr.Size > maxFile {
			return m, fmt.Errorf("%s : trop volumineux", name)
		}
		if name == manifestName {
			if err := json.NewDecoder(io.LimitReader(tr, 16<<20)).Decode(&m); err != nil {
				return m, fmt.Errorf("manifeste illisible : %w", err)
			}
			continue
		}
		if _, dup := sums[name]; dup {
			return m, fmt.Errorf("entrée en double : %q", name)
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return m, err
		}
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return m, err
		}
		h := sha256.New()
		_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(tr, hdr.Size))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return m, err
		}
		sums[name] = hex.EncodeToString(h.Sum(nil))
	}
	if m.Format != 1 {
		return m, errors.New("manifeste absent ou format inconnu : archive incomplète ?")
	}
	var missing []string
	for name, want := range m.Files {
		got, ok := sums[name]
		switch {
		case !ok:
			missing = append(missing, name)
		case got != want:
			return m, fmt.Errorf("%s : empreinte différente du manifeste (archive corrompue ou modifiée)", name)
		}
	}
	for name := range sums {
		if _, ok := m.Files[name]; !ok {
			return m, fmt.Errorf("%s : fichier absent du manifeste", name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return m, fmt.Errorf("fichiers manquants : %s", strings.Join(missing, ", "))
	}
	return m, nil
}

// Préfixes des dossiers créés par la restauration, dans le dossier cible
// (même système de fichiers, y compris quand c'est la racine d'un volume).
const (
	AsidePrefix = ".avant-restauration-"
	TempPrefix  = ".rempart-restauration-"
)

func ours(name string) bool {
	return strings.HasPrefix(name, AsidePrefix) || strings.HasPrefix(name, TempPrefix)
}

// moveContents déplace les entrées de from dans to (renommage ; copie puis
// suppression si les dossiers sont sur des systèmes de fichiers différents).
func moveContents(from, to string, filter func(string) bool) error {
	entries, err := os.ReadDir(from)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(to, 0o700); err != nil {
		return err
	}
	for _, e := range entries {
		if filter != nil && !filter(e.Name()) {
			continue
		}
		src, dst := filepath.Join(from, e.Name()), filepath.Join(to, e.Name())
		if err := os.Rename(src, dst); err != nil {
			if err := copyTree(src, dst); err != nil {
				return err
			}
			if err := os.RemoveAll(src); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
}

// Install met en place une extraction vérifiée. Un dossier cible non vide est
// refusé, sauf force : son contenu est alors déplacé dans un sous-dossier
// « .avant-restauration-<date> », jamais supprimé (le dossier de données
// peut être la racine d'un volume, qu'on ne peut pas renommer).
func Install(extracted, dataDir, keystoreDir string, force bool) ([]string, error) {
	var moved []string
	stamp := time.Now().UTC().Format("20060102-150405")
	type pair struct{ from, to string }
	pairs := []pair{{filepath.Join(extracted, "data"), dataDir}}
	if _, err := os.Stat(filepath.Join(extracted, "keystore")); err == nil {
		if keystoreDir == "" {
			return nil, errors.New("l'archive contient un keystore logiciel : indiquez son dossier (keystore.software.dir)")
		}
		pairs = append(pairs, pair{filepath.Join(extracted, "keystore"), keystoreDir})
	}
	for _, p := range pairs {
		entries, err := os.ReadDir(p.to)
		busy := 0
		for _, e := range entries {
			if !ours(e.Name()) {
				busy++
			}
		}
		if err == nil && busy > 0 {
			if !force {
				return moved, fmt.Errorf("%s n'est pas vide : arrêtez Rempart et relancez avec -force (le contenu actuel sera mis de côté)", p.to)
			}
			aside := filepath.Join(p.to, AsidePrefix+stamp)
			if err := moveContents(p.to, aside, func(n string) bool { return !ours(n) }); err != nil {
				return moved, err
			}
			moved = append(moved, aside)
		}
		if _, err := os.Stat(p.from); errors.Is(err, os.ErrNotExist) {
			continue // dossier de données vide dans l'archive
		}
		if err := moveContents(p.from, p.to, nil); err != nil {
			return moved, err
		}
	}
	return moved, nil
}
