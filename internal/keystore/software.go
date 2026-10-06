// software.go - keystore logiciel : clé racine, trousseau de KEK et clés de signature.
// Entrées : dossier du keystore, phrase de passe serveur ou parts du quorum ;
// sorties : Wrap/Unwrap et crypto.Signer. Rempart, sans HSM.

package keystore

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/rempart-dns/rempart/internal/secmem"
)

var labelRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// ValidLabel reports whether a key label is acceptable.
func ValidLabel(l string) bool { return labelRe.MatchString(l) }

// Software est un keystore sur fichiers. Hiérarchie (voir master.go) :
// phrase de passe serveur et/ou quorum → clé racine → KEK par génération →
// clés de données et clés de signature.
type Software struct {
	dir string

	kmu  sync.RWMutex
	body *masterBody
	root []byte // clé racine, verrouillée en mémoire
	pk   []byte // clé dérivée de la phrase de passe serveur (mode auto), sinon nil
	keks map[uint32]cipher.AEAD
	// superseded : générations remplacées par la dernière reconfiguration,
	// que PurgeSuperseded peut détruire sans nouvelle approbation.
	superseded map[uint32]bool

	mu   sync.Mutex
	keys map[string]crypto.Signer
}

// OpenSoftware ouvre (ou crée) un keystore logiciel avec la phrase de passe
// du serveur. Une phrase vide garde la clé racine en clair (fichier 0600) :
// acceptable seulement pour les tests et un usage domestique ; un
// avertissement est alors renvoyé. En mode quorum, ErrQuorumRequired est
// renvoyée : le keystore s'ouvre par un Unsealer.
func OpenSoftware(dir, passphrase string) (*Software, string, error) {
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		return nil, "", err
	}
	raw, err := os.ReadFile(masterPath(dir))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return createSoftware(dir, passphrase)
	case err != nil:
		return nil, "", err
	}
	if isLegacyMaster(raw) {
		return upgradeLegacy(dir, raw, passphrase)
	}
	mf, err := parseMaster(raw)
	if err != nil {
		return nil, "", err
	}
	b := mf.body
	if b.Mode == ModeQuorum || b.Passphrase == nil || (passphrase == "" && b.Passphrase.KDF != kdfNone && b.Quorum != nil) {
		return nil, "", ErrQuorumRequired
	}
	var warning string
	var root, pk []byte
	if b.Passphrase.KDF == kdfNone {
		root, err = base64.StdEncoding.DecodeString(b.Passphrase.Data)
		if err != nil {
			return nil, "", err
		}
		secmem.Lock(root)
		if passphrase == "" {
			warning = "keystore logiciel SANS phrase de passe : la clé racine est stockée en clair dans " + masterPath(dir)
		} else {
			// Une phrase est fournie pour un keystore créé sans. L'ancienne
			// racine a existé en clair (disque, sauvegardes) : on passe à une
			// racine et une KEK neuves, protégées par la phrase ; la
			// maintenance rechiffre les données puis détruit les anciennes KEK.
			s, err := newSoftware(dir, mf, root, nil)
			if err != nil {
				return nil, "", err
			}
			if err := s.Reconfigure(Reconfig{Mode: ModeAuto, ServerPassphrase: passphrase}, nil); err != nil {
				s.Close()
				return nil, "", err
			}
			return s, "keystore désormais protégé par la phrase de passe fournie (nouvelle clé racine, nouvelle KEK)", nil
		}
	} else {
		if passphrase == "" {
			return nil, "", errors.New("le keystore est protégé : définissez REMPART_KEYSTORE_PASSPHRASE (ou keystore.passphrase_file)")
		}
		if pk, err = b.Passphrase.derive(passphrase); err != nil {
			return nil, "", err
		}
		root, err = b.Passphrase.open(pk, rootAAD(b.RootID, "passphrase"))
		if err != nil {
			secmem.Wipe(pk)
			return nil, "", errors.New("phrase de passe du keystore incorrecte")
		}
	}
	s, err := newSoftware(dir, mf, root, pk)
	if err != nil {
		return nil, "", err
	}
	return s, warning, nil
}

func createSoftware(dir, passphrase string) (*Software, string, error) {
	root, err := randomKey()
	if err != nil {
		return nil, "", err
	}
	kek, err := randomKey()
	if err != nil {
		return nil, "", err
	}
	b := &masterBody{Version: 2, Mode: ModeAuto, RootID: randomID(), Created: now(), RotateDays: DefaultRotateDays, Current: 1}
	var pk []byte
	var warning string
	if passphrase == "" {
		b.Passphrase = &box{KDF: kdfNone, Data: base64.StdEncoding.EncodeToString(root)}
		warning = "keystore logiciel SANS phrase de passe : la clé racine est stockée en clair dans " + masterPath(dir)
	} else {
		bx, k, err := sealWithPassphrase(passphrase, root, rootAAD(b.RootID, "passphrase"))
		if err != nil {
			return nil, "", err
		}
		b.Passphrase, pk = bx, k
	}
	e, err := sealKEK(root, b.RootID, 1, kek)
	secmem.Wipe(kek)
	if err != nil {
		return nil, "", err
	}
	b.Keyring = []kekEntry{e}
	mf := &masterFile{body: b}
	if err := mf.write(dir, root); err != nil {
		return nil, "", err
	}
	s, err := newSoftware(dir, mf, root, pk)
	return s, warning, err
}

// newSoftware vérifie l'intégrité de master.json avec la clé racine (une
// clé racine fausse, issue d'une mauvaise phrase ou de parts erronées, est
// rejetée ici), puis déchiffre le trousseau.
func newSoftware(dir string, mf *masterFile, root, pk []byte) (*Software, error) {
	secmem.Lock(root)
	if pk != nil {
		secmem.Lock(pk)
	}
	fail := func(err error) (*Software, error) {
		secmem.Wipe(root)
		secmem.Wipe(pk)
		return nil, err
	}
	if mf.mac != nil && !mf.verify(root) {
		return fail(errors.New("clé racine incorrecte ou master.json modifié"))
	}
	keks, err := openKeyring(root, mf.body)
	if err != nil {
		return fail(err)
	}
	if _, ok := keks[mf.body.Current]; !ok {
		return fail(fmt.Errorf("génération de KEK courante %d absente du trousseau", mf.body.Current))
	}
	// Un master.json v1 resté sur disque permettrait de recalculer la KEK
	// de génération 0 avec l'ancienne phrase de passe.
	if err := shred(masterPath(dir) + ".v1"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	return &Software{dir: dir, body: mf.body, root: root, pk: pk, keks: keks, keys: map[string]crypto.Signer{}}, nil
}

func (s *Software) Backend() string  { return "software" }
func (s *Software) Describe() string { return "logiciel (" + s.dir + ")" }

// Format des blocs chiffrés : version 1 (historique, génération 0) =
// 0x01 | nonce | ct ; version 2 = 0x02 | génération (4 octets) | nonce | ct.
func (s *Software) Wrap(plaintext, aad []byte) ([]byte, error) {
	s.kmu.RLock()
	gen := s.body.Current
	a := s.keks[gen]
	s.kmu.RUnlock()
	if a == nil {
		return nil, errors.New("keystore fermé")
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 5, 5+len(nonce)+len(plaintext)+a.Overhead())
	out[0] = 2
	binary.BigEndian.PutUint32(out[1:5], gen)
	out = append(out, nonce...)
	return a.Seal(out, nonce, plaintext, aad), nil
}

func (s *Software) Unwrap(ct, aad []byte) ([]byte, error) {
	gen, body, ok := WrapGeneration(ct)
	if !ok {
		return nil, errors.New("données chiffrées invalides")
	}
	s.kmu.RLock()
	a, ok := s.keks[gen]
	s.kmu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("génération de KEK %d inconnue ou détruite", gen)
	}
	ns := a.NonceSize()
	if len(body) < ns+a.Overhead() {
		return nil, errors.New("données chiffrées invalides")
	}
	return a.Open(nil, body[:ns], body[ns:], aad)
}

// WrapGeneration renvoie la génération de KEK d'un bloc produit par Wrap
// et le reste du bloc (nonce et chiffré).
func WrapGeneration(ct []byte) (gen uint32, rest []byte, ok bool) {
	switch {
	case len(ct) > 1 && ct[0] == 1:
		return 0, ct[1:], true
	case len(ct) > 5 && ct[0] == 2:
		return binary.BigEndian.Uint32(ct[1:5]), ct[5:], true
	}
	return 0, nil, false
}

// IsCurrent indique si un bloc est chiffré par la KEK courante.
func (s *Software) IsCurrent(ct []byte) bool {
	gen, _, ok := WrapGeneration(ct)
	s.kmu.RLock()
	defer s.kmu.RUnlock()
	return ok && gen == s.body.Current
}

func randomKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	secmem.Lock(k)
	return k, nil
}

func randomID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func (s *Software) keyPath(label string) string {
	return filepath.Join(s.dir, "keys", label+".key")
}

func (s *Software) Signer(label string, alg Algorithm, create bool) (crypto.Signer, error) {
	if !ValidLabel(label) {
		return nil, fmt.Errorf("label de clé invalide %q", label)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, ok := s.keys[label]; ok {
		return k, nil
	}
	raw, err := os.ReadFile(s.keyPath(label))
	if err == nil {
		der, err := s.Unwrap(raw, []byte("rempart-key:"+label))
		if err != nil {
			return nil, fmt.Errorf("clé %s: %w", label, err)
		}
		secmem.Lock(der)
		k, err := x509.ParsePKCS8PrivateKey(der)
		secmem.Wipe(der)
		if err != nil {
			return nil, err
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("clé non signante")
		}
		s.keys[label] = signer
		return signer, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if !create {
		return nil, ErrNotFound
	}
	var signer crypto.Signer
	switch alg {
	case ECDSAP256:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ECDSAP384:
		signer, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case Ed25519:
		_, signer, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, fmt.Errorf("algorithme %q non supporté", alg)
	}
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, err
	}
	ct, err := s.Wrap(der, []byte("rempart-key:"+label))
	secmem.Wipe(der)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(s.keyPath(label), ct, 0o600); err != nil {
		return nil, err
	}
	s.keys[label] = signer
	return signer, nil
}

func (s *Software) Keys() []KeyInfo {
	entries, _ := os.ReadDir(filepath.Join(s.dir, "keys"))
	out := []KeyInfo{}
	for _, e := range entries {
		label, ok := strings.CutSuffix(e.Name(), ".key")
		if !ok {
			continue
		}
		k, err := s.Signer(label, "", false)
		if err != nil {
			continue
		}
		alg, _ := AlgorithmOf(k.Public())
		out = append(out, KeyInfo{Label: label, Algorithm: alg, Backend: "software", Fingerprint: Fingerprint(k.Public()), Origin: "logiciel"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// Destroy écrase puis supprime le fichier chiffré de la clé.
func (s *Software) Destroy(label string) error {
	if !ValidLabel(label) {
		return fmt.Errorf("label de clé invalide %q", label)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, label)
	err := shred(s.keyPath(label))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Dir renvoie le dossier du keystore (utilisé par la migration vers un HSM).
func (s *Software) Dir() string { return s.dir }

// privateKey renvoie la clé privée en mémoire ; réservé à la migration vers
// un HSM, qui l'importe comme objet non extractible.
func (s *Software) privateKey(label string) (crypto.Signer, error) {
	return s.Signer(label, "", false)
}

func shred(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return os.Remove(path)
	}
	if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		junk := make([]byte, fi.Size())
		_, _ = rand.Read(junk)
		_, _ = f.WriteAt(junk, 0)
		_ = f.Sync()
		f.Close()
	}
	return os.Remove(path)
}

func (s *Software) Close() error {
	s.kmu.Lock()
	secmem.Wipe(s.root)
	secmem.Wipe(s.pk)
	s.keks = map[uint32]cipher.AEAD{}
	s.kmu.Unlock()
	return nil
}

// Fingerprint returns a short SHA-256 fingerprint of a public key.
func Fingerprint(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "?"
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:12])
}
