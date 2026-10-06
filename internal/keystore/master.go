// master.go - format de master.json (v2) : protecteurs de la clé racine, trousseau, intégrité.
// Entrées/sorties : le fichier master.json du keystore logiciel, écrit de façon atomique.
// Rempart ; Argon2id (golang.org/x/crypto), HKDF et HMAC-SHA-256 de la bibliothèque standard.

package keystore

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/rempart-dns/rempart/internal/secmem"
	"golang.org/x/crypto/argon2"
)

const (
	ModeAuto   = "auto"   // démarrage par la phrase de passe serveur ; quorum pour les opérations sensibles
	ModeQuorum = "quorum" // démarrage verrouillé tant que M dépositaires ne se sont pas présentés

	// DefaultRotateDays : rotation annuelle de la KEK, rythme courant d'une
	// clé de chiffrement de clés (NIST SP 800-57 laisse jusqu'à 2 ans).
	DefaultRotateDays = 365

	kdfArgon2id = "argon2id"
	kdfNone     = "none"
)

// Paramètres Argon2id : deuxième recommandation de la RFC 9106 (§4),
// t=3, m=64 Mio, p=4. Les dérivations sont faites une à la fois pour
// qu'une rafale de demandes n'épuise pas la mémoire du conteneur.
const (
	argonT = 3
	argonM = 64 * 1024
	argonP = 4
)

var argonMu sync.Mutex

// ErrQuorumRequired : la clé racine ne peut être reconstituée que par le
// quorum des dépositaires (mode quorum, ou phrase de passe serveur absente).
var ErrQuorumRequired = errors.New("keystore verrouillé : le quorum des dépositaires est requis")

type masterBody struct {
	Version    int        `json:"version"`
	Mode       string     `json:"mode"`
	RootID     string     `json:"root_id"` // change à chaque nouvelle clé racine
	Created    time.Time  `json:"created"`
	Passphrase *box       `json:"passphrase,omitempty"` // absent en mode quorum
	Quorum     *quorumCfg `json:"quorum,omitempty"`
	Keyring    []kekEntry `json:"keyring"`
	Current    uint32     `json:"current"`
	RotateDays int        `json:"rotate_days"` // 0 : pas de rotation planifiée
}

type quorumCfg struct {
	Threshold    int         `json:"threshold"`
	TerminalOnly bool        `json:"terminal_only,omitempty"`
	Custodians   []custodian `json:"custodians"`
	Since        time.Time   `json:"since"`
}

type custodian struct {
	ID    string    `json:"id"`
	Name  string    `json:"name"`
	X     byte      `json:"x"`
	Added time.Time `json:"added"`
	Box   box       `json:"box"` // part chiffrée par la phrase de passe du dépositaire
	// TerminalSet : phrase fixée par le dépositaire lui-même au terminal
	// (rempart passwd), donc jamais passée par la session de l'administrateur.
	TerminalSet bool `json:"terminal_set,omitempty"`
}

type kekEntry struct {
	Gen     uint32     `json:"gen"`
	Created time.Time  `json:"created"`
	Retired *time.Time `json:"retired,omitempty"` // plus aucune donnée ne l'utilise
	Data    string     `json:"data"`              // KEK chiffrée par la clé racine
}

// box : un secret chiffré en AES-256-GCM par une clé dérivée d'une phrase
// de passe (Argon2id). Data = nonce | chiffré, en base64. kdf "none" : le
// secret est en clair (keystore sans phrase de passe).
type box struct {
	KDF  string `json:"kdf"`
	Salt string `json:"salt,omitempty"`
	T    uint32 `json:"t,omitempty"`
	M    uint32 `json:"m,omitempty"`
	P    uint8  `json:"p,omitempty"`
	Data string `json:"data"`
}

// derive calcule la clé d'une boîte. Les paramètres viennent de master.json,
// lu avant toute vérification d'intégrité : ils sont bornés pour qu'un
// fichier modifié ne provoque ni panique ni épuisement de la mémoire.
func (b *box) derive(pass string) ([]byte, error) {
	if err := argonBounds(b.T, b.M, b.P); err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(b.Salt)
	if err != nil || len(salt) < 16 {
		return nil, errors.New("master.json : sel Argon2id invalide")
	}
	argonMu.Lock()
	defer argonMu.Unlock()
	k := argon2.IDKey([]byte(pass), salt, b.T, b.M, b.P, 32)
	secmem.Lock(k)
	return k, nil
}

func argonBounds(t, m uint32, p uint8) error {
	if t < 1 || t > 16 || m < 8*1024 || m > 1024*1024 || p < 1 || p > 16 {
		return errors.New("master.json : paramètres Argon2id hors bornes")
	}
	return nil
}

// burnArgon fait le même travail qu'une vraie dérivation, pour qu'un nom
// de dépositaire inconnu ne se distingue pas au chronomètre.
func burnArgon(pass string) {
	salt := make([]byte, 16)
	argonMu.Lock()
	k := argon2.IDKey([]byte(pass), salt, argonT, argonM, argonP, 32)
	argonMu.Unlock()
	secmem.Wipe(k)
}

func (b *box) open(key, aad []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b.Data)
	if err != nil {
		return nil, err
	}
	pt, err := aeadOpen(key, raw, aad)
	if err == nil {
		secmem.Lock(pt)
	}
	return pt, err
}

// sealWithPassphrase chiffre secret par une clé dérivée de pass avec un sel
// neuf ; renvoie aussi la clé dérivée (gardée en mémoire en mode auto pour
// rechiffrer une future clé racine).
func sealWithPassphrase(pass string, secret, aad []byte) (*box, []byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	b := &box{KDF: kdfArgon2id, Salt: base64.StdEncoding.EncodeToString(salt), T: argonT, M: argonM, P: argonP}
	k, err := b.derive(pass)
	if err != nil {
		return nil, nil, err
	}
	if err := b.seal(k, secret, aad); err != nil {
		secmem.Wipe(k)
		return nil, nil, err
	}
	return b, k, nil
}

func (b *box) seal(key, secret, aad []byte) error {
	ct, err := aeadSeal(key, secret, aad)
	if err != nil {
		return err
	}
	b.Data = base64.StdEncoding.EncodeToString(ct)
	return nil
}

func aeadSeal(key, pt, aad []byte) ([]byte, error) {
	a, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return a.Seal(nonce, nonce, pt, aad), nil
}

func aeadOpen(key, ct, aad []byte) ([]byte, error) {
	a, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(ct) < a.NonceSize()+a.Overhead() {
		return nil, errors.New("bloc chiffré tronqué")
	}
	return a.Open(nil, ct[:a.NonceSize()], ct[a.NonceSize():], aad)
}

// Données associées : chaque bloc est lié à la clé racine qui l'a produit
// et à son rôle, pour qu'aucun ne puisse être déplacé ou rejoué ailleurs.
func rootAAD(rootID, role string) []byte { return []byte("rempart-root:" + rootID + ":" + role) }
func shareAAD(rootID, id string, x byte) []byte {
	return []byte("rempart-share:" + rootID + ":" + id + ":" + strconv.Itoa(int(x)))
}
func kekAAD(rootID string, gen uint32) []byte {
	return []byte("rempart-kek:" + rootID + ":" + strconv.FormatUint(uint64(gen), 10))
}

// Clés dérivées de la clé racine (HKDF-SHA-256, RFC 5869) : une pour
// chiffrer le trousseau, une pour l'intégrité de master.json.
func rootSubkey(root []byte, purpose string) []byte {
	k, err := hkdf.Key(sha256.New, root, nil, "rempart/root/"+purpose, 32)
	if err != nil {
		panic(err) // longueur fixe et valide : ne peut pas échouer
	}
	secmem.Lock(k)
	return k
}

func sealKEK(root []byte, rootID string, gen uint32, kek []byte) (kekEntry, error) {
	k := rootSubkey(root, "enc")
	defer secmem.Wipe(k)
	ct, err := aeadSeal(k, kek, kekAAD(rootID, gen))
	if err != nil {
		return kekEntry{}, err
	}
	return kekEntry{Gen: gen, Created: now(), Data: base64.StdEncoding.EncodeToString(ct)}, nil
}

func openKeyring(root []byte, b *masterBody) (map[uint32]cipher.AEAD, error) {
	k := rootSubkey(root, "enc")
	defer secmem.Wipe(k)
	out := map[uint32]cipher.AEAD{}
	for _, e := range b.Keyring {
		ct, err := base64.StdEncoding.DecodeString(e.Data)
		if err != nil {
			return nil, err
		}
		kek, err := aeadOpen(k, ct, kekAAD(b.RootID, e.Gen))
		if err != nil {
			return nil, fmt.Errorf("KEK génération %d : %w", e.Gen, err)
		}
		a, err := gcm(kek)
		secmem.Wipe(kek)
		if err != nil {
			return nil, err
		}
		out[e.Gen] = a
	}
	return out, nil
}

// ---- fichier ----

// masterFile : le corps est authentifié par HMAC-SHA-256 sous une clé tirée
// de la clé racine. Le corps est gardé octet pour octet tel qu'écrit : pas
// de canonicalisation JSON à reproduire.
type masterFile struct {
	body *masterBody
	raw  []byte // corps tel que lu sur disque
	mac  []byte
}

type masterEnvelope struct {
	Format string          `json:"format"`
	Body   json.RawMessage `json:"body"`
	MAC    string          `json:"mac"`
}

const masterFormat = "rempart-keystore-v2"

func masterPath(dir string) string { return filepath.Join(dir, "master.json") }

func parseMaster(raw []byte) (*masterFile, error) {
	var env masterEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Format != masterFormat {
		return nil, errors.New("master.json illisible ou de format inconnu")
	}
	mac, err := hex.DecodeString(env.MAC)
	if err != nil || len(mac) != sha256.Size {
		return nil, errors.New("master.json : empreinte d'intégrité invalide")
	}
	var b masterBody
	if err := json.Unmarshal(env.Body, &b); err != nil {
		return nil, fmt.Errorf("master.json illisible : %w", err)
	}
	if b.Version != 2 {
		return nil, fmt.Errorf("master.json : version %d inconnue", b.Version)
	}
	return &masterFile{body: &b, raw: env.Body, mac: mac}, nil
}

func (m *masterFile) verify(root []byte) bool {
	k := rootSubkey(root, "mac")
	defer secmem.Wipe(k)
	h := hmac.New(sha256.New, k)
	h.Write(m.raw)
	return hmac.Equal(h.Sum(nil), m.mac)
}

// write sérialise, authentifie et remplace master.json de façon atomique
// (fichier temporaire, fsync, renommage, fsync du dossier).
func (m *masterFile) write(dir string, root []byte) error {
	body, err := json.Marshal(m.body)
	if err != nil {
		return err
	}
	k := rootSubkey(root, "mac")
	h := hmac.New(sha256.New, k)
	h.Write(body)
	mac := h.Sum(nil)
	secmem.Wipe(k)
	out, err := json.Marshal(masterEnvelope{Format: masterFormat, Body: body, MAC: hex.EncodeToString(mac)})
	if err != nil {
		return err
	}
	tmp := masterPath(dir) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(out, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if err := os.Rename(tmp, masterPath(dir)); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	m.raw, m.mac = body, mac
	return nil
}

func now() time.Time { return time.Now().UTC().Truncate(time.Second) }

// ---- master.json v1 (phrase de passe → clé maître directement) ----

type legacyMaster struct {
	KDF    string `json:"kdf"`
	Salt   string `json:"salt,omitempty"`
	Time   uint32 `json:"t,omitempty"`
	Memory uint32 `json:"m,omitempty"`
	Thread uint8  `json:"p,omitempty"`
	Key    string `json:"key,omitempty"`
	Check  string `json:"check,omitempty"`
}

func isLegacyMaster(raw []byte) bool {
	var probe struct {
		Format string `json:"format"`
		KDF    string `json:"kdf"`
	}
	return json.Unmarshal(raw, &probe) == nil && probe.Format == "" && probe.KDF != ""
}

// upgradeLegacy convertit un master.json v1 : l'ancienne clé maître devient
// la KEK de génération 0 (les données existantes restent lisibles), une clé
// racine neuve la protège, une génération 1 neuve chiffre tout ce qui
// s'écrit ensuite. L'ancien fichier est remplacé : il ne doit pas survivre,
// il permettrait de recalculer la génération 0.
func upgradeLegacy(dir string, raw []byte, passphrase string) (*Software, string, error) {
	var lm legacyMaster
	if err := json.Unmarshal(raw, &lm); err != nil {
		return nil, "", fmt.Errorf("master.json illisible: %w", err)
	}
	var master []byte
	var err error
	switch lm.KDF {
	case kdfNone:
		master, err = base64.StdEncoding.DecodeString(lm.Key)
		if err != nil {
			return nil, "", err
		}
	case kdfArgon2id:
		if passphrase == "" {
			return nil, "", errors.New("le keystore est protégé : définissez REMPART_KEYSTORE_PASSPHRASE (ou keystore.passphrase_file)")
		}
		salt, err := base64.StdEncoding.DecodeString(lm.Salt)
		if err != nil {
			return nil, "", err
		}
		if err := argonBounds(lm.Time, lm.Memory, lm.Thread); err != nil {
			return nil, "", err
		}
		argonMu.Lock()
		master = argon2.IDKey([]byte(passphrase), salt, lm.Time, lm.Memory, lm.Thread, 32)
		argonMu.Unlock()
	default:
		return nil, "", fmt.Errorf("kdf inconnu %q", lm.KDF)
	}
	secmem.Lock(master)
	defer secmem.Wipe(master)
	// Contrôle de la phrase avec la valeur témoin v1.
	chk, _ := base64.StdEncoding.DecodeString(lm.Check)
	a, err := gcm(master)
	if err != nil {
		return nil, "", err
	}
	if len(chk) < 1+a.NonceSize() || chk[0] != 1 {
		return nil, "", errors.New("master.json v1 : valeur témoin invalide")
	}
	if pt, err := a.Open(nil, chk[1:1+a.NonceSize()], chk[1+a.NonceSize():], []byte("check")); err != nil || string(pt) != "rempart" {
		return nil, "", errors.New("phrase de passe du keystore incorrecte")
	}

	root, err := randomKey()
	if err != nil {
		return nil, "", err
	}
	b := &masterBody{Version: 2, Mode: ModeAuto, RootID: randomID(), Created: now(), RotateDays: DefaultRotateDays}
	var pk []byte
	var warning string
	if lm.KDF == kdfNone {
		b.Passphrase = &box{KDF: kdfNone, Data: base64.StdEncoding.EncodeToString(root)}
		warning = "keystore logiciel SANS phrase de passe : la clé racine est stockée en clair dans " + masterPath(dir)
	} else {
		bx, k, err := sealWithPassphrase(passphrase, root, rootAAD(b.RootID, "passphrase"))
		if err != nil {
			return nil, "", err
		}
		b.Passphrase, pk = bx, k
	}
	e, err := sealKEK(root, b.RootID, 0, master)
	if err != nil {
		return nil, "", err
	}
	b.Keyring = []kekEntry{e}
	// Les nouvelles données ne doivent plus dépendre de l'ancienne clé maître
	// (recalculable depuis une sauvegarde v1) : la génération 1 est en service
	// dès la conversion ; la maintenance rechiffre ensuite les données de la
	// génération 0, que l'interface propose alors de détruire.
	if err := addGeneration(root, b, map[uint32]cipher.AEAD{}); err != nil {
		return nil, "", err
	}
	mf := &masterFile{body: b}
	if err := mf.write(dir, root); err != nil {
		return nil, "", err
	}
	s, err := newSoftware(dir, mf, root, pk)
	if err != nil {
		return nil, "", err
	}
	// master.json v1 est remplacé par le renommage atomique de write ; une
	// copie restée sur disque (sauvegarde manuelle d'une version antérieure)
	// permettrait de recalculer la génération 0 : on l'efface si elle existe.
	if err := shred(masterPath(dir) + ".v1"); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.Close()
		return nil, "", err
	}
	return s, warning, nil
}
