// Package sealed implements envelope encryption: data is encrypted with a
// fresh random AES-256-GCM data key, and that data key is wrapped by the
// keystore (inside the HSM when one is configured).
package sealed

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"

	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/secmem"
)

var magic = []byte("RMPS1")

// NewDataKey returns a random 32-byte key, locked in memory.
func NewDataKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	secmem.Lock(k)
	return k
}

// AEAD builds an AES-256-GCM cipher from a data key.
func AEAD(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// Seal encrypts data; aad binds the ciphertext to its purpose (e.g. the file
// name) so that files cannot be swapped.
func Seal(ks keystore.Keystore, data, aad []byte) ([]byte, error) {
	dek := NewDataKey()
	defer secmem.Wipe(dek)
	wrapped, err := ks.Wrap(dek, aad)
	if err != nil {
		return nil, err
	}
	a, err := AEAD(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Write(magic)
	_ = binary.Write(&buf, binary.BigEndian, uint16(len(wrapped)))
	buf.Write(wrapped)
	buf.Write(nonce)
	buf.Write(a.Seal(nil, nonce, data, aad))
	return buf.Bytes(), nil
}

// Open decrypts what Seal produced.
func Open(ks keystore.Keystore, blob, aad []byte) ([]byte, error) {
	if len(blob) < len(magic)+2 || !bytes.Equal(blob[:len(magic)], magic) {
		return nil, errors.New("fichier scellé invalide")
	}
	p := blob[len(magic):]
	n := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) < n+12 {
		return nil, errors.New("fichier scellé tronqué")
	}
	dek, err := ks.Unwrap(p[:n], aad)
	if err != nil {
		return nil, err
	}
	defer secmem.Wipe(dek)
	a, err := AEAD(dek)
	if err != nil {
		return nil, err
	}
	p = p[n:]
	return a.Open(nil, p[:a.NonceSize()], p[a.NonceSize():], aad)
}

// FileAAD lie un fichier scellé à son nom : deux fichiers ne peuvent pas
// être échangés sur le disque.
func FileAAD(path string) []byte { return []byte("rempart-file:" + filepath.Base(path)) }

// WrappedKey renvoie la clé de données chiffrée par le keystore en tête
// d'un fichier scellé (pour savoir quelle génération de KEK l'a chiffrée).
func WrappedKey(blob []byte) ([]byte, bool) {
	if len(blob) < len(magic)+2 || !bytes.Equal(blob[:len(magic)], magic) {
		return nil, false
	}
	p := blob[len(magic):]
	n := int(binary.BigEndian.Uint16(p))
	if len(p) < 2+n {
		return nil, false
	}
	return p[2 : 2+n], true
}

// IsSealed indique si le contenu commence par l'en-tête des fichiers scellés.
func IsSealed(blob []byte) bool { return bytes.HasPrefix(blob, magic) }

// WriteFile seals data and writes it atomically.
func WriteFile(ks keystore.Keystore, path string, data []byte) error {
	blob, err := Seal(ks, data, FileAAD(path))
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	// Sans Sync, un arrêt brutal juste après le renommage peut laisser un
	// fichier vide à la place de l'état précédent.
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// ReadFile reads and opens a sealed file.
func ReadFile(ks keystore.Keystore, path string) ([]byte, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Open(ks, blob, FileAAD(path))
}

// Shred overwrites a file with random bytes before removing it. On SSDs and
// copy-on-write filesystems this is best effort, which is why Rempart relies
// on crypto-shredding (destroying keys) rather than on overwriting data.
func Shred(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return os.Remove(path) // ne jamais écraser la cible d'un lien
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
