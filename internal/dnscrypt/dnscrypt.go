// Package dnscrypt implémente le côté serveur du protocole DNSCrypt v2
// (https://dnscrypt.info/protocol) : certificats signés par la clé de
// fournisseur Ed25519 (dans le keystore, HSM compris), clés de résolveur
// X25519 éphémères renouvelées toutes les heures et jamais écrites sur
// disque, chiffrement XChaCha20-Poly1305 (et XSalsa20-Poly1305 pour les
// anciens clients), et tampon de serveur « sdns:// ».
package dnscrypt

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/poly1305"
)

// Constructions de chiffrement (es-version du certificat).
const (
	XSalsa20Poly1305  uint16 = 0x0001
	XChaCha20Poly1305 uint16 = 0x0002
)

const (
	clientMagicLen = 8
	pkLen          = 32
	halfNonce      = 12
	nonceLen       = 24
	tagLen         = 16
	queryHeader    = clientMagicLen + pkLen + halfNonce
	minDNS         = 12
	maxDNS         = 65535
	// KeyLifetime : durée de vie d'une clé de résolveur ; ses certificats
	// restent valables un peu plus, pour les clients qui les ont en cache.
	KeyLifetime  = time.Hour
	certValidity = 4 * time.Hour
)

var (
	certMagic   = []byte("DNSC")
	serverMagic = []byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
)

// resolverKey : clé X25519 de résolveur et ses certificats.
type resolverKey struct {
	sk, pk  [32]byte
	magic   [clientMagicLen]byte // une par construction : xsalsa, xchacha
	magicX  [clientMagicLen]byte
	serial  uint32
	created time.Time
	certs   [][]byte
}

// Server : clés en service. Sûr en accès concurrent.
type Server struct {
	ProviderName string        // « 2.dnscrypt-cert.exemple »
	Provider     crypto.Signer // Ed25519
	Now          func() time.Time

	mu   sync.RWMutex
	keys []*resolverKey // la plus récente en premier ; la précédente reste valable
}

// ErrNotDNSCrypt : le paquet n'est pas une requête DNSCrypt (requête DNS en
// clair, éventuellement la demande de certificat).
var ErrNotDNSCrypt = errors.New("pas une requête DNSCrypt")

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// New prépare un serveur et sa première clé de résolveur.
func New(providerName string, provider crypto.Signer) (*Server, error) {
	if _, ok := provider.Public().(ed25519.PublicKey); !ok {
		return nil, errors.New("la clé de fournisseur DNSCrypt doit être Ed25519")
	}
	name := strings.ToLower(strings.TrimSuffix(providerName, "."))
	if !strings.HasPrefix(name, "2.dnscrypt-cert.") || len(name) <= len("2.dnscrypt-cert.") {
		return nil, errors.New("le nom de fournisseur doit commencer par « 2.dnscrypt-cert. »")
	}
	s := &Server{ProviderName: name + ".", Provider: provider}
	if err := s.Rotate(); err != nil {
		return nil, err
	}
	return s, nil
}

// ProviderKey renvoie la clé publique du fournisseur.
func (s *Server) ProviderKey() ed25519.PublicKey { return s.Provider.Public().(ed25519.PublicKey) }

// Rotate crée une nouvelle clé de résolveur ; la précédente est gardée
// pour les requêtes en vol, les plus anciennes sont effacées.
func (s *Server) Rotate() error {
	k := &resolverKey{created: s.now()}
	if _, err := rand.Read(k.sk[:]); err != nil {
		return err
	}
	pk, err := curve25519.X25519(k.sk[:], curve25519.Basepoint)
	if err != nil {
		return err
	}
	copy(k.pk[:], pk)
	// Deux « magic » distincts, un par construction : le client désigne
	// ainsi la construction choisie.
	copy(k.magic[:], k.pk[:clientMagicLen])
	copy(k.magicX[:], k.pk[clientMagicLen:2*clientMagicLen])
	k.serial = uint32(k.created.Unix())
	for _, c := range []struct {
		es    uint16
		magic [clientMagicLen]byte
	}{{XChaCha20Poly1305, k.magicX}, {XSalsa20Poly1305, k.magic}} {
		cert, err := s.cert(k, c.es, c.magic)
		if err != nil {
			return err
		}
		k.certs = append(k.certs, cert)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.keys
	s.keys = []*resolverKey{k}
	if len(old) > 0 {
		s.keys = append(s.keys, old[0])
	}
	for _, o := range old[min(1, len(old)):] {
		clear(o.sk[:])
	}
	return nil
}

// cert construit un certificat (format DNSCrypt v2, 124 octets).
func (s *Server) cert(k *resolverKey, es uint16, magic [clientMagicLen]byte) ([]byte, error) {
	signed := make([]byte, 0, 52)
	signed = append(signed, k.pk[:]...)
	signed = append(signed, magic[:]...)
	signed = binary.BigEndian.AppendUint32(signed, k.serial)
	start := k.created.Add(-5 * time.Minute)
	signed = binary.BigEndian.AppendUint32(signed, uint32(start.Unix()))
	signed = binary.BigEndian.AppendUint32(signed, uint32(k.created.Add(certValidity).Unix()))
	sig, err := s.Provider.Sign(rand.Reader, signed, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("signature du certificat DNSCrypt : %w", err)
	}
	if !ed25519.Verify(s.ProviderKey(), signed, sig) {
		return nil, errors.New("signature du certificat DNSCrypt invalide")
	}
	out := append([]byte{}, certMagic...)
	out = binary.BigEndian.AppendUint16(out, es)
	out = binary.BigEndian.AppendUint16(out, 0) // version mineure
	out = append(out, sig...)
	return append(out, signed...), nil
}

// Certificates renvoie les certificats à publier (enregistrements TXT du
// nom de fournisseur).
func (s *Server) Certificates() [][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out [][]byte
	for _, k := range s.keys {
		out = append(out, k.certs...)
	}
	return out
}

// Session : contexte d'une requête déchiffrée, pour chiffrer la réponse.
type Session struct {
	es          uint16
	shared      [32]byte
	clientNonce [halfNonce]byte
}

func sharedKey(es uint16, sk, pk *[32]byte) ([32]byte, error) {
	var out [32]byte
	switch es {
	case XSalsa20Poly1305:
		box.Precompute(&out, pk, sk)
	case XChaCha20Poly1305:
		x, err := curve25519.X25519(sk[:], pk[:])
		if err != nil {
			return out, err
		}
		k, err := chacha20.HChaCha20(x, make([]byte, 16))
		if err != nil {
			return out, err
		}
		copy(out[:], k)
	}
	var z byte
	for _, b := range out {
		z |= b
	}
	if z == 0 {
		return out, errors.New("clé publique faible")
	}
	return out, nil
}

// Decrypt déchiffre une requête DNSCrypt et renvoie le message DNS.
func (s *Server) Decrypt(pkt []byte) ([]byte, *Session, error) {
	if len(pkt) < queryHeader+tagLen+minDNS {
		return nil, nil, ErrNotDNSCrypt
	}
	var key *resolverKey
	var es uint16
	s.mu.RLock()
	for _, k := range s.keys {
		switch {
		case subtle.ConstantTimeCompare(pkt[:clientMagicLen], k.magicX[:]) == 1:
			key, es = k, XChaCha20Poly1305
		case subtle.ConstantTimeCompare(pkt[:clientMagicLen], k.magic[:]) == 1:
			key, es = k, XSalsa20Poly1305
		}
		if key != nil {
			break
		}
	}
	var sk [32]byte
	if key != nil {
		sk = key.sk
	}
	s.mu.RUnlock()
	if key == nil {
		return nil, nil, ErrNotDNSCrypt
	}
	defer clear(sk[:])
	var clientPK [32]byte
	copy(clientPK[:], pkt[clientMagicLen:clientMagicLen+pkLen])
	sess := &Session{es: es}
	copy(sess.clientNonce[:], pkt[clientMagicLen+pkLen:queryHeader])
	shared, err := sharedKey(es, &sk, &clientPK)
	if err != nil {
		return nil, nil, err
	}
	sess.shared = shared
	var nonce [nonceLen]byte
	copy(nonce[:], sess.clientNonce[:])
	plain, err := open(es, pkt[queryHeader:], &nonce, &sess.shared)
	if err != nil {
		return nil, nil, err
	}
	msg, err := unpad(plain)
	if err != nil || len(msg) < minDNS {
		return nil, nil, errors.New("bourrage DNSCrypt invalide")
	}
	return msg, sess, nil
}

// Encrypt chiffre une réponse. maxLen (UDP) : taille de la requête reçue ;
// une réponse chiffrée plus grande ne doit pas être envoyée (l'appelant
// répond alors avec TC). 0 : pas de limite (TCP).
func (sess *Session) Encrypt(msg []byte, maxLen int) ([]byte, error) {
	overhead := len(serverMagic) + nonceLen + tagLen
	padded := (len(msg) + 1 + 63) &^ 63
	if maxLen > 0 && overhead+padded > maxLen {
		return nil, errors.New("réponse trop grande pour la requête UDP")
	}
	// Bourrage aléatoire supplémentaire en TCP (dans la limite d'un message).
	if maxLen == 0 {
		var r [1]byte
		_, _ = rand.Read(r[:])
		extra := int(r[0]&0x3) * 64
		if overhead+padded+extra <= maxDNS {
			padded += extra
		}
	}
	plain := make([]byte, padded)
	copy(plain, msg)
	plain[len(msg)] = 0x80
	var nonce [nonceLen]byte
	copy(nonce[:], sess.clientNonce[:])
	if _, err := rand.Read(nonce[halfNonce:]); err != nil {
		return nil, err
	}
	out := append([]byte{}, serverMagic...)
	out = append(out, nonce[:]...)
	return seal(sess.es, out, plain, &nonce, &sess.shared), nil
}

func unpad(b []byte) ([]byte, error) {
	for i := len(b) - 1; i >= 0; i-- {
		switch b[i] {
		case 0x80:
			return b[:i], nil
		case 0x00:
		default:
			return nil, errors.New("bourrage invalide")
		}
	}
	return nil, errors.New("bourrage absent")
}

func seal(es uint16, out, msg []byte, nonce *[24]byte, key *[32]byte) []byte {
	if es == XSalsa20Poly1305 {
		return secretbox.Seal(out, msg, nonce, key)
	}
	// XChaCha20-Poly1305 dans la construction « secretbox » : étiquette en
	// tête, clé Poly1305 tirée des 32 premiers octets du flux.
	c, _ := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	var first [64]byte
	c.XORKeyStream(first[:], first[:])
	var polyKey [32]byte
	copy(polyKey[:], first[:32])
	ct := make([]byte, len(msg))
	n := min(32, len(msg))
	for i := 0; i < n; i++ {
		ct[i] = first[32+i] ^ msg[i]
	}
	c.SetCounter(1)
	c.XORKeyStream(ct[n:], msg[n:])
	var tag [16]byte
	poly1305.Sum(&tag, ct, &polyKey)
	out = append(out, tag[:]...)
	return append(out, ct...)
}

func open(es uint16, boxed []byte, nonce *[24]byte, key *[32]byte) ([]byte, error) {
	if len(boxed) < tagLen {
		return nil, errors.New("message chiffré trop court")
	}
	if es == XSalsa20Poly1305 {
		out, ok := secretbox.Open(nil, boxed, nonce, key)
		if !ok {
			return nil, errors.New("authentification DNSCrypt échouée")
		}
		return out, nil
	}
	c, _ := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	var first [64]byte
	c.XORKeyStream(first[:], first[:])
	var polyKey [32]byte
	copy(polyKey[:], first[:32])
	var tag [16]byte
	copy(tag[:], boxed[:tagLen])
	ct := boxed[tagLen:]
	if !poly1305.Verify(&tag, ct, &polyKey) {
		return nil, errors.New("authentification DNSCrypt échouée")
	}
	out := make([]byte, len(ct))
	n := min(32, len(ct))
	for i := 0; i < n; i++ {
		out[i] = first[32+i] ^ ct[i]
	}
	c.SetCounter(1)
	c.XORKeyStream(out[n:], ct[n:])
	return out, nil
}

// Stamp renvoie le tampon « sdns:// » du serveur (format DNS Stamps,
// protocole 0x01). addr : adresse publique (IP ou IP:port).
func (s *Server) Stamp(addr string, dnssec, noLog, noFilter bool) string {
	var props uint64
	if dnssec {
		props |= 1
	}
	if noLog {
		props |= 2
	}
	if noFilter {
		props |= 4
	}
	var b bytes.Buffer
	b.WriteByte(0x01)
	_ = binary.Write(&b, binary.LittleEndian, props)
	lp := func(v []byte) {
		b.WriteByte(byte(len(v)))
		b.Write(v)
	}
	lp([]byte(addr))
	lp(s.ProviderKey())
	lp([]byte(strings.TrimSuffix(s.ProviderName, ".")))
	return "sdns://" + base64.RawURLEncoding.EncodeToString(b.Bytes())
}
