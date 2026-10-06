package dnscrypt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Cert : certificat de résolveur vérifié.
type Cert struct {
	ES     uint16
	PK     [32]byte
	Magic  [8]byte
	Serial uint32
}

// ParseCert vérifie un certificat (signature du fournisseur, validité).
func ParseCert(c []byte, provider ed25519.PublicKey, now time.Time) (Cert, error) {
	var out Cert
	if len(c) < 124 || !bytes.Equal(c[:4], certMagic) {
		return out, errors.New("certificat mal formé")
	}
	if !ed25519.Verify(provider, c[72:], c[8:72]) {
		return out, errors.New("signature du certificat invalide")
	}
	out.ES = binary.BigEndian.Uint16(c[4:6])
	if out.ES != XSalsa20Poly1305 && out.ES != XChaCha20Poly1305 {
		return out, errors.New("construction non prise en charge")
	}
	copy(out.PK[:], c[72:104])
	copy(out.Magic[:], c[104:112])
	out.Serial = binary.BigEndian.Uint32(c[112:116])
	start, end := binary.BigEndian.Uint32(c[116:120]), binary.BigEndian.Uint32(c[120:124])
	if t := uint32(now.Unix()); t < start || t > end {
		return out, errors.New("certificat hors de sa période de validité")
	}
	return out, nil
}

// Seal chiffre une requête DNS pour ce certificat ; open déchiffre la
// réponse correspondante.
func (c Cert) Seal(msg []byte, minLen int) ([]byte, func([]byte) ([]byte, error), error) {
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		return nil, nil, err
	}
	pk, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	shared, err := sharedKey(c.ES, &sk, &c.PK)
	clear(sk[:])
	if err != nil {
		return nil, nil, err
	}
	var nonce [nonceLen]byte
	if _, err := rand.Read(nonce[:halfNonce]); err != nil {
		return nil, nil, err
	}
	n := max(minLen-queryHeader-tagLen, len(msg)+1)
	n = (n + 63) &^ 63
	plain := make([]byte, n)
	copy(plain, msg)
	plain[len(msg)] = 0x80
	pkt := append(append(append([]byte{}, c.Magic[:]...), pk...), nonce[:halfNonce]...)
	pkt = seal(c.ES, pkt, plain, &nonce, &shared)
	opener := func(resp []byte) ([]byte, error) {
		if len(resp) < len(serverMagic)+nonceLen+tagLen || !bytes.Equal(resp[:8], serverMagic) || !bytes.Equal(resp[8:20], nonce[:halfNonce]) {
			return nil, errors.New("réponse DNSCrypt invalide")
		}
		var rn [nonceLen]byte
		copy(rn[:], resp[8:32])
		p, err := open(c.ES, resp[32:], &rn, &shared)
		if err != nil {
			return nil, err
		}
		return unpad(p)
	}
	return pkt, opener, nil
}
