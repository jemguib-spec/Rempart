// Package softkey simule un authentificateur WebAuthn ES256 pour les tests.
package softkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
)

// Key : authentificateur logiciel.
type Key struct {
	priv   *ecdsa.PrivateKey
	ID     []byte
	Count  uint32
	UV     bool
	Handle []byte
}

var b64 = base64.RawURLEncoding

// New crée une clé ES256.
func New() *Key {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &Key{priv: k, ID: id, UV: true}
}

func head(major byte, n int) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	}
	return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
}

func bs(b []byte) []byte  { return append(head(2, len(b)), b...) }
func txt(s string) []byte { return append(head(3, len(s)), s...) }
func neg(n int) []byte    { return head(1, -1-n) }

func (k *Key) cose() []byte {
	x, y := make([]byte, 32), make([]byte, 32)
	k.priv.X.FillBytes(x)
	k.priv.Y.FillBytes(y)
	out := head(5, 5)
	out = append(out, head(0, 1)...)
	out = append(out, head(0, 2)...)
	out = append(out, head(0, 3)...)
	out = append(out, neg(-7)...)
	out = append(out, neg(-1)...)
	out = append(out, head(0, 1)...)
	out = append(out, neg(-2)...)
	out = append(out, bs(x)...)
	out = append(out, neg(-3)...)
	out = append(out, bs(y)...)
	return out
}

func (k *Key) authData(rpID string, cred bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, h[:]...)
	f := byte(0x01)
	if k.UV {
		f |= 0x04
	}
	if cred {
		f |= 0x40
	}
	out = append(out, f)
	out = binary.BigEndian.AppendUint32(out, k.Count)
	if cred {
		out = append(out, make([]byte, 16)...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(k.ID)))
		out = append(out, k.ID...)
		out = append(out, k.cose()...)
	}
	return out
}

func clientData(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]string{"type": typ, "challenge": challenge, "origin": origin})
	return b
}

// Create répond à navigator.credentials.create (champs base64url).
func (k *Key) Create(challenge, rpID, origin string) map[string]string {
	att := head(5, 3)
	att = append(att, txt("fmt")...)
	att = append(att, txt("none")...)
	att = append(att, txt("attStmt")...)
	att = append(att, head(5, 0)...)
	att = append(att, txt("authData")...)
	att = append(att, bs(k.authData(rpID, true))...)
	return map[string]string{"clientDataJSON": b64.EncodeToString(clientData("webauthn.create", challenge, origin)), "attestationObject": b64.EncodeToString(att)}
}

// Get répond à navigator.credentials.get.
func (k *Key) Get(challenge, rpID, origin string) map[string]string {
	k.Count++
	ad := k.authData(rpID, false)
	cd := clientData("webauthn.get", challenge, origin)
	h := sha256.Sum256(cd)
	d := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, k.priv, d[:])
	return map[string]string{"id": b64.EncodeToString(k.ID), "clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(ad),
		"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString(k.Handle), "challenge": challenge}
}
