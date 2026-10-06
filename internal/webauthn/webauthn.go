// Package webauthn vérifie l'inscription et l'utilisation de clés d'accès
// (passkeys, clés de sécurité FIDO2) selon WebAuthn niveau 2, sans
// dépendance : décodage CBOR et COSE, vérification des signatures ES256,
// EdDSA et RS256.
//
// L'attestation n'est pas vérifiée (mode « none ») : Rempart retient la clé
// publique que l'authentificateur présente lors d'une inscription faite par
// un administrateur déjà authentifié, comme le recommandent les passkeys.
package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// Algorithmes COSE acceptés (ordre de préférence annoncé au navigateur).
const (
	AlgES256 = -7
	AlgEdDSA = -8
	AlgRS256 = -257
)

// Indicateurs des données d'authentification.
const (
	flagUP = 0x01 // présence de l'utilisateur
	flagUV = 0x04 // utilisateur vérifié (PIN, biométrie)
	flagBE = 0x08 // sauvegardable (passkey synchronisée)
	flagBS = 0x10 // sauvegardée
	flagAT = 0x40 // données de clé attestée présentes
	flagED = 0x80 // extensions présentes
)

var b64 = base64.RawURLEncoding

// Credential : clé enregistrée.
type Credential struct {
	ID             []byte
	PublicKey      []byte // SubjectPublicKeyInfo DER
	Alg            int
	SignCount      uint32
	BackupEligible bool
}

// clientData : champs utiles de clientDataJSON.
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

func checkClientData(raw []byte, typ string, challenge []byte, origin string) error {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return errors.New("clientDataJSON illisible")
	}
	if cd.Type != typ {
		return fmt.Errorf("type %q inattendu", cd.Type)
	}
	got, err := b64.DecodeString(cd.Challenge)
	if err != nil || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return errors.New("défi incorrect")
	}
	if cd.Origin != origin {
		return fmt.Errorf("origine %q inattendue (attendu %q)", cd.Origin, origin)
	}
	if cd.CrossOrigin {
		return errors.New("requête depuis un cadre d'une autre origine")
	}
	return nil
}

type authData struct {
	rpIDHash []byte
	flags    byte
	count    uint32
	credID   []byte
	cose     []byte
}

func parseAuthData(b []byte, wantCred bool) (*authData, error) {
	if len(b) < 37 {
		return nil, errors.New("données d'authentification trop courtes")
	}
	ad := &authData{rpIDHash: b[:32], flags: b[32], count: binary.BigEndian.Uint32(b[33:37])}
	rest := b[37:]
	if ad.flags&flagAT != 0 {
		if len(rest) < 18 {
			return nil, errors.New("données de clé attestée tronquées")
		}
		n := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if n == 0 || n > 1023 || len(rest) < n {
			return nil, errors.New("identifiant de clé invalide")
		}
		ad.credID = rest[:n]
		rest = rest[n:]
		_, used, err := decodeCBOR(rest)
		if err != nil {
			return nil, fmt.Errorf("clé COSE : %w", err)
		}
		ad.cose = rest[:used]
		rest = rest[used:]
	} else if wantCred {
		return nil, errors.New("aucune clé dans la réponse d'inscription")
	}
	if ad.flags&flagED != 0 {
		_, used, err := decodeCBOR(rest)
		if err != nil {
			return nil, fmt.Errorf("extensions : %w", err)
		}
		rest = rest[used:]
	}
	if len(rest) != 0 {
		return nil, errors.New("octets en trop dans les données d'authentification")
	}
	return ad, nil
}

func (ad *authData) check(rpID string, requireUV bool) error {
	h := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(ad.rpIDHash, h[:]) != 1 {
		return errors.New("identifiant de site (rpId) différent")
	}
	if ad.flags&flagUP == 0 {
		return errors.New("présence de l'utilisateur non confirmée")
	}
	if requireUV && ad.flags&flagUV == 0 {
		return errors.New("vérification de l'utilisateur (PIN ou biométrie) exigée")
	}
	// BS sans BE est incohérent (WebAuthn §6.1).
	if ad.flags&flagBS != 0 && ad.flags&flagBE == 0 {
		return errors.New("indicateurs de sauvegarde incohérents")
	}
	return nil
}

// coseToPublicKey convertit une clé COSE (RFC 9053) en clé Go.
func coseToPublicKey(raw []byte) (crypto.PublicKey, int, error) {
	v, n, err := decodeCBOR(raw)
	if err != nil || n != len(raw) {
		return nil, 0, errors.New("clé COSE illisible")
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, 0, errors.New("clé COSE : table attendue")
	}
	i := func(k int64) (int64, bool) { x, ok := m[k].(int64); return x, ok }
	bs := func(k int64) []byte { x, _ := m[k].([]byte); return x }
	kty, _ := i(1)
	alg, ok := i(3)
	if !ok {
		return nil, 0, errors.New("clé COSE sans algorithme")
	}
	switch {
	case kty == 2 && alg == AlgES256:
		crv, _ := i(-1)
		x, y := bs(-2), bs(-3)
		if crv != 1 || len(x) != 32 || len(y) != 32 {
			return nil, 0, errors.New("clé EC2 invalide (P-256 attendue)")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, 0, errors.New("point hors de la courbe")
		}
		return pub, AlgES256, nil
	case kty == 1 && alg == AlgEdDSA:
		crv, _ := i(-1)
		x := bs(-2)
		if crv != 6 || len(x) != ed25519.PublicKeySize {
			return nil, 0, errors.New("clé OKP invalide (Ed25519 attendue)")
		}
		return ed25519.PublicKey(x), AlgEdDSA, nil
	case kty == 3 && alg == AlgRS256:
		nb, eb := bs(-1), bs(-2)
		if len(nb) < 256 || len(eb) == 0 || len(eb) > 4 {
			return nil, 0, errors.New("clé RSA invalide (2048 bits au moins)")
		}
		e := 0
		for _, c := range eb {
			e = e<<8 | int(c)
		}
		if e < 3 || e%2 == 0 {
			return nil, 0, errors.New("exposant RSA invalide")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, AlgRS256, nil
	}
	return nil, 0, fmt.Errorf("algorithme COSE %d (type %d) non pris en charge", alg, kty)
}

// Registration : réponse du navigateur à navigator.credentials.create().
type Registration struct {
	ClientDataJSON    []byte
	AttestationObject []byte
}

// VerifyRegistration contrôle une inscription et renvoie la clé à conserver.
func VerifyRegistration(reg Registration, challenge []byte, rpID, origin string, requireUV bool) (*Credential, error) {
	if err := checkClientData(reg.ClientDataJSON, "webauthn.create", challenge, origin); err != nil {
		return nil, err
	}
	v, n, err := decodeCBOR(reg.AttestationObject)
	if err != nil || n != len(reg.AttestationObject) {
		return nil, errors.New("objet d'attestation illisible")
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, errors.New("objet d'attestation : table attendue")
	}
	raw, ok := m["authData"].([]byte)
	if !ok {
		return nil, errors.New("objet d'attestation sans authData")
	}
	ad, err := parseAuthData(raw, true)
	if err != nil {
		return nil, err
	}
	if err := ad.check(rpID, requireUV); err != nil {
		return nil, err
	}
	pub, alg, err := coseToPublicKey(ad.cose)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return &Credential{ID: append([]byte(nil), ad.credID...), PublicKey: der, Alg: alg, SignCount: ad.count, BackupEligible: ad.flags&flagBE != 0}, nil
}

// Assertion : réponse du navigateur à navigator.credentials.get().
type Assertion struct {
	CredentialID      []byte
	ClientDataJSON    []byte
	AuthenticatorData []byte
	Signature         []byte
	UserHandle        []byte
}

// VerifyAssertion contrôle une authentification avec la clé enregistrée et
// renvoie le nouveau compteur de signatures. Un compteur qui ne progresse
// pas alors que l'authentificateur en tient un signale un clone.
func VerifyAssertion(as Assertion, cred Credential, challenge []byte, rpID, origin string, requireUV bool) (uint32, error) {
	if !bytes.Equal(as.CredentialID, cred.ID) {
		return 0, errors.New("clé différente")
	}
	if err := checkClientData(as.ClientDataJSON, "webauthn.get", challenge, origin); err != nil {
		return 0, err
	}
	ad, err := parseAuthData(as.AuthenticatorData, false)
	if err != nil {
		return 0, err
	}
	if ad.flags&flagAT != 0 {
		return 0, errors.New("données de clé attestée inattendues")
	}
	if err := ad.check(rpID, requireUV); err != nil {
		return 0, err
	}
	pub, err := x509.ParsePKIXPublicKey(cred.PublicKey)
	if err != nil {
		return 0, err
	}
	h := sha256.Sum256(as.ClientDataJSON)
	signed := append(append([]byte(nil), as.AuthenticatorData...), h[:]...)
	digest := sha256.Sum256(signed)
	ok := false
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		ok = cred.Alg == AlgES256 && ecdsa.VerifyASN1(k, digest[:], as.Signature)
	case ed25519.PublicKey:
		ok = cred.Alg == AlgEdDSA && ed25519.Verify(k, signed, as.Signature)
	case *rsa.PublicKey:
		ok = cred.Alg == AlgRS256 && rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], as.Signature) == nil
	}
	if !ok {
		return 0, errors.New("signature invalide")
	}
	if (ad.count != 0 || cred.SignCount != 0) && ad.count <= cred.SignCount {
		return 0, errors.New("compteur de signatures en recul : clé possiblement clonée")
	}
	return ad.count, nil
}
