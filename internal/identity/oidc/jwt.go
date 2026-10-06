// jwt.go - vérification des jetons JWS (RFC 7515/7519) signés par le
// fournisseur d'identité. Seuls les algorithmes asymétriques sont acceptés :
// « none » et HS* (clé partagée) sont refusés, et l'algorithme annoncé doit
// correspondre au type de la clé (pas de confusion RSA/HMAC).

package oidc

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

var b64 = base64.RawURLEncoding

// jwk est une clé publique publiée par le fournisseur (RFC 7517).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`

	pub crypto.PublicKey
}

func (k *jwk) parse() error {
	switch k.Kty {
	case "RSA":
		n, err1 := b64.DecodeString(k.N)
		e, err2 := b64.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
			return errors.New("clé RSA mal formée")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < 2048 || pub.E < 3 || pub.E%2 == 0 {
			return errors.New("clé RSA trop faible")
		}
		k.pub = pub
	case "EC":
		var c elliptic.Curve
		switch k.Crv {
		case "P-256":
			c = elliptic.P256()
		case "P-384":
			c = elliptic.P384()
		case "P-521":
			c = elliptic.P521()
		default:
			return errors.New("courbe non prise en charge")
		}
		x, err1 := b64.DecodeString(k.X)
		y, err2 := b64.DecodeString(k.Y)
		size := (c.Params().BitSize + 7) / 8
		if err1 != nil || err2 != nil || len(x) != size || len(y) != size {
			return errors.New("clé EC mal formée")
		}
		// crypto/ecdh vérifie que le point appartient bien à la courbe.
		raw := append(append([]byte{4}, x...), y...)
		if err := onCurve(k.Crv, raw); err != nil {
			return err
		}
		k.pub = &ecdsa.PublicKey{Curve: c, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	case "OKP":
		x, err := b64.DecodeString(k.X)
		if k.Crv != "Ed25519" || err != nil || len(x) != ed25519.PublicKeySize {
			return errors.New("clé OKP non prise en charge")
		}
		k.pub = ed25519.PublicKey(x)
	default:
		return errors.New("type de clé non pris en charge")
	}
	return nil
}

func onCurve(crv string, raw []byte) error {
	var c ecdh.Curve
	switch crv {
	case "P-256":
		c = ecdh.P256()
	case "P-384":
		c = ecdh.P384()
	default:
		c = ecdh.P521()
	}
	if _, err := c.NewPublicKey(raw); err != nil {
		return errors.New("clé EC hors de la courbe")
	}
	return nil
}

// algOK indique si l'algorithme convient à la clé.
func algOK(alg string, pub crypto.PublicKey) bool {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		return alg == "RS256" || alg == "RS384" || alg == "RS512" || alg == "PS256" || alg == "PS384" || alg == "PS512"
	case *ecdsa.PublicKey:
		return (alg == "ES256" && p.Curve == elliptic.P256()) || (alg == "ES384" && p.Curve == elliptic.P384()) ||
			(alg == "ES512" && p.Curve == elliptic.P521())
	case ed25519.PublicKey:
		return alg == "EdDSA"
	}
	return false
}

func hashFor(alg string) (crypto.Hash, func([]byte) []byte) {
	switch alg[2:] {
	case "384":
		return crypto.SHA384, func(b []byte) []byte { h := sha512.Sum384(b); return h[:] }
	case "512":
		return crypto.SHA512, func(b []byte) []byte { h := sha512.Sum512(b); return h[:] }
	}
	return crypto.SHA256, func(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
}

func verifySig(alg string, pub crypto.PublicKey, signed, sig []byte) error {
	if !algOK(alg, pub) {
		return fmt.Errorf("algorithme %s incompatible avec la clé", alg)
	}
	bad := errors.New("signature du jeton invalide")
	switch p := pub.(type) {
	case *rsa.PublicKey:
		h, sum := hashFor(alg)
		d := sum(signed)
		var err error
		if alg[0] == 'P' {
			err = rsa.VerifyPSS(p, h, d, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			err = rsa.VerifyPKCS1v15(p, h, d, sig)
		}
		if err != nil {
			return bad
		}
	case *ecdsa.PublicKey:
		_, sum := hashFor(alg)
		size := (p.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size { // r || s, pas de DER en JWS
			return bad
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(p, sum(signed), r, s) {
			return bad
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(p, signed, sig) {
			return bad
		}
	default:
		return bad
	}
	return nil
}

type jwsHeader struct {
	Alg  string          `json:"alg"`
	Kid  string          `json:"kid"`
	Typ  string          `json:"typ"`
	Crit json.RawMessage `json:"crit"`
	JKU  string          `json:"jku"`
	JWK  json.RawMessage `json:"jwk"`
	X5U  string          `json:"x5u"`
}

// splitJWT décode l'en-tête et la charge utile sans vérifier la signature.
func splitJWT(raw string) (h jwsHeader, claims map[string]any, signed, sig []byte, err error) {
	if len(raw) > 64<<10 {
		return h, nil, nil, nil, errors.New("jeton trop grand")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return h, nil, nil, nil, errors.New("jeton JWS compact attendu")
	}
	hb, err1 := b64.DecodeString(parts[0])
	pb, err2 := b64.DecodeString(parts[1])
	sig, err3 := b64.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return h, nil, nil, nil, errors.New("jeton mal encodé")
	}
	if err := json.Unmarshal(hb, &h); err != nil {
		return h, nil, nil, nil, errors.New("en-tête du jeton illisible")
	}
	// Une clé désignée par le jeton lui-même n'est jamais suivie.
	if len(h.Crit) > 0 || h.JKU != "" || len(h.JWK) > 0 || h.X5U != "" {
		return h, nil, nil, nil, errors.New("en-tête du jeton refusé (crit, jku, jwk ou x5u)")
	}
	dec := json.NewDecoder(bytes.NewReader(pb))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil || claims == nil {
		return h, nil, nil, nil, errors.New("contenu du jeton illisible")
	}
	return h, claims, []byte(parts[0] + "." + parts[1]), sig, nil
}

// num lit une date numérique (secondes) d'une revendication.
func num(claims map[string]any, k string) (int64, bool) {
	n, ok := claims[k].(json.Number)
	if !ok {
		return 0, false
	}
	if i, err := n.Int64(); err == nil {
		return i, true
	}
	f, err := n.Float64()
	if err != nil {
		return 0, false
	}
	return int64(f), true
}

// ClaimStrings lit une revendication par un chemin pointé
// (« realm_access.roles », « resource_access.rempart.roles », « groups »).
// Une chaîne seule donne une liste d'un élément.
func ClaimStrings(claims map[string]any, path string) []string {
	var cur any = claims
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	switch v := cur.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// ClaimString lit une revendication textuelle de premier niveau.
func ClaimString(claims map[string]any, k string) string {
	s, _ := claims[k].(string)
	return s
}
