// Package cms produit une signature CMS (RFC 5652, SignedData) d'un
// contenu attaché : c'est le format des profils .mobileconfig signés
// d'Apple. La clé de signature est un crypto.Signer du keystore (HSM
// compris) ; elle ne quitte jamais celui-ci.
package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"sort"
	"time"
)

var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidECDSASHA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidRSASHA256     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
)

type algID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type signerInfo struct {
	Version            int
	SID                issuerAndSerial
	DigestAlgorithm    algID
	SignedAttrs        asn1.RawValue
	SignatureAlgorithm algID
	Signature          []byte
}

type encapContent struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue // [0] EXPLICIT, construit à la main
}

type signedData struct {
	Version          int
	DigestAlgorithms []algID `asn1:"set"`
	Encap            encapContent
	Certificates     asn1.RawValue
	SignerInfos      []signerInfo `asn1:"set"`
}

type contentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue // [0] EXPLICIT, construit à la main
}

// explicit0 enveloppe un encodage dans une étiquette [0] EXPLICIT
// (encoding/asn1 ignore l'option « explicit » sur un RawValue).
func explicit0(der []byte) asn1.RawValue {
	return asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: der}
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// set encode un SET OF à partir d'éléments déjà encodés, triés comme
// l'exige DER (X.690 §11.6).
func set(elems [][]byte, tag int, class int) asn1.RawValue {
	sort.Slice(elems, func(i, j int) bool { return bytes.Compare(elems[i], elems[j]) < 0 })
	return asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: bytes.Join(elems, nil)}
}

// Sign renvoie la structure CMS (DER) qui contient content, signé par
// signer avec le certificat chain[0] ; les autres certificats de la chaîne
// sont joints pour permettre la vérification.
func Sign(content []byte, chain [][]byte, signer crypto.Signer, now time.Time) ([]byte, error) {
	if len(chain) == 0 {
		return nil, errors.New("certificat de signature absent")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, err
	}
	var sigAlg algID
	switch signer.Public().(type) {
	case *ecdsa.PublicKey:
		sigAlg = algID{Algorithm: oidECDSASHA256}
	case *rsa.PublicKey:
		sigAlg = algID{Algorithm: oidRSASHA256, Parameters: asn1.NullRawValue}
	default:
		return nil, errors.New("type de clé non pris en charge pour la signature CMS")
	}
	digest := sha256.Sum256(content)
	attrs := [][]byte{
		mustMarshal(attribute{Type: oidContentType, Values: asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: mustMarshal(oidData)}}),
		mustMarshal(attribute{Type: oidSigningTime, Values: asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: mustMarshal(now.UTC())}}),
		mustMarshal(attribute{Type: oidMessageDigest, Values: asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: mustMarshal(digest[:])}}),
	}
	// La signature porte sur les attributs encodés en SET (RFC 5652 §5.4) ;
	// dans la structure, ils sont marqués [0] IMPLICIT.
	signedSet := set(append([][]byte{}, attrs...), 17, 0)
	toSign := mustMarshal(signedSet)
	h := sha256.Sum256(toSign)
	sig, err := signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(x509MarshalPub(leaf), x509MarshalPub2(signer.Public())) {
		return nil, errors.New("le certificat ne correspond pas à la clé de signature")
	}
	si := signerInfo{
		Version:            1,
		SID:                issuerAndSerial{Issuer: asn1.RawValue{FullBytes: leaf.RawIssuer}, Serial: leaf.SerialNumber},
		DigestAlgorithm:    algID{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
		SignedAttrs:        asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: signedSet.Bytes},
		SignatureAlgorithm: sigAlg,
		Signature:          sig,
	}
	certs := make([][]byte, len(chain))
	copy(certs, chain)
	sd := signedData{
		Version:          1,
		DigestAlgorithms: []algID{{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}},
		Encap:            encapContent{Type: oidData, Content: explicit0(mustMarshal(content))},
		Certificates:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: bytes.Join(certs, nil)},
		SignerInfos:      []signerInfo{si},
	}
	return asn1.Marshal(contentInfo{Type: oidSignedData, Content: explicit0(mustMarshal(sd))})
}

func x509MarshalPub(c *x509.Certificate) []byte { return c.RawSubjectPublicKeyInfo }

func x509MarshalPub2(p crypto.PublicKey) []byte {
	b, _ := x509.MarshalPKIXPublicKey(p)
	return b
}
