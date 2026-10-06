//go:build cgo

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// PKCS#11 v3 constants missing from miekg/pkcs11.
const (
	ckkECEdwards           = 0x40
	ckmECEdwardsKeyPairGen = 0x1055
	ckmEdDSA               = 0x1057
)

var (
	oidP256    = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384    = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// PKCS11Available reports whether this binary was built with HSM support.
const PKCS11Available = true

// PKCS11Config configures the HSM backend.
type PKCS11Config struct {
	Module     string // path to the vendor library (.so)
	TokenLabel string
	PIN        string
	KEKLabel   string // AES-256 key used to wrap data keys
}

// HSM is a keystore backed by a PKCS#11 token.
type HSM struct {
	cfg   PKCS11Config
	ctx   *pkcs11.Ctx
	slot  uint
	mu    sync.Mutex // PKCS#11 sessions are not safe for concurrent use
	sess  pkcs11.SessionHandle
	kek   pkcs11.ObjectHandle
	cache map[string]*hsmSigner
	info  string
}

// OpenPKCS11 loads the vendor module, logs into the token and makes sure the
// key-encryption key exists (it is generated inside the HSM if missing).
func OpenPKCS11(cfg PKCS11Config) (Keystore, error) {
	h, err := openHSM(cfg)
	if err != nil {
		return nil, err
	}
	return h, nil
}

func openHSM(cfg PKCS11Config) (*HSM, error) {
	if cfg.KEKLabel == "" {
		cfg.KEKLabel = "rempart-kek"
	}
	ctx := pkcs11.New(cfg.Module)
	if ctx == nil {
		return nil, fmt.Errorf("impossible de charger le module PKCS#11 %q", cfg.Module)
	}
	if err := ctx.Initialize(); err != nil {
		var perr pkcs11.Error
		if !(errors.As(err, &perr) && perr == pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			return nil, fmt.Errorf("C_Initialize: %w", err)
		}
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, err
	}
	found := false
	var slot uint
	var tinfo pkcs11.TokenInfo
	for _, s := range slots {
		ti, err := ctx.GetTokenInfo(s)
		if err == nil && ti.Label == cfg.TokenLabel {
			slot, tinfo, found = s, ti, true
			break
		}
	}
	if !found {
		ctx.Finalize()
		return nil, fmt.Errorf("token PKCS#11 %q introuvable", cfg.TokenLabel)
	}
	sess, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("C_OpenSession: %w", err)
	}
	if err := ctx.Login(sess, pkcs11.CKU_USER, cfg.PIN); err != nil {
		var perr pkcs11.Error
		if !(errors.As(err, &perr) && perr == pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return nil, fmt.Errorf("C_Login (PIN incorrect ?): %w", err)
		}
	}
	h := &HSM{cfg: cfg, ctx: ctx, slot: slot, sess: sess, cache: map[string]*hsmSigner{}}
	h.info = fmt.Sprintf("HSM PKCS#11 %s %s, token %q (série %s)", tinfo.ManufacturerID, tinfo.Model, tinfo.Label, tinfo.SerialNumber)
	if err := h.ensureKEK(); err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

func (h *HSM) Backend() string  { return "pkcs11" }
func (h *HSM) Describe() string { return h.info }

func (h *HSM) find(tmpl []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if err := h.ctx.FindObjectsInit(h.sess, tmpl); err != nil {
		return nil, err
	}
	defer h.ctx.FindObjectsFinal(h.sess)
	var all []pkcs11.ObjectHandle
	for {
		objs, _, err := h.ctx.FindObjects(h.sess, 64)
		if err != nil {
			return nil, err
		}
		if len(objs) == 0 {
			return all, nil
		}
		all = append(all, objs...)
	}
}

func (h *HSM) ensureKEK() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	objs, err := h.find([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, h.cfg.KEKLabel),
	})
	if err != nil {
		return err
	}
	if len(objs) > 0 {
		h.kek = objs[0]
		return nil
	}
	kek, err := h.ctx.GenerateKey(h.sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, h.cfg.KEKLabel),
		})
	if err != nil {
		return fmt.Errorf("génération de la KEK AES dans le HSM: %w", err)
	}
	h.kek = kek
	return nil
}

// Wrap encrypts with AES-256-GCM inside the HSM. Output: 0x02 | iv | ct+tag.
func (h *HSM) Wrap(plaintext, aad []byte) ([]byte, error) {
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	params := pkcs11.NewGCMParams(iv, aad, 128)
	defer params.Free()
	if err := h.ctx.EncryptInit(h.sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, h.kek); err != nil {
		return nil, fmt.Errorf("C_EncryptInit: %w", err)
	}
	ct, err := h.ctx.Encrypt(h.sess, plaintext)
	if err != nil {
		return nil, fmt.Errorf("C_Encrypt: %w", err)
	}
	if real := params.IV(); len(real) == 12 {
		iv = real // some HSMs choose the IV themselves
	}
	out := append([]byte{2}, iv...)
	return append(out, ct...), nil
}

func (h *HSM) Unwrap(ct, aad []byte) ([]byte, error) {
	if len(ct) < 1+12+16 || ct[0] != 2 {
		return nil, errors.New("données chiffrées invalides")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	params := pkcs11.NewGCMParams(ct[1:13], aad, 128)
	defer params.Free()
	if err := h.ctx.DecryptInit(h.sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}, h.kek); err != nil {
		return nil, fmt.Errorf("C_DecryptInit: %w", err)
	}
	pt, err := h.ctx.Decrypt(h.sess, ct[13:])
	if err != nil {
		return nil, errors.New("échec du déchiffrement (données modifiées ou mauvaise clé)")
	}
	return pt, nil
}

func (h *HSM) Signer(label string, alg Algorithm, create bool) (crypto.Signer, error) {
	if !ValidLabel(label) {
		return nil, fmt.Errorf("label de clé invalide %q", label)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.cache[label]; ok {
		return s, nil
	}
	s, err := h.loadSigner(label)
	if err == nil {
		h.cache[label] = s
		return s, nil
	}
	if !errors.Is(err, ErrNotFound) || !create {
		return nil, err
	}
	if err := h.generate(label, alg); err != nil {
		return nil, err
	}
	s, err = h.loadSigner(label)
	if err != nil {
		return nil, err
	}
	h.cache[label] = s
	return s, nil
}

func (h *HSM) generate(label string, alg Algorithm) error {
	var oid asn1.ObjectIdentifier
	var keyType uint = pkcs11.CKK_EC
	mech := uint(pkcs11.CKM_EC_KEY_PAIR_GEN)
	switch alg {
	case ECDSAP256:
		oid = oidP256
	case ECDSAP384:
		oid = oidP384
	case Ed25519:
		oid, keyType, mech = oidEd25519, ckkECEdwards, ckmECEdwardsKeyPairGen
	default:
		return fmt.Errorf("algorithme %q non supporté par le HSM", alg)
	}
	params, _ := asn1.Marshal(oid)
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	pub := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, params),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	priv := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	_, _, err := h.ctx.GenerateKeyPair(h.sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)}, pub, priv)
	if err != nil {
		return fmt.Errorf("génération de la paire %s dans le HSM: %w", label, err)
	}
	return nil
}

// supports vérifie dans la liste des mécanismes du token que l'algorithme
// peut être généré et utilisé pour signer. La courbe elle-même n'est pas
// annoncée par PKCS#11 : un refus éventuel viendra de C_GenerateKeyPair.
func (h *HSM) supports(alg Algorithm) error {
	var need []uint
	var names []string
	switch alg {
	case ECDSAP256, ECDSAP384:
		need, names = []uint{pkcs11.CKM_EC_KEY_PAIR_GEN, pkcs11.CKM_ECDSA}, []string{"CKM_EC_KEY_PAIR_GEN", "CKM_ECDSA"}
	case Ed25519:
		need, names = []uint{ckmECEdwardsKeyPairGen, ckmEdDSA}, []string{"CKM_EC_EDWARDS_KEY_PAIR_GEN", "CKM_EDDSA"}
	default:
		return fmt.Errorf("algorithme %q non supporté par le HSM", alg)
	}
	h.mu.Lock()
	mechs, err := h.ctx.GetMechanismList(h.slot)
	h.mu.Unlock()
	if err != nil {
		return fmt.Errorf("C_GetMechanismList: %w", err)
	}
	has := map[uint]bool{}
	for _, m := range mechs {
		has[m.Mechanism] = true
	}
	var missing []string
	for i, m := range need {
		if !has[m] {
			missing = append(missing, names[i])
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("non pris en charge par ce HSM (mécanisme %s absent)", strings.Join(missing, ", "))
	}
	return nil
}

// loadSigner must be called with h.mu held.
func (h *HSM) loadSigner(label string) (*hsmSigner, error) {
	privs, err := h.find([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	})
	if err != nil {
		return nil, err
	}
	pubs, err := h.find([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	})
	if err != nil {
		return nil, err
	}
	if len(privs) == 0 || len(pubs) == 0 {
		return nil, ErrNotFound
	}
	attrs, err := h.ctx.GetAttributeValue(h.sess, pubs[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("lecture de la clé publique %s: %w", label, err)
	}
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(attrs[0].Value, &oid); err != nil {
		return nil, fmt.Errorf("CKA_EC_PARAMS non supporté pour %s", label)
	}
	point := attrs[1].Value
	var inner []byte
	if rest, err := asn1.Unmarshal(point, &inner); err == nil && len(rest) == 0 {
		point = inner // most tokens DER-wrap the point in an OCTET STRING
	}
	s := &hsmSigner{h: h, priv: privs[0], label: label}
	switch {
	case oid.Equal(oidP256), oid.Equal(oidP384):
		curve := elliptic.P256()
		s.alg = ECDSAP256
		if oid.Equal(oidP384) {
			curve, s.alg = elliptic.P384(), ECDSAP384
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(point) != 1+2*size || point[0] != 4 {
			return nil, fmt.Errorf("point EC invalide pour %s", label)
		}
		s.pub = &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(point[1 : 1+size]), Y: new(big.Int).SetBytes(point[1+size:])}
	case oid.Equal(oidEd25519):
		if len(point) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("clé Ed25519 invalide pour %s", label)
		}
		s.alg, s.pub = Ed25519, ed25519.PublicKey(append([]byte(nil), point...))
	default:
		return nil, fmt.Errorf("courbe non supportée pour %s", label)
	}
	return s, nil
}

func (h *HSM) Keys() []KeyInfo {
	h.mu.Lock()
	objs, err := h.find([]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)})
	origin := map[string]string{}
	var labels []string
	if err == nil {
		for _, o := range objs {
			a, err := h.ctx.GetAttributeValue(h.sess, o, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil)})
			if err != nil || len(a) != 1 {
				continue
			}
			l := string(a[0].Value)
			labels = append(labels, l)
			// CKA_LOCAL vrai : la clé a été générée dans le token.
			origin[l] = "importée"
			if loc, err := h.ctx.GetAttributeValue(h.sess, o, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LOCAL, nil)}); err == nil && len(loc) == 1 && len(loc[0].Value) == 1 && loc[0].Value[0] == 1 {
				origin[l] = "générée"
			}
		}
	}
	h.mu.Unlock()
	out := []KeyInfo{}
	for _, l := range labels {
		s, err := h.Signer(l, "", false)
		if err != nil {
			continue
		}
		out = append(out, KeyInfo{Label: l, Algorithm: s.(*hsmSigner).alg, Backend: "pkcs11", Fingerprint: Fingerprint(s.Public()), Origin: origin[l]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// Destroy détruit la paire de clés (objets privé et public) portant ce label.
func (h *HSM) Destroy(label string) error {
	if !ValidLabel(label) {
		return fmt.Errorf("label de clé invalide %q", label)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.cache, label)
	for _, class := range []uint{pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY} {
		objs, err := h.find([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		})
		if err != nil {
			return err
		}
		for _, o := range objs {
			if err := h.ctx.DestroyObject(h.sess, o); err != nil {
				return fmt.Errorf("C_DestroyObject %s: %w", label, err)
			}
		}
	}
	return nil
}

func (h *HSM) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	_ = h.ctx.Logout(h.sess)
	_ = h.ctx.CloseSession(h.sess)
	_ = h.ctx.Finalize()
	h.ctx.Destroy()
	return nil
}

type hsmSigner struct {
	h     *HSM
	priv  pkcs11.ObjectHandle
	pub   crypto.PublicKey
	alg   Algorithm
	label string
}

func (s *hsmSigner) Public() crypto.PublicKey { return s.pub }

// Sign implements crypto.Signer. ECDSA signatures are returned ASN.1 encoded
// as required by the crypto.Signer contract.
func (s *hsmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	mech := uint(pkcs11.CKM_ECDSA)
	if s.alg == Ed25519 {
		if opts != nil && opts.HashFunc() != crypto.Hash(0) {
			return nil, errors.New("Ed25519 signe le message complet (pas de pré-hachage)")
		}
		mech = ckmEdDSA
	}
	s.h.mu.Lock()
	defer s.h.mu.Unlock()
	if err := s.h.ctx.SignInit(s.h.sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)}, s.priv); err != nil {
		return nil, fmt.Errorf("C_SignInit: %w", err)
	}
	sig, err := s.h.ctx.Sign(s.h.sess, digest)
	if err != nil {
		return nil, fmt.Errorf("C_Sign: %w", err)
	}
	if s.alg == Ed25519 {
		return sig, nil
	}
	n := len(sig) / 2
	return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])})
}
