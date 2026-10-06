// pkcs11_admin.go - administration PKCS#11 : import de clés, migration, test de token.
// Objets non extractibles, PIN en []byte effacé, objets de session pour l'auto-test.
// Rempart ; cgo + miekg/pkcs11, testé avec SoftHSM2.

//go:build cgo

package keystore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/pkcs11"
	"github.com/rempart-dns/rempart/internal/secmem"
)

// importKey place une clé privée logicielle dans le token, non extractible.
// La clé n'a jamais été générée dans le HSM (CKA_LOCAL faux) : l'interface la
// signale comme « importée » et recommande une rotation.
func (h *HSM) importKey(label string, priv crypto.Signer) error {
	if !ValidLabel(label) {
		return fmt.Errorf("label de clé invalide %q", label)
	}
	var (
		oid     asn1.ObjectIdentifier
		keyType uint
		value   []byte
		point   []byte
	)
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		switch k.Curve {
		case elliptic.P256():
			oid = oidP256
		case elliptic.P384():
			oid = oidP384
		default:
			return fmt.Errorf("courbe non supportée pour %s", label)
		}
		keyType = pkcs11.CKK_EC
		value = k.D.FillBytes(make([]byte, size))
		pub, err := k.PublicKey.ECDH()
		if err != nil {
			return err
		}
		point = pub.Bytes() // 0x04 | X | Y
	case ed25519.PrivateKey:
		oid, keyType = oidEd25519, ckkECEdwards
		value = append([]byte(nil), k.Seed()...)
		point = append([]byte(nil), k.Public().(ed25519.PublicKey)...)
	default:
		return fmt.Errorf("type de clé non supporté pour %s : %T", label, priv)
	}
	secmem.Lock(value)
	defer secmem.Wipe(value)
	params, _ := asn1.Marshal(oid)
	ecPoint, _ := asn1.Marshal(point) // CKA_EC_POINT : OCTET STRING DER
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	privTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, params),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, value),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	pubTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, params),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPoint),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	privObj, err := h.ctx.CreateObject(h.sess, privTmpl)
	// Le tampon passé au module contient la clé : on l'efface aussi.
	for _, a := range privTmpl {
		if a.Type == pkcs11.CKA_VALUE {
			secmem.Wipe(a.Value)
		}
	}
	if err != nil {
		return fmt.Errorf("import de %s dans le HSM: %w", label, err)
	}
	// Certains tokens ignorent silencieusement des attributs : on relit.
	got, err := h.ctx.GetAttributeValue(h.sess, privObj, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, nil), pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil)})
	if err != nil || len(got) != 2 || len(got[0].Value) != 1 || got[0].Value[0] != 1 || len(got[1].Value) != 1 || got[1].Value[0] != 0 {
		_ = h.ctx.DestroyObject(h.sess, privObj)
		return fmt.Errorf("%s : le token n'a pas appliqué CKA_SENSITIVE=vrai / CKA_EXTRACTABLE=faux, import annulé", label)
	}
	if _, err := h.ctx.CreateObject(h.sess, pubTmpl); err != nil {
		_ = h.ctx.DestroyObject(h.sess, privObj)
		return fmt.Errorf("import de la clé publique %s: %w", label, err)
	}
	return nil
}

// MigrateKeys importe dans le HSM chaque clé de signature du keystore
// logiciel, puis vérifie que la clé importée produit des signatures valides
// pour la même clé publique. Une clé déjà présente avec la même clé publique
// est ignorée (migration reprise après interruption) ; une clé différente
// sous le même label est une erreur.
func MigrateKeys(src *Software, dst Keystore) ([]string, error) {
	h, ok := dst.(*HSM)
	if !ok {
		return nil, errors.New("la destination de la migration doit être un HSM")
	}
	var done []string
	for _, k := range src.Keys() {
		priv, err := src.privateKey(k.Label)
		if err != nil {
			return done, fmt.Errorf("lecture de %s: %w", k.Label, err)
		}
		if existing, err := h.Signer(k.Label, "", false); err == nil {
			if Fingerprint(existing.Public()) != Fingerprint(priv.Public()) {
				return done, fmt.Errorf("le HSM contient déjà une clé %s différente : migration interrompue", k.Label)
			}
		} else if !errors.Is(err, ErrNotFound) {
			return done, err
		} else if err := h.importKey(k.Label, priv); err != nil {
			return done, err
		}
		if err := checkSigner(h, k.Label, priv.Public()); err != nil {
			return done, err
		}
		done = append(done, k.Label)
	}
	return done, nil
}

// checkSigner signe un condensat de test dans le HSM et le vérifie avec la
// clé publique d'origine.
func checkSigner(h *HSM, label string, want crypto.PublicKey) error {
	s, err := h.Signer(label, "", false)
	if err != nil {
		return err
	}
	if Fingerprint(s.Public()) != Fingerprint(want) {
		return fmt.Errorf("%s : la clé publique lue dans le HSM ne correspond pas", label)
	}
	msg := []byte("rempart-migration:" + label)
	switch pub := want.(type) {
	case *ecdsa.PublicKey:
		d := sha256.Sum256(msg)
		sig, err := s.Sign(rand.Reader, d[:], crypto.SHA256)
		if err != nil || !ecdsa.VerifyASN1(pub, d[:], sig) {
			return fmt.Errorf("%s : signature de contrôle invalide après import", label)
		}
	case ed25519.PublicKey:
		sig, err := s.Sign(rand.Reader, msg, crypto.Hash(0))
		if err != nil || !ed25519.Verify(pub, msg, sig) {
			return fmt.Errorf("%s : signature de contrôle invalide après import", label)
		}
	}
	return nil
}

// ProbeModule charge un module PKCS#11 et liste ses tokens, sans se
// connecter. Le module doit avoir été validé par AllowedModule.
func ProbeModule(module string) (ModuleInfo, []TokenInfo, error) {
	var mi ModuleInfo
	ctx, err := loadModule(module)
	if err != nil {
		return mi, nil, err
	}
	defer unloadModule(ctx)
	if info, err := ctx.GetInfo(); err == nil {
		mi = ModuleInfo{Path: module, Manufacturer: strings.TrimSpace(info.ManufacturerID), Description: strings.TrimSpace(info.LibraryDescription),
			Version:  fmt.Sprintf("%d.%d", info.LibraryVersion.Major, info.LibraryVersion.Minor),
			Cryptoki: fmt.Sprintf("%d.%d", info.CryptokiVersion.Major, info.CryptokiVersion.Minor)}
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return mi, nil, fmt.Errorf("C_GetSlotList: %w", err)
	}
	tokens := []TokenInfo{}
	for _, s := range slots {
		ti, err := ctx.GetTokenInfo(s)
		if err != nil {
			continue
		}
		tokens = append(tokens, tokenInfo(s, ti))
	}
	return mi, tokens, nil
}

func tokenInfo(slot uint, ti pkcs11.TokenInfo) TokenInfo {
	return TokenInfo{
		Slot: slot, Label: strings.TrimSpace(ti.Label), Manufacturer: strings.TrimSpace(ti.ManufacturerID),
		Model: strings.TrimSpace(ti.Model), Serial: strings.TrimSpace(ti.SerialNumber),
		Initialized:   ti.Flags&pkcs11.CKF_TOKEN_INITIALIZED != 0,
		LoginRequired: ti.Flags&pkcs11.CKF_LOGIN_REQUIRED != 0,
		PINCountLow:   ti.Flags&pkcs11.CKF_USER_PIN_COUNT_LOW != 0,
		PINFinalTry:   ti.Flags&pkcs11.CKF_USER_PIN_FINAL_TRY != 0,
		PINLocked:     ti.Flags&pkcs11.CKF_USER_PIN_LOCKED != 0,
	}
}

// TestToken se connecte au token, vérifie les mécanismes nécessaires puis
// exerce chacun avec des objets de session (CKA_TOKEN faux) : rien n'est
// écrit dans le token. allowFinalTry doit être vrai pour tenter une
// connexion quand le token signale qu'il ne reste qu'un essai de PIN.
func TestToken(module, label string, pin []byte, allowFinalTry bool) (TestReport, error) {
	rep := TestReport{}
	ctx, err := loadModule(module)
	if err != nil {
		return rep, err
	}
	defer unloadModule(ctx)
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return rep, fmt.Errorf("C_GetSlotList: %w", err)
	}
	var slot uint
	found := false
	for _, s := range slots {
		if ti, err := ctx.GetTokenInfo(s); err == nil && strings.TrimSpace(ti.Label) == label {
			slot, found = s, true
			rep.Token = tokenInfo(s, ti)
			break
		}
	}
	if !found {
		return rep, fmt.Errorf("token %q introuvable", label)
	}
	if rep.Token.PINLocked {
		return rep, errors.New("le PIN utilisateur de ce token est verrouillé : débloquez-le avec l'outil du constructeur")
	}
	if rep.Token.PINFinalTry && !allowFinalTry {
		return rep, errors.New("dernier essai de PIN avant verrouillage : confirmez explicitement pour tenter la connexion")
	}
	mechs, err := ctx.GetMechanismList(slot)
	if err != nil {
		return rep, fmt.Errorf("C_GetMechanismList: %w", err)
	}
	has := map[uint]bool{}
	for _, m := range mechs {
		has[m.Mechanism] = true
	}
	need := []struct {
		id       uint
		name     string
		required bool
	}{
		{pkcs11.CKM_AES_KEY_GEN, "CKM_AES_KEY_GEN", true},
		{pkcs11.CKM_AES_GCM, "CKM_AES_GCM", true},
		{pkcs11.CKM_EC_KEY_PAIR_GEN, "CKM_EC_KEY_PAIR_GEN", true},
		{pkcs11.CKM_ECDSA, "CKM_ECDSA", true},
		{ckmECEdwardsKeyPairGen, "CKM_EC_EDWARDS_KEY_PAIR_GEN", false},
		{ckmEdDSA, "CKM_EDDSA", false},
	}
	for _, n := range need {
		rep.Mechanisms = append(rep.Mechanisms, Mechanism{Name: n.name, Present: has[n.id], Required: n.required})
	}
	sess, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return rep, fmt.Errorf("C_OpenSession: %w", err)
	}
	defer ctx.CloseSession(sess)
	// Limite connue : miekg/pkcs11 attend une chaîne Go, que ni Go ni la copie
	// C faite par la bibliothèque ne permettent d'effacer. La tranche
	// d'origine est effacée par l'appelant ; le processus est non-dumpable.
	if err := ctx.Login(sess, pkcs11.CKU_USER, string(pin)); err != nil {
		var perr pkcs11.Error
		if !(errors.As(err, &perr) && perr == pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return rep, fmt.Errorf("connexion refusée par le token (PIN incorrect ?) : %w", err)
		}
	}
	defer ctx.Logout(sess)
	rep.Login = true
	for _, m := range rep.Mechanisms {
		if m.Required && !m.Present {
			return rep, fmt.Errorf("mécanisme %s absent : ce token ne convient pas", m.Name)
		}
	}
	if err := sessionSelfTest(ctx, sess); err != nil {
		return rep, err
	}
	rep.SelfTest = true
	return rep, nil
}

// sessionSelfTest génère une clé AES et une paire P-256 éphémères, chiffre
// et déchiffre en AES-256-GCM, signe et vérifie en ECDSA. Les objets de
// session disparaissent à la fermeture de la session.
func sessionSelfTest(ctx *pkcs11.Ctx, sess pkcs11.SessionHandle) error {
	aes, err := ctx.GenerateKey(sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	})
	if err != nil {
		return fmt.Errorf("auto-test : génération AES-256 refusée : %w", err)
	}
	defer ctx.DestroyObject(sess, aes)
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return err
	}
	msg := []byte("auto-test rempart")
	gp := pkcs11.NewGCMParams(iv, []byte("aad"), 128)
	if err := ctx.EncryptInit(sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gp)}, aes); err != nil {
		gp.Free()
		return fmt.Errorf("auto-test : AES-GCM refusé : %w", err)
	}
	ct, err := ctx.Encrypt(sess, msg)
	if real := gp.IV(); len(real) == 12 {
		iv = real
	}
	gp.Free()
	if err != nil {
		return fmt.Errorf("auto-test : chiffrement AES-GCM : %w", err)
	}
	gp = pkcs11.NewGCMParams(iv, []byte("aad"), 128)
	defer gp.Free()
	if err := ctx.DecryptInit(sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gp)}, aes); err != nil {
		return fmt.Errorf("auto-test : déchiffrement AES-GCM : %w", err)
	}
	pt, err := ctx.Decrypt(sess, ct)
	if err != nil || !bytes.Equal(pt, msg) {
		return errors.New("auto-test : le déchiffrement AES-GCM ne restitue pas le message")
	}
	params, _ := asn1.Marshal(oidP256)
	pub, priv, err := ctx.GenerateKeyPair(sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY), pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false), pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, params),
		},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY), pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false), pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true), pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		})
	if err != nil {
		return fmt.Errorf("auto-test : génération ECDSA P-256 refusée : %w", err)
	}
	defer ctx.DestroyObject(sess, pub)
	defer ctx.DestroyObject(sess, priv)
	d := sha256.Sum256(msg)
	if err := ctx.SignInit(sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, priv); err != nil {
		return fmt.Errorf("auto-test : signature ECDSA : %w", err)
	}
	sig, err := ctx.Sign(sess, d[:])
	if err != nil {
		return fmt.Errorf("auto-test : signature ECDSA : %w", err)
	}
	if err := ctx.VerifyInit(sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, pub); err != nil {
		return fmt.Errorf("auto-test : vérification ECDSA : %w", err)
	}
	if err := ctx.Verify(sess, d[:], sig); err != nil {
		return errors.New("auto-test : la signature ECDSA produite par le token est invalide")
	}
	return nil
}

func loadModule(module string) (*pkcs11.Ctx, error) {
	ctx := pkcs11.New(module)
	if ctx == nil {
		return nil, fmt.Errorf("impossible de charger le module PKCS#11 %q", module)
	}
	if err := ctx.Initialize(); err != nil {
		var perr pkcs11.Error
		if errors.As(err, &perr) && perr == pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			ctx.Destroy()
			return nil, errors.New("ce module est déjà utilisé par le keystore actif : il ne peut pas être testé à chaud")
		}
		ctx.Destroy()
		return nil, fmt.Errorf("C_Initialize: %w", err)
	}
	return ctx, nil
}

func unloadModule(ctx *pkcs11.Ctx) {
	_ = ctx.Finalize()
	ctx.Destroy()
}
