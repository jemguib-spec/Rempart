// pkcs11_clone.go - vérification d'un token cloné avant d'y basculer.
//
// Les clés de Rempart sont créées non extractibles : elles ne peuvent pas
// être copiées d'un HSM à un autre par Rempart. Le constructeur sait cloner
// un token (sauvegarde chiffrée, clonage entre partitions) ; VerifyClone
// contrôle ensuite, sans rien écrire dans le token cible, que celui-ci
// contient exactement les mêmes clés : mêmes clés publiques, signatures de
// contrôle valides, KEK capable d'ouvrir les données actuelles.

//go:build cgo

package keystore

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/miekg/pkcs11"
	"github.com/rempart-dns/rempart/internal/secmem"
)

// CloneCheck : résultat du contrôle d'une clé.
type CloneCheck struct {
	Label string `json:"label"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// CloneReport : résultat de VerifyClone.
type CloneReport struct {
	Token string       `json:"token"`
	Keys  []CloneCheck `json:"keys"`
	KEK   CloneCheck   `json:"kek"`
	OK    bool         `json:"ok"`
}

func sameFile(a, b string) bool {
	x, err1 := filepath.EvalSymlinks(a)
	y, err2 := filepath.EvalSymlinks(b)
	return err1 == nil && err2 == nil && x == y
}

// VerifyClone ouvre le token cible en lecture et le compare au keystore en
// service. samples : clés de données enveloppées par la KEK actuelle, avec
// leur donnée associée, que la KEK du token cible doit savoir ouvrir.
func VerifyClone(active Keystore, cfg PKCS11Config, samples [][2][]byte) (CloneReport, error) {
	rep := CloneReport{Token: cfg.TokenLabel}
	cur, ok := active.(*HSM)
	if !ok {
		return rep, errors.New("le keystore en service n'est pas un HSM")
	}
	if cfg.KEKLabel == "" {
		cfg.KEKLabel = cur.cfg.KEKLabel
	}
	if sameFile(cfg.Module, cur.cfg.Module) && cfg.TokenLabel == cur.cfg.TokenLabel {
		return rep, errors.New("c'est le token en service")
	}
	var ctx *pkcs11.Ctx
	shared := sameFile(cfg.Module, cur.cfg.Module)
	if shared {
		// Même bibliothèque : un second C_Initialize/C_Finalize couperait
		// le token en service ; on réutilise le contexte chargé.
		ctx = cur.ctx
	} else {
		ctx = pkcs11.New(cfg.Module)
		if ctx == nil {
			return rep, fmt.Errorf("impossible de charger le module PKCS#11 %q", cfg.Module)
		}
		if err := ctx.Initialize(); err != nil {
			var perr pkcs11.Error
			if !(errors.As(err, &perr) && perr == pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
				return rep, fmt.Errorf("C_Initialize: %w", err)
			}
		}
		defer func() { ctx.Finalize(); ctx.Destroy() }()
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return rep, err
	}
	var slot uint
	found := false
	for _, s := range slots {
		if ti, err := ctx.GetTokenInfo(s); err == nil && ti.Label == cfg.TokenLabel {
			slot, found = s, true
			break
		}
	}
	if !found {
		return rep, fmt.Errorf("token PKCS#11 %q introuvable", cfg.TokenLabel)
	}
	// Session en lecture seule : rien ne peut être créé dans le token cible.
	sess, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return rep, fmt.Errorf("C_OpenSession: %w", err)
	}
	defer ctx.CloseSession(sess)
	pin := []byte(cfg.PIN)
	defer secmem.Wipe(pin)
	if err := ctx.Login(sess, pkcs11.CKU_USER, string(pin)); err != nil {
		var perr pkcs11.Error
		if !(errors.As(err, &perr) && perr == pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return rep, fmt.Errorf("C_Login (PIN incorrect ?): %w", err)
		}
	}
	defer ctx.Logout(sess)
	tgt := &HSM{cfg: cfg, ctx: ctx, slot: slot, sess: sess, cache: map[string]*hsmSigner{}}

	rep.OK = true
	for _, k := range cur.Keys() {
		c := CloneCheck{Label: k.Label}
		want, err := cur.Signer(k.Label, "", false)
		if err == nil {
			err = checkSigner(tgt, k.Label, want.Public())
		}
		if err == nil {
			err = tgt.checkNonExtractable(k.Label)
		}
		if err != nil {
			c.Error, rep.OK = err.Error(), false
		} else {
			c.OK = true
		}
		rep.Keys = append(rep.Keys, c)
	}
	rep.KEK = CloneCheck{Label: cfg.KEKLabel}
	objs, err := tgt.find([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, cfg.KEKLabel),
	})
	switch {
	case err != nil:
		rep.KEK.Error = err.Error()
	case len(objs) == 0:
		rep.KEK.Error = "KEK absente du token cible"
	default:
		tgt.kek = objs[0]
		rep.KEK.OK = true
		for _, s := range samples {
			dek, err := tgt.Unwrap(s[0], s[1])
			if err != nil {
				rep.KEK.OK, rep.KEK.Error = false, "la KEK du token cible n'ouvre pas les données actuelles : "+err.Error()
				break
			}
			secmem.Wipe(dek)
		}
		if rep.KEK.OK && len(samples) == 0 {
			rep.KEK.OK, rep.KEK.Error = false, "aucune donnée chiffrée pour contrôler la KEK"
		}
	}
	rep.OK = rep.OK && rep.KEK.OK
	return rep, nil
}

// checkNonExtractable vérifie qu'une clé privée du token ne peut pas en
// sortir.
func (h *HSM) checkNonExtractable(label string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	objs, err := h.find([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	})
	if err != nil || len(objs) == 0 {
		return fmt.Errorf("%s : clé privée introuvable", label)
	}
	attrs, err := h.ctx.GetAttributeValue(h.sess, objs[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, nil),
	})
	if err != nil {
		return err
	}
	for _, a := range attrs {
		v := len(a.Value) == 1 && a.Value[0] == 1
		if a.Type == pkcs11.CKA_EXTRACTABLE && v {
			return fmt.Errorf("%s : clé extractible dans le token cible", label)
		}
		if a.Type == pkcs11.CKA_SENSITIVE && !v {
			return fmt.Errorf("%s : clé non sensible dans le token cible", label)
		}
	}
	return nil
}
