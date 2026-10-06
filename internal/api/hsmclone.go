package api

// hsmclone.go - passage à un autre token qui contient les mêmes clés
// (clonage ou restauration par l'outil du constructeur). Rempart ne copie
// jamais lui-même des clés non extractibles ; il vérifie le token cible,
// puis programme la bascule au prochain démarrage.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/sealed"
	"github.com/rempart-dns/rempart/internal/secmem"
)

var cloneVerified struct {
	sync.Mutex
	module, token, kek string
	at                 time.Time
	failures           []time.Time
}

// cloneSamples : clés de données enveloppées par la KEK en service, que la
// KEK du token cible doit savoir ouvrir (état scellé, tête d'audit…).
func (a *API) cloneSamples() [][2][]byte {
	var out [][2][]byte
	entries, _ := os.ReadDir(a.DataDir)
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".sealed" {
			continue
		}
		p := filepath.Join(a.DataDir, e.Name())
		blob, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if w, ok := sealed.WrappedKey(blob); ok {
			out = append(out, [2][]byte{w, sealed.FileAAD(p)})
		}
		if len(out) >= 3 {
			break
		}
	}
	return out
}

func (a *API) hsmCloneVerify(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		Module, Token string
		PIN           string `json:"pin"`
		KEKLabel      string `json:"kek_label"`
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, "requête invalide")
		return
	}
	pin := in.PIN
	in.PIN = ""
	if a.KS.Backend() != "pkcs11" {
		jsonError(w, http.StatusBadRequest, "Rempart n'utilise pas encore de HSM : utilisez l'assistant de passage au HSM")
		return
	}
	if err := keystore.AllowedModule(in.Module, a.ModuleDirs); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.KEKLabel != "" && !keystore.ValidLabel(in.KEKLabel) {
		jsonError(w, http.StatusBadRequest, "label de KEK invalide")
		return
	}
	cloneVerified.Lock()
	recent := cloneVerified.failures[:0]
	for _, t := range cloneVerified.failures {
		if time.Since(t) < 15*time.Minute {
			recent = append(recent, t)
		}
	}
	cloneVerified.failures = recent
	blocked := len(recent) >= 2
	cloneVerified.Unlock()
	if blocked {
		jsonError(w, http.StatusTooManyRequests, "deux échecs récents : attendez 15 minutes et vérifiez le PIN (risque de verrouillage du token)")
		return
	}
	samples := a.cloneSamples()
	rep, err := keystore.VerifyClone(a.KS, keystore.PKCS11Config{Module: in.Module, TokenLabel: in.Token, PIN: pin, KEKLabel: in.KEKLabel}, samples)
	b := []byte(pin)
	secmem.Wipe(b)
	if err != nil {
		cloneVerified.Lock()
		cloneVerified.failures = append(cloneVerified.failures, time.Now())
		cloneVerified.Unlock()
		a.record(user, "hsm.clone.échec", fmt.Sprintf("token %q : %v", in.Token, err))
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if rep.OK {
		cloneVerified.Lock()
		cloneVerified.module, cloneVerified.token, cloneVerified.kek, cloneVerified.at = in.Module, in.Token, rep.KEK.Label, time.Now()
		cloneVerified.Unlock()
	}
	a.record(user, "hsm.clone.vérifié", fmt.Sprintf("token %q : %d clé(s), conforme=%v", in.Token, len(rep.Keys), rep.OK))
	writeJSON(w, rep)
}

func (a *API) hsmCloneApply(w http.ResponseWriter, r *http.Request, user string) {
	var in struct{ Module, Token string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	cloneVerified.Lock()
	ok := cloneVerified.module == in.Module && cloneVerified.token == in.Token && time.Since(cloneVerified.at) < 15*time.Minute
	kek := cloneVerified.kek
	cloneVerified.Unlock()
	if !ok {
		jsonError(w, http.StatusBadRequest, "vérifiez d'abord ce token (vérification valable 15 minutes)")
		return
	}
	if ov, _ := keystore.LoadOverride(a.DataDir); ov != nil && ov.PendingMigration {
		jsonError(w, http.StatusConflict, "une migration est déjà programmée")
		return
	}
	// Pas de migration : le token cible contient déjà les mêmes clés.
	ov := &keystore.Override{Backend: "pkcs11", Module: in.Module, TokenLabel: in.Token, KEKLabel: kek,
		RequestedBy: user, RequestedAt: time.Now().UTC()}
	if err := ov.Save(a.DataDir); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.record(user, "hsm.clone.bascule", fmt.Sprintf("module %s, token %q au prochain démarrage", in.Module, in.Token))
	a.hsmStatus(w, r, user)
}

