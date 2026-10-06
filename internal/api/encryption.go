// encryption.go - API de l'interrupteur DNS-over-TLS / DNS-over-HTTPS (Réglages → Chiffrement).
// GET rend l'état des deux écoutes ; PUT les allume ou les éteint à chaud, sans redémarrage.
// Contexte : Rempart ; adresses et ports restent dans le fichier de configuration (dot.listen, doh.listen).
package api

import (
	"net/http"

	"github.com/rempart-dns/rempart/internal/server"
	"github.com/rempart-dns/rempart/internal/state"
)

// encStatus : sans contrôleur (tests), DoT et DoH sont absents.
func (a *API) encStatus() server.EncryptionStatus {
	if a.Encrypted == nil {
		return server.EncryptionStatus{}
	}
	return a.Encrypted.Status()
}

func (a *API) getEncryption(w http.ResponseWriter, r *http.Request, _ string) {
	writeJSON(w, a.encStatus())
}

func (a *API) putEncryption(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		DoT      bool `json:"dot_enabled"`
		DoH      bool `json:"doh_enabled"`
		DoQ      bool `json:"doq_enabled"`
		DNSCrypt bool `json:"dnscrypt_enabled"`
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if a.Encrypted == nil {
		jsonError(w, http.StatusConflict, "écoutes chiffrées indisponibles")
		return
	}
	cur := a.encStatus()
	if (in.DoT && cur.DoT.Listen == "") || (in.DoH && cur.DoH.Listen == "") || (in.DoQ && cur.DoQ.Listen == "") || (in.DNSCrypt && cur.DNSCrypt.Listen == "") {
		jsonError(w, http.StatusConflict, "adresse d'écoute absente du fichier de configuration (dot.listen, doh.listen, doq.listen, dnscrypt.listen)")
		return
	}
	old := a.Store.Get().Encryption
	next := state.Encryption{DoTDisabled: !in.DoT, DoHDisabled: !in.DoH, DoQDisabled: !in.DoQ, DNSCryptEnabled: in.DNSCrypt}
	// Écoutes d'abord : un port occupé laisse l'état enregistré inchangé,
	// et le redémarrage suivant n'échouera pas sur ce choix.
	if err := a.Encrypted.Apply(next); err != nil {
		_ = a.Encrypted.Apply(old)
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	if err := a.Store.Update(func(s *state.State) error { s.Encryption = next; return nil }); err != nil {
		_ = a.Encrypted.Apply(old)
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if old != next {
		a.record(user, "chiffrement.modifié", "DoT "+onOff(in.DoT)+", DoH "+onOff(in.DoH)+", DoQ "+onOff(in.DoQ)+", DNSCrypt "+onOff(in.DNSCrypt))
	}
	writeJSON(w, a.encStatus())
}

func onOff(b bool) string {
	if b {
		return "activé"
	}
	return "désactivé"
}
