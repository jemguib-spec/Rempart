package api

// passkeys.go - clés d'accès WebAuthn du compte local : inscription (après
// mot de passe et second facteur), connexion en second facteur, ou sans mot
// de passe quand l'authentificateur vérifie l'utilisateur (PIN, biométrie).

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/webauthn"
)

const (
	passkeyTTL  = 2 * time.Minute
	maxPasskeys = 10
)

type waChallenge struct {
	purpose string // register | 2fa | passwordless
	ip      netip.Addr
	rpID    string
	origin  string
	pwChal  string // défi du mot de passe (second facteur)
	expires time.Time
}

type waChallenges struct {
	mu sync.Mutex
	m  map[string]*waChallenge // sha256(défi) -> état
}

func (c *waChallenges) create(ch *waChallenge) []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*waChallenge{}
	}
	now := time.Now()
	for k, v := range c.m {
		if now.After(v.expires) {
			delete(c.m, k)
		}
	}
	if len(c.m) > 1000 { // une rafale de demandes ne fait pas grossir la mémoire
		for k := range c.m {
			delete(c.m, k)
			break
		}
	}
	ch.expires = now.Add(passkeyTTL)
	c.m[hashToken(string(b))] = ch
	return b
}

// take retire et renvoie le défi : un défi ne sert qu'une fois.
func (c *waChallenges) take(raw []byte, ip netip.Addr, purpose ...string) (*waChallenge, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := hashToken(string(raw))
	v, ok := c.m[k]
	delete(c.m, k)
	if !ok || time.Now().After(v.expires) || v.ip != ip {
		return nil, false
	}
	for _, p := range purpose {
		if p == v.purpose {
			return v, true
		}
	}
	return nil, false
}

// relyingParty déduit l'identifiant de site et l'origine de la requête. Le
// navigateur ne laisse pas une page choisir l'en-tête Host d'une autre
// origine ; WebAuthn refuse une adresse IP comme identifiant.
func (a *API) relyingParty(r *http.Request) (rpID, origin string, err error) {
	host := r.Host
	h := host
	if hh, _, e := net.SplitHostPort(host); e == nil {
		h = hh
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "" {
		return "", "", errors.New("en-tête Host absent")
	}
	if _, e := netip.ParseAddr(h); e == nil {
		return "", "", errors.New("les clés d'accès exigent un nom (rempart.maison.lan…), pas une adresse IP : ouvrez l'interface par son nom")
	}
	scheme := "https"
	if r.TLS == nil {
		if h != "localhost" {
			return "", "", errors.New("les clés d'accès exigent HTTPS")
		}
		scheme = "http"
	}
	return h, scheme + "://" + strings.ToLower(host), nil
}

var b64u = base64.RawURLEncoding

func (a *API) passkeyOptions(ch []byte, rpID string, uv string, allow []state.Passkey) map[string]any {
	ids := []map[string]string{}
	for _, p := range allow {
		if p.RPID == rpID {
			ids = append(ids, map[string]string{"type": "public-key", "id": p.ID})
		}
	}
	return map[string]any{"challenge": b64u.EncodeToString(ch), "rpId": rpID, "timeout": passkeyTTL.Milliseconds(),
		"userVerification": uv, "allowCredentials": ids}
}

// ---- inscription ----

func (a *API) passkeyList(w http.ResponseWriter, _ *http.Request, _ string) {
	out := []map[string]any{}
	for _, p := range a.Store.Get().Admin.Passkeys {
		out = append(out, map[string]any{"id": p.ID, "name": p.Name, "rp_id": p.RPID, "synced": p.Synced, "created": p.Created, "last_used": p.LastUsed, "alg": p.Alg})
	}
	writeJSON(w, out)
}

// reauthLocal vérifie le mot de passe et, si la double authentification
// TOTP est active, un code.
func (a *API) reauthLocal(s *state.State, password, code string) error {
	if !CheckPassword(password, s.Admin.PasswordHash) {
		return errors.New("mot de passe incorrect")
	}
	if s.Admin.TOTPSecret != "" {
		if _, err := consumeSecondFactor(s, code); err != nil {
			return err
		}
	}
	return nil
}

func (a *API) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request, user string) {
	var in struct{ Password, Code string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	rpID, origin, err := a.relyingParty(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	var adm state.Admin
	err = a.Store.Update(func(s *state.State) error {
		if err := a.reauthLocal(s, in.Password, in.Code); err != nil {
			return err
		}
		if len(s.Admin.Passkeys) >= maxPasskeys {
			return fmt.Errorf("%d clés d'accès au plus", maxPasskeys)
		}
		if s.Admin.WebAuthnUser == "" {
			b := make([]byte, 32)
			_, _ = rand.Read(b)
			s.Admin.WebAuthnUser = b64u.EncodeToString(b)
		}
		adm = s.Admin
		return nil
	})
	if err != nil {
		a.guard.failed(a.clientIP(r))
		jsonError(w, http.StatusForbidden, err.Error())
		return
	}
	ch := a.wa.create(&waChallenge{purpose: "register", ip: a.clientIP(r), rpID: rpID, origin: origin})
	exclude := []map[string]string{}
	for _, p := range adm.Passkeys {
		exclude = append(exclude, map[string]string{"type": "public-key", "id": p.ID})
	}
	writeJSON(w, map[string]any{
		"challenge": b64u.EncodeToString(ch),
		"rp":        map[string]string{"id": rpID, "name": "Rempart DNS"},
		"user":      map[string]string{"id": adm.WebAuthnUser, "name": adm.Username, "displayName": "Administrateur Rempart (" + adm.Username + ")"},
		"pubKeyCredParams": []map[string]any{{"type": "public-key", "alg": webauthn.AlgES256}, {"type": "public-key", "alg": webauthn.AlgEdDSA},
			{"type": "public-key", "alg": webauthn.AlgRS256}},
		"timeout":                passkeyTTL.Milliseconds(),
		"attestation":            "none",
		"excludeCredentials":     exclude,
		"authenticatorSelection": map[string]any{"residentKey": "preferred", "requireResidentKey": false, "userVerification": "preferred"},
	})
}

func (a *API) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		Name, Challenge, ClientDataJSON, AttestationObject string
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 60 {
		jsonError(w, http.StatusBadRequest, "nom de la clé : 1 à 60 caractères")
		return
	}
	raw, err1 := b64u.DecodeString(in.Challenge)
	cd, err2 := b64u.DecodeString(in.ClientDataJSON)
	att, err3 := b64u.DecodeString(in.AttestationObject)
	if errors.Join(err1, err2, err3) != nil {
		jsonError(w, http.StatusBadRequest, "encodage base64url attendu")
		return
	}
	ch, ok := a.wa.take(raw, a.clientIP(r), "register")
	if !ok {
		jsonError(w, http.StatusBadRequest, "inscription expirée : recommencez")
		return
	}
	cred, err := webauthn.VerifyRegistration(webauthn.Registration{ClientDataJSON: cd, AttestationObject: att}, raw, ch.rpID, ch.origin, false)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "clé refusée : "+err.Error())
		return
	}
	id := b64u.EncodeToString(cred.ID)
	err = a.Store.Update(func(s *state.State) error {
		for _, p := range s.Admin.Passkeys {
			if p.ID == id {
				return errors.New("cette clé est déjà enregistrée")
			}
		}
		if len(s.Admin.Passkeys) >= maxPasskeys {
			return fmt.Errorf("%d clés d'accès au plus", maxPasskeys)
		}
		s.Admin.Passkeys = append(s.Admin.Passkeys, state.Passkey{ID: id, Name: name, PublicKey: base64.StdEncoding.EncodeToString(cred.PublicKey),
			Alg: cred.Alg, SignCount: cred.SignCount, RPID: ch.rpID, Synced: cred.BackupEligible, Created: time.Now().UTC()})
		return nil
	})
	if err != nil {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	a.record(user, "passkey.ajoutée", fmt.Sprintf("%s (%s)", name, ch.rpID))
	a.passkeyList(w, r, user)
}

func (a *API) passkeyDelete(w http.ResponseWriter, r *http.Request, user string) {
	var in struct{ Password, Code string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := r.PathValue("id")
	var name string
	err := a.Store.Update(func(s *state.State) error {
		if err := a.reauthLocal(s, in.Password, in.Code); err != nil {
			return err
		}
		for i, p := range s.Admin.Passkeys {
			if p.ID == id {
				name = p.Name
				s.Admin.Passkeys = append(s.Admin.Passkeys[:i:i], s.Admin.Passkeys[i+1:]...)
				return nil
			}
		}
		return errors.New("clé introuvable")
	})
	if err != nil {
		jsonError(w, http.StatusForbidden, err.Error())
		return
	}
	a.record(user, "passkey.supprimée", name)
	a.passkeyList(w, r, user)
}

// ---- connexion ----

func (a *API) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	ip := a.clientIP(r)
	if d := a.guard.blocked(ip); d > 0 {
		jsonError(w, http.StatusTooManyRequests, fmt.Sprintf("trop d'échecs, réessayez dans %s", d.Round(time.Second)))
		return
	}
	var in struct{ Challenge string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	rpID, origin, err := a.relyingParty(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	adm := a.Store.Get().Admin
	if in.Challenge != "" {
		// Second facteur : le mot de passe a été vérifié.
		if _, ok := a.chal.get(in.Challenge, ip); !ok {
			jsonError(w, http.StatusUnauthorized, "étape expirée, reconnectez-vous")
			return
		}
		if len(adm.Passkeys) == 0 {
			jsonError(w, http.StatusBadRequest, "aucune clé d'accès enregistrée")
			return
		}
		ch := a.wa.create(&waChallenge{purpose: "2fa", ip: ip, rpID: rpID, origin: origin, pwChal: in.Challenge})
		writeJSON(w, a.passkeyOptions(ch, rpID, "preferred", adm.Passkeys))
		return
	}
	// Sans mot de passe : clé détectable, utilisateur vérifié exigé. La
	// réponse ne révèle pas si des clés existent.
	ch := a.wa.create(&waChallenge{purpose: "passwordless", ip: ip, rpID: rpID, origin: origin})
	writeJSON(w, a.passkeyOptions(ch, rpID, "required", nil))
}

func (a *API) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	ip := a.clientIP(r)
	if d := a.guard.blocked(ip); d > 0 {
		jsonError(w, http.StatusTooManyRequests, fmt.Sprintf("trop d'échecs, réessayez dans %s", d.Round(time.Second)))
		return
	}
	var in struct {
		Challenge, ID, ClientDataJSON, AuthenticatorData, Signature, UserHandle string
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	fail := func(why string) {
		a.guard.failed(ip)
		a.record("", "connexion.passkey-échec", why+" depuis "+ip.String())
		jsonError(w, http.StatusUnauthorized, "clé d'accès refusée")
	}
	raw, err := b64u.DecodeString(in.Challenge)
	if err != nil {
		fail("défi illisible")
		return
	}
	ch, ok := a.wa.take(raw, ip, "2fa", "passwordless")
	if !ok {
		jsonError(w, http.StatusUnauthorized, "étape expirée, recommencez")
		return
	}
	var as webauthn.Assertion
	var errs [4]error
	as.CredentialID, errs[0] = b64u.DecodeString(in.ID)
	as.ClientDataJSON, errs[1] = b64u.DecodeString(in.ClientDataJSON)
	as.AuthenticatorData, errs[2] = b64u.DecodeString(in.AuthenticatorData)
	as.Signature, errs[3] = b64u.DecodeString(in.Signature)
	if errors.Join(errs[:]...) != nil {
		fail("encodage invalide")
		return
	}
	passwordless := ch.purpose == "passwordless"
	if ch.purpose == "2fa" {
		if _, ok := a.chal.get(ch.pwChal, ip); !ok {
			jsonError(w, http.StatusUnauthorized, "étape expirée, reconnectez-vous")
			return
		}
	}
	var userName, keyName string
	err = a.Store.Update(func(s *state.State) error {
		if passwordless && in.UserHandle != "" && in.UserHandle != s.Admin.WebAuthnUser {
			return errors.New("compte inconnu")
		}
		for i := range s.Admin.Passkeys {
			p := &s.Admin.Passkeys[i]
			if p.ID != in.ID || p.RPID != ch.rpID {
				continue
			}
			pub, err := base64.StdEncoding.DecodeString(p.PublicKey)
			if err != nil {
				return err
			}
			n, err := webauthn.VerifyAssertion(as, webauthn.Credential{ID: as.CredentialID, PublicKey: pub, Alg: p.Alg, SignCount: p.SignCount}, raw, ch.rpID, ch.origin, passwordless)
			if err != nil {
				return err
			}
			p.SignCount, p.LastUsed = n, time.Now().UTC()
			userName, keyName = s.Admin.Username, p.Name
			return nil
		}
		return errors.New("clé inconnue")
	})
	if err != nil {
		if ch.purpose == "2fa" {
			a.chal.fail(ch.pwChal)
		}
		fail(err.Error())
		return
	}
	if ch.purpose == "2fa" {
		a.chal.done(ch.pwChal)
	}
	a.guard.success(ip)
	a.startSession(w, localPrincipal(userName))
	how := "clé d'accès en second facteur"
	if passwordless {
		how = "clé d'accès sans mot de passe"
	}
	a.record(userName, "connexion", fmt.Sprintf("%s (%s) depuis %s", how, keyName, ip))
	writeJSON(w, map[string]any{"user": userName, "method": "passkey"})
}
