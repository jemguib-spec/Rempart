package api

// totp.go - double authentification par code à usage unique (TOTP, RFC 6238)
// et codes de secours. Le secret est stocké dans l'état scellé ; un pas déjà
// accepté ne peut pas être rejoué ; chaque code de secours ne sert qu'une fois.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rempart-dns/rempart/internal/state"
)

const (
	totpPeriod   = 30
	totpDigits   = 6
	totpIssuer   = "Rempart DNS"
	recoveryN    = 10
	challengeTTL = 5 * time.Minute
	challengeTry = 5
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func totpCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	o := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

// totpVerify accepte le pas courant et ses deux voisins (dérive d'horloge),
// à condition qu'ils soient postérieurs au dernier pas accepté. Il renvoie
// le pas reconnu, ou 0.
func totpVerify(secretB32, code string, now time.Time, last int64) int64 {
	secret, err := b32.DecodeString(secretB32)
	if err != nil || len(code) != totpDigits {
		return 0
	}
	cur := now.Unix() / totpPeriod
	var found int64
	for d := int64(-1); d <= 1; d++ {
		s := cur + d
		// Pas de court-circuit : même durée quel que soit le pas reconnu.
		if subtle.ConstantTimeCompare([]byte(totpCode(secret, s)), []byte(code)) == 1 && s > last && found == 0 {
			found = s
		}
	}
	return found
}

func otpURI(user, secret string) string {
	label := url.PathEscape(totpIssuer + ":" + user)
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", totpIssuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(totpDigits))
	v.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + strings.ReplaceAll(v.Encode(), "+", "%20")
}

// normCode retire espaces et tirets : « 123 456 » ou « abcd-efgh-… ».
func normCode(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	return strings.NewReplacer(" ", "", "-", "").Replace(c)
}

// newRecoveryCodes renvoie les codes en clair (affichés une fois) et leurs
// empreintes. 80 bits chacun : une empreinte SHA-256 suffit.
func newRecoveryCodes() (plain, hashes []string) {
	enc := base32.NewEncoding("abcdefghijkmnpqrstuvwxyz23456789").WithPadding(base32.NoPadding)
	for i := 0; i < recoveryN; i++ {
		b := make([]byte, 10)
		_, _ = rand.Read(b)
		s := enc.EncodeToString(b) // 16 caractères
		plain = append(plain, s[0:4]+"-"+s[4:8]+"-"+s[8:12]+"-"+s[12:16])
		hashes = append(hashes, recoveryHash(s))
	}
	return
}

func recoveryHash(norm string) string {
	h := sha256.Sum256([]byte("rempart-recovery:" + norm))
	return hex.EncodeToString(h[:])
}

// consumeSecondFactor vérifie un code TOTP ou un code de secours dans s et
// met à jour l'état (dernier pas, code de secours consommé). Il renvoie la
// méthode reconnue.
func consumeSecondFactor(s *state.State, code string) (string, error) {
	c := normCode(code)
	if s.Admin.TOTPSecret == "" {
		return "", errors.New("double authentification non activée")
	}
	if len(c) == totpDigits {
		if step := totpVerify(s.Admin.TOTPSecret, c, time.Now(), s.Admin.TOTPLast); step != 0 {
			s.Admin.TOTPLast = step
			return "totp", nil
		}
		return "", errors.New("code incorrect ou déjà utilisé")
	}
	h := recoveryHash(c)
	for i, r := range s.Admin.Recovery {
		if subtle.ConstantTimeCompare([]byte(r), []byte(h)) == 1 {
			s.Admin.Recovery = append(s.Admin.Recovery[:i:i], s.Admin.Recovery[i+1:]...)
			return "code de secours", nil
		}
	}
	return "", errors.New("code incorrect ou déjà utilisé")
}

// ---- défi de connexion : mot de passe vérifié, second facteur attendu ----

type challenge struct {
	user    string
	ip      netip.Addr
	expires time.Time
	tries   int
}

type challenges struct {
	mu sync.Mutex
	m  map[string]*challenge // sha256(jeton) -> défi
}

func (c *challenges) create(user string, ip netip.Addr) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := base64.RawURLEncoding.EncodeToString(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*challenge{}
	}
	now := time.Now()
	for k, v := range c.m {
		if now.After(v.expires) {
			delete(c.m, k)
		}
	}
	c.m[hashToken(tok)] = &challenge{user: user, ip: ip, expires: now.Add(challengeTTL)}
	return tok
}

// get renvoie le défi s'il est valide pour cette adresse ; fail le compte
// comme un essai manqué (et l'efface au-delà de la limite) ; done l'efface.
func (c *challenges) get(tok string, ip netip.Addr) (*challenge, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[hashToken(tok)]
	if !ok || time.Now().After(v.expires) || v.ip != ip {
		return nil, false
	}
	return v, true
}

func (c *challenges) fail(tok string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.m[hashToken(tok)]; ok {
		v.tries++
		if v.tries >= challengeTry {
			delete(c.m, hashToken(tok))
		}
	}
}

func (c *challenges) done(tok string) {
	c.mu.Lock()
	delete(c.m, hashToken(tok))
	c.mu.Unlock()
}

func (c *challenges) clear() {
	c.mu.Lock()
	c.m = map[string]*challenge{}
	c.mu.Unlock()
}

// ---- inscription : secret en attente de confirmation ----

type pendingOTP struct {
	mu      sync.Mutex
	secret  string
	expires time.Time
}

func (p *pendingOTP) take() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.secret == "" || time.Now().After(p.expires) {
		return ""
	}
	return p.secret
}

// ---- points d'entrée ----

func (a *API) loginOTP(w http.ResponseWriter, r *http.Request) {
	ip := a.clientIP(r)
	if d := a.guard.blocked(ip); d > 0 {
		jsonError(w, http.StatusTooManyRequests, fmt.Sprintf("trop d'échecs, réessayez dans %s", d.Round(time.Second)))
		return
	}
	var in struct{ Challenge, Code string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	ch, ok := a.chal.get(in.Challenge, ip)
	if !ok {
		jsonError(w, http.StatusUnauthorized, "étape expirée, reconnectez-vous")
		return
	}
	var method string
	err := a.Store.Update(func(s *state.State) error {
		m, err := consumeSecondFactor(s, in.Code)
		method = m
		return err
	})
	if err != nil {
		a.guard.failed(ip)
		a.chal.fail(in.Challenge)
		a.record(ch.user, "connexion.otp-échec", "depuis "+ip.String())
		jsonError(w, http.StatusUnauthorized, err.Error())
		return
	}
	a.chal.done(in.Challenge)
	a.guard.success(ip)
	a.startSession(w, localPrincipal(ch.user))
	left := len(a.Store.Get().Admin.Recovery)
	a.record(ch.user, "connexion", fmt.Sprintf("depuis %s (%s)", ip, method))
	writeJSON(w, map[string]any{"user": ch.user, "method": method, "recovery_left": left})
}

func (a *API) startSession(w http.ResponseWriter, p Principal) {
	tok := a.sess.create(p)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: a.SecureCk, SameSite: http.SameSiteStrictMode, MaxAge: int(a.sess.ttl.Seconds())})
}

func (a *API) otpStatus(w http.ResponseWriter, _ *http.Request, _ string) {
	adm := a.Store.Get().Admin
	writeJSON(w, map[string]any{"enabled": adm.TOTPSecret != "", "recovery_left": len(adm.Recovery)})
}

func (a *API) otpSetup(w http.ResponseWriter, _ *http.Request, user string) {
	if a.Store.Get().Admin.TOTPSecret != "" {
		jsonError(w, http.StatusConflict, "la double authentification est déjà active : désactivez-la d'abord")
		return
	}
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	sec := b32.EncodeToString(b)
	a.otpNew.mu.Lock()
	a.otpNew.secret, a.otpNew.expires = sec, time.Now().Add(10*time.Minute)
	a.otpNew.mu.Unlock()
	uri := otpURI(user, sec)
	m, err := qrEncode(uri)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	qr := "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(qrSVG(m)))
	writeJSON(w, map[string]string{"secret": sec, "uri": uri, "qr": qr, "issuer": totpIssuer, "account": user})
}

func (a *API) otpEnable(w http.ResponseWriter, r *http.Request, user string) {
	var in struct{ Code, Password string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !CheckPassword(in.Password, a.Store.Get().Admin.PasswordHash) {
		jsonError(w, http.StatusForbidden, "mot de passe incorrect")
		return
	}
	sec := a.otpNew.take()
	if sec == "" {
		jsonError(w, http.StatusBadRequest, "l'inscription a expiré, recommencez")
		return
	}
	step := totpVerify(sec, normCode(in.Code), time.Now(), 0)
	if step == 0 {
		jsonError(w, http.StatusBadRequest, "code incorrect : vérifiez l'heure du téléphone et réessayez")
		return
	}
	plain, hashes := newRecoveryCodes()
	if err := a.Store.Update(func(s *state.State) error {
		if s.Admin.TOTPSecret != "" {
			return errors.New("déjà active")
		}
		s.Admin.TOTPSecret, s.Admin.TOTPLast, s.Admin.Recovery = sec, step, hashes
		return nil
	}); err != nil {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	a.otpNew.mu.Lock()
	a.otpNew.secret = ""
	a.otpNew.mu.Unlock()
	a.record(user, "otp.activé", "")
	writeJSON(w, map[string]any{"recovery": plain})
}

// otpReauth vérifie mot de passe et second facteur avant une opération
// sensible (désactivation, nouveaux codes de secours).
func (a *API) otpReauth(w http.ResponseWriter, r *http.Request, apply func(*state.State)) bool {
	var in struct{ Code, Password string }
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return false
	}
	if !CheckPassword(in.Password, a.Store.Get().Admin.PasswordHash) {
		jsonError(w, http.StatusForbidden, "mot de passe incorrect")
		return false
	}
	if err := a.Store.Update(func(s *state.State) error {
		if _, err := consumeSecondFactor(s, in.Code); err != nil {
			return err
		}
		apply(s)
		return nil
	}); err != nil {
		jsonError(w, http.StatusForbidden, err.Error())
		return false
	}
	return true
}

func (a *API) otpDisable(w http.ResponseWriter, r *http.Request, user string) {
	if !a.otpReauth(w, r, func(s *state.State) {
		s.Admin.TOTPSecret, s.Admin.TOTPLast, s.Admin.Recovery = "", 0, nil
	}) {
		return
	}
	a.record(user, "otp.désactivé", "")
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *API) otpRecovery(w http.ResponseWriter, r *http.Request, user string) {
	plain, hashes := newRecoveryCodes()
	if !a.otpReauth(w, r, func(s *state.State) { s.Admin.Recovery = hashes }) {
		return
	}
	a.record(user, "otp.codes-de-secours-renouvelés", "")
	writeJSON(w, map[string]any{"recovery": plain})
}
