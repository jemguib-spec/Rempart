// tokens.go - jetons d'API porteurs (création, révocation, authentification par portée).
// Jeton rmp_ + 256 bits, seul le SHA-256 est conservé dans l'état scellé.
// Rempart ; utilisé par requireAuth dans api.go.

package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rempart-dns/rempart/internal/state"
)

// Préfixe des jetons : permet aux outils de détection de secrets (gitleaks,
// trufflehog…) de les reconnaître s'ils fuient dans un dépôt.
const tokenPrefix = "rmp_"

var tokenScopes = []string{"read", "tls", "dnssec", "admin", "metrics", "backup", "sync"}

// explicitScopes : portées qu'un jeton « admin » n'inclut pas. Une
// sauvegarde contient le keystore ; la synchronisation, des secrets TSIG.
var explicitScopes = map[string]bool{"backup": true, "sync": true}

func hasBearer(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func tokenHash(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// tokenUsage limite l'écriture de la date de dernière utilisation (l'état
// est scellé : une écriture par requête serait coûteuse).
type tokenUsage struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// tokenAuth valide un jeton porteur et sa portée. Le jeton est comparé par
// son empreinte SHA-256 : 256 bits d'aléa rendent une dérivation lente inutile.
func (a *API) tokenAuth(r *http.Request, scope string) (string, error) {
	if scope == "session" || scope == "local" {
		return "", errors.New("action réservée à l'interface d'administration")
	}
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !strings.HasPrefix(raw, tokenPrefix) {
		return "", errors.New("jeton invalide")
	}
	h := tokenHash(raw)
	for _, t := range a.Store.Get().APITokens {
		if t.Hash != h {
			continue
		}
		if !t.Expires.IsZero() && time.Now().After(t.Expires) {
			return "", errors.New("jeton expiré")
		}
		ok := slices.Contains(t.Scopes, scope) || (slices.Contains(t.Scopes, "admin") && !explicitScopes[scope]) ||
			(scope == "read" && len(t.Scopes) > 0 && !onlyExplicit(t.Scopes)) ||
			(scope == "metrics" && slices.Contains(t.Scopes, "read"))
		if !ok {
			return "", errors.New("portée insuffisante pour cette action (" + scope + ")")
		}
		a.touchToken(t.ID)
		return "jeton:" + t.Name, nil
	}
	return "", errors.New("jeton inconnu ou révoqué")
}

// onlyExplicit : un jeton de sauvegarde ou de synchronisation ne sert qu'à
// cela (pas de lecture de la configuration par ailleurs).
func onlyExplicit(scopes []string) bool {
	for _, s := range scopes {
		if !explicitScopes[s] && s != "metrics" {
			return false
		}
	}
	return true
}

func (a *API) touchToken(id string) {
	a.tokenUse.mu.Lock()
	if a.tokenUse.last == nil {
		a.tokenUse.last = map[string]time.Time{}
	}
	now := time.Now().UTC()
	stale := now.Sub(a.tokenUse.last[id]) > time.Hour
	if stale {
		a.tokenUse.last[id] = now
	}
	a.tokenUse.mu.Unlock()
	if stale {
		_ = a.Store.Update(func(s *state.State) error {
			for i := range s.APITokens {
				if s.APITokens[i].ID == id {
					s.APITokens[i].LastUsed = now
				}
			}
			return nil
		})
	}
}

type tokenView struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Scopes   []string  `json:"scopes"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
	LastUsed time.Time `json:"last_used"`
}

func (a *API) listTokens(w http.ResponseWriter, r *http.Request, _ string) {
	out := []tokenView{}
	for _, t := range a.Store.Get().APITokens {
		out = append(out, tokenView{t.ID, t.Name, t.Scopes, t.Created, t.Expires, t.LastUsed})
	}
	writeJSON(w, out)
}

func (a *API) createToken(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		Name   string
		Scopes []string
		Days   int
	}
	if err := decode(r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		jsonError(w, http.StatusBadRequest, "nom du jeton requis (64 caractères au plus)")
		return
	}
	if len(in.Scopes) == 0 {
		jsonError(w, http.StatusBadRequest, "choisissez au moins une portée")
		return
	}
	for _, s := range in.Scopes {
		if !slices.Contains(tokenScopes, s) {
			jsonError(w, http.StatusBadRequest, "portée inconnue : "+s)
			return
		}
	}
	if in.Days < 0 || in.Days > 730 {
		jsonError(w, http.StatusBadRequest, "durée de validité entre 1 et 730 jours (0 = sans expiration)")
		return
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tok := tokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	now := time.Now().UTC()
	t := state.APIToken{ID: newID(), Name: in.Name, Hash: tokenHash(tok), Scopes: in.Scopes, Created: now}
	if in.Days > 0 {
		t.Expires = now.AddDate(0, 0, in.Days)
	}
	if err := a.Store.Update(func(s *state.State) error { s.APITokens = append(s.APITokens, t); return nil }); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.record(user, "jeton.création", in.Name+" ("+strings.Join(in.Scopes, ", ")+")")
	// Le jeton n'est renvoyé qu'ici, une seule fois ; seul son SHA-256 est conservé.
	writeJSON(w, map[string]any{"token": tok, "info": tokenView{t.ID, t.Name, t.Scopes, t.Created, t.Expires, t.LastUsed}})
}

func (a *API) deleteToken(w http.ResponseWriter, r *http.Request, user string) {
	id := r.PathValue("id")
	name := ""
	if err := a.Store.Update(func(s *state.State) error {
		for i, t := range s.APITokens {
			if t.ID == id {
				name = t.Name
				s.APITokens = slices.Delete(s.APITokens, i, i+1)
				return nil
			}
		}
		return errors.New("jeton introuvable")
	}); err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	a.record(user, "jeton.révocation", name)
	writeJSON(w, map[string]bool{"ok": true})
}
