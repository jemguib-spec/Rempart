package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// HashPassword returns an Argon2id PHC string.
func HashPassword(pw string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	const t, m, p = 3, 64 * 1024, 2
	h := argon2.IDKey([]byte(pw), salt, t, m, p, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", m, t, p,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(h))
}

// CheckPassword verifies a password in constant time.
func CheckPassword(pw, phc string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// RandomPassword generates a readable random password.
func RandomPassword() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ValidatePassword enforces a minimal policy.
func ValidatePassword(pw string) error {
	if len(pw) < 12 {
		return errors.New("le mot de passe doit contenir au moins 12 caractères")
	}
	return nil
}

// Principal décrit qui est connecté : compte local, utilisateur LDAP ou OIDC.
type Principal struct {
	User    string // identifiant d'audit : « admin », « ldap:alice », « oidc:alice »
	Name    string // nom affiché
	Role    string // admin | operator | read
	Source  string // local | ldap | oidc
	idToken string // OIDC : pour la déconnexion chez le fournisseur (mémoire seulement)
}

type session struct {
	p       Principal
	expires time.Time
}

type sessions struct {
	mu  sync.Mutex
	m   map[string]session // sha256(token) -> session
	ttl time.Duration
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func (s *sessions) create(p Principal) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.m {
		if now.After(v.expires) {
			delete(s.m, k)
		}
	}
	s.m[hashToken(tok)] = session{p: p, expires: now.Add(s.ttl)}
	return tok
}

func (s *sessions) get(tok string) (Principal, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[hashToken(tok)]
	if !ok || time.Now().After(v.expires) {
		return Principal{}, false
	}
	return v.p, true
}

func (s *sessions) delete(tok string) {
	s.mu.Lock()
	delete(s.m, hashToken(tok))
	s.mu.Unlock()
}

// clearExternal ferme les sessions ouvertes par un annuaire ou un
// fournisseur d'identité (configuration ou correspondance des rôles changée).
func (s *sessions) clearExternal() {
	s.mu.Lock()
	for k, v := range s.m {
		if v.p.Source != "local" {
			delete(s.m, k)
		}
	}
	s.mu.Unlock()
}

func (s *sessions) clear() {
	s.mu.Lock()
	s.m = map[string]session{}
	s.mu.Unlock()
}

// loginGuard slows down brute force: 5 failures per IP then a growing lockout.
type loginGuard struct {
	mu   sync.Mutex
	fail map[netip.Addr]*attempts
}

type attempts struct {
	n     int
	until time.Time
}

func (g *loginGuard) blocked(ip netip.Addr) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	if a, ok := g.fail[ip]; ok && time.Now().Before(a.until) {
		return time.Until(a.until)
	}
	return 0
}

func (g *loginGuard) failed(ip netip.Addr) {
	g.mu.Lock()
	defer g.mu.Unlock()
	a, ok := g.fail[ip]
	if !ok {
		a = &attempts{}
		g.fail[ip] = a
	}
	a.n++
	if a.n >= 5 {
		a.until = time.Now().Add(time.Duration(1<<min(a.n-5, 10)) * time.Minute)
	}
}

func (g *loginGuard) success(ip netip.Addr) {
	g.mu.Lock()
	delete(g.fail, ip)
	g.mu.Unlock()
}
