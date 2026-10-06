// Package tsig fournit les clés TSIG (RFC 8945) aux transferts de zone, aux
// NOTIFY, aux mises à jour dynamiques et aux flux RPZ. Seuls HMAC-SHA256,
// HMAC-SHA384 et HMAC-SHA512 sont acceptés : HMAC-MD5 et HMAC-SHA1, encore
// proposés par d'anciens serveurs, sont refusés.
package tsig

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/state"
)

// Algorithms : algorithmes admis et taille de clé générée (celle de la
// sortie du hachage, RFC 4868 §2.1.1).
var Algorithms = map[string]int{dns.HmacSHA256: 32, dns.HmacSHA384: 48, dns.HmacSHA512: 64}

var (
	ErrUnknownKey = errors.New("clé TSIG inconnue")
	ErrAlgorithm  = errors.New("algorithme TSIG refusé (hmac-sha256, hmac-sha384 ou hmac-sha512 attendu)")
)

// CanonicalName normalise un nom de clé (FQDN en minuscules).
func CanonicalName(name string) string { return strings.ToLower(dns.Fqdn(strings.TrimSpace(name))) }

// CanonicalAlgorithm normalise et vérifie un nom d'algorithme.
func CanonicalAlgorithm(alg string) (string, error) {
	a := dns.CanonicalName(strings.TrimSpace(alg))
	if a == "." {
		a = dns.HmacSHA256
	}
	if _, ok := Algorithms[a]; !ok {
		return "", ErrAlgorithm
	}
	return a, nil
}

// NewKey crée une clé : secret aléatoire de la taille de l'algorithme.
func NewKey(name, alg string) (state.TSIGKey, error) {
	n := CanonicalName(name)
	if _, ok := dns.IsDomainName(n); !ok || n == "." {
		return state.TSIGKey{}, fmt.Errorf("nom de clé invalide %q", name)
	}
	a, err := CanonicalAlgorithm(alg)
	if err != nil {
		return state.TSIGKey{}, err
	}
	b := make([]byte, Algorithms[a])
	if _, err := rand.Read(b); err != nil {
		return state.TSIGKey{}, err
	}
	return state.TSIGKey{Name: n, Algorithm: a, Secret: base64.StdEncoding.EncodeToString(b), Created: time.Now().UTC()}, nil
}

// ImportKey vérifie une clé fournie par un autre serveur (BIND, Knot,
// éditeur RPZ) : algorithme admis et secret d'au moins 128 bits.
func ImportKey(name, alg, secret string) (state.TSIGKey, error) {
	k, err := NewKey(name, alg)
	if err != nil {
		return k, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(secret))
	if err != nil || len(raw) < 16 {
		return k, errors.New("secret TSIG : base64 de 16 octets au moins attendu")
	}
	k.Secret = base64.StdEncoding.EncodeToString(raw)
	return k, nil
}

// Provider implémente dns.TsigProvider sur l'ensemble des clés en service,
// remplacé atomiquement à chaque modification de l'état.
type Provider struct {
	keys atomic.Pointer[map[string]state.TSIGKey]
}

func NewProvider() *Provider {
	p := &Provider{}
	p.keys.Store(&map[string]state.TSIGKey{})
	return p
}

// Set installe les clés.
func (p *Provider) Set(keys []state.TSIGKey) {
	m := make(map[string]state.TSIGKey, len(keys))
	for _, k := range keys {
		m[k.Name] = k
	}
	p.keys.Store(&m)
}

// Key renvoie une clé par son nom.
func (p *Provider) Key(name string) (state.TSIGKey, bool) {
	k, ok := (*p.keys.Load())[CanonicalName(name)]
	return k, ok
}

func (p *Provider) mac(msg []byte, t *dns.TSIG) ([]byte, error) {
	k, ok := p.Key(t.Hdr.Name)
	if !ok {
		return nil, ErrUnknownKey
	}
	// L'algorithme est celui de la clé, pas celui annoncé par le message :
	// un message ne peut pas imposer un algorithme plus faible.
	if dns.CanonicalName(t.Algorithm) != k.Algorithm {
		return nil, ErrAlgorithm
	}
	raw, err := base64.StdEncoding.DecodeString(k.Secret)
	if err != nil {
		return nil, err
	}
	var h hash.Hash
	switch k.Algorithm {
	case dns.HmacSHA256:
		h = hmac.New(sha256.New, raw)
	case dns.HmacSHA384:
		h = hmac.New(sha512.New384, raw)
	case dns.HmacSHA512:
		h = hmac.New(sha512.New, raw)
	default:
		return nil, ErrAlgorithm
	}
	h.Write(msg)
	return h.Sum(nil), nil
}

// Generate implémente dns.TsigProvider.
func (p *Provider) Generate(msg []byte, t *dns.TSIG) ([]byte, error) { return p.mac(msg, t) }

// Verify implémente dns.TsigProvider (comparaison en temps constant). La
// fenêtre de temps (fudge) est contrôlée ensuite par la bibliothèque.
func (p *Provider) Verify(msg []byte, t *dns.TSIG) error {
	want, err := p.mac(msg, t)
	if err != nil {
		return err
	}
	got, err := hex.DecodeString(t.MAC)
	if err != nil || len(got) != len(want) || !hmac.Equal(want, got) {
		return dns.ErrSig
	}
	return nil
}

// Replay retient les MAC des requêtes signées acceptées pendant la fenêtre
// de validité TSIG : une mise à jour capturée ne peut pas être rejouée.
//
// Avec Save, chaque MAC retenu est écrit avant que la requête soit traitée
// (journal en écriture anticipée) : un redémarrage n'ouvre pas de fenêtre de
// rejeu. Si l'écriture échoue, la requête est refusée.
type Replay struct {
	mu   sync.Mutex
	seen map[string]time.Time
	// Save reçoit une copie de la mémoire à conserver ; nil : mémoire seule.
	Save func(map[string]time.Time) error
}

// MaxReplayEntries borne la mémoire anti-rejeu : au-delà, les requêtes
// signées sont refusées jusqu'à l'expiration des plus anciennes.
const MaxReplayEntries = 20000

// Load reprend une mémoire enregistrée (au démarrage).
func (r *Replay) Load(m map[string]time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = map[string]time.Time{}
	}
	for k, v := range m {
		r.seen[k] = v
	}
}

// Fresh enregistre mac jusqu'à until (fin de validité de la signature) et
// indique s'il n'a pas déjà été vu.
func (r *Replay) Fresh(mac string, now, until time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = map[string]time.Time{}
	}
	for k, u := range r.seen {
		if now.After(u) {
			delete(r.seen, k)
		}
	}
	mac = strings.ToLower(mac)
	if _, dup := r.seen[mac]; dup {
		return false
	}
	if len(r.seen) >= MaxReplayEntries {
		return false
	}
	r.seen[mac] = until
	if r.Save != nil {
		cp := make(map[string]time.Time, len(r.seen))
		for k, v := range r.seen {
			cp[k] = v
		}
		if err := r.Save(cp); err != nil {
			delete(r.seen, mac)
			return false
		}
	}
	return true
}

// Single : fournisseur limité à une seule clé, pour vérifier la réponse à
// une requête que l'on a signée. Avec le fournisseur général, un pair qui
// détient une autre clé connue de Rempart (éditeur RPZ, client de mises à
// jour) pourrait signer la réponse destinée à un autre primaire.
type Single struct {
	p    *Provider
	name string
}

// NewSingle construit le fournisseur d'une clé.
func NewSingle(k state.TSIGKey) *Single {
	p := NewProvider()
	p.Set([]state.TSIGKey{k})
	return &Single{p: p, name: CanonicalName(k.Name)}
}

func (s *Single) check(t *dns.TSIG) error {
	if CanonicalName(t.Hdr.Name) != s.name {
		return ErrUnknownKey
	}
	return nil
}

// Generate implémente dns.TsigProvider.
func (s *Single) Generate(msg []byte, t *dns.TSIG) ([]byte, error) {
	if err := s.check(t); err != nil {
		return nil, err
	}
	return s.p.Generate(msg, t)
}

// Verify implémente dns.TsigProvider.
func (s *Single) Verify(msg []byte, t *dns.TSIG) error {
	if err := s.check(t); err != nil {
		return err
	}
	return s.p.Verify(msg, t)
}
