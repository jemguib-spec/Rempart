// router.go - routage des requêtes vers les résolveurs : défaut et transfert conditionnel.
// Configuration remplacée atomiquement, AC internes ajoutées aux racines système.
// Rempart ; utilisé par server et api.

package upstream

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

// Router choisit le groupe de résolveurs selon le nom demandé : transfert
// conditionnel pour les domaines internes (Active Directory, intranet),
// résolveurs par défaut pour tout le reste. La configuration est remplacée
// atomiquement, sans redémarrage ni requête perdue.
type Router struct {
	cur atomic.Pointer[routes]
}

type routes struct {
	def *Group
	fwd []route // triées du suffixe le plus long au plus court
}

type route struct {
	suffix string // fqdn en minuscules
	g      *Group
}

// Forward associe un domaine à ses serveurs (specs au format de Parse).
type Forward struct {
	Domain  string
	Servers []string
}

// NewRouter construit un routeur ; il échoue si une spec est invalide.
func NewRouter(def []string, fwd []Forward, o Options) (*Router, error) {
	r := &Router{}
	return r, r.Set(def, fwd, o)
}

// Set valide puis applique une nouvelle configuration. En cas d'erreur, la
// configuration précédente reste active.
func (r *Router) Set(def []string, fwd []Forward, o Options) error {
	g, err := buildGroup(def, o)
	if err != nil {
		return err
	}
	rt := &routes{def: g}
	seen := map[string]bool{}
	for _, f := range fwd {
		name := strings.ToLower(dns.Fqdn(strings.TrimSpace(f.Domain)))
		if _, ok := dns.IsDomainName(name); !ok || name == "." {
			return fmt.Errorf("domaine de transfert invalide %q", f.Domain)
		}
		if seen[name] {
			return fmt.Errorf("domaine de transfert en double : %s", name)
		}
		seen[name] = true
		fg, err := buildGroup(f.Servers, o)
		if err != nil {
			return fmt.Errorf("%s : %w", name, err)
		}
		rt.fwd = append(rt.fwd, route{suffix: name, g: fg})
	}
	sort.Slice(rt.fwd, func(i, j int) bool { return len(rt.fwd[i].suffix) > len(rt.fwd[j].suffix) })
	r.cur.Store(rt)
	return nil
}

func buildGroup(specs []string, o Options) (*Group, error) {
	var us []Upstream
	for _, s := range specs {
		if strings.TrimSpace(s) == "" {
			continue
		}
		u, err := Parse(s, o)
		if err != nil {
			return nil, err
		}
		us = append(us, u)
	}
	return NewGroup(us)
}

func (r *Router) pick(name string) (*Group, bool) {
	rt := r.cur.Load()
	name = strings.ToLower(dns.Fqdn(name))
	for _, f := range rt.fwd {
		if dns.IsSubDomain(f.suffix, name) {
			return f.g, true
		}
	}
	return rt.def, false
}

// Exchange envoie la requête au groupe compétent pour le nom demandé.
func (r *Router) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, string, error) {
	if len(q.Question) != 1 {
		return nil, "", errors.New("une seule question attendue")
	}
	g, _ := r.pick(q.Question[0].Name)
	return g.Exchange(ctx, q)
}

// Forwarded indique si le nom relève d'un transfert conditionnel. Ces noms
// internes répondent légitimement avec des adresses privées : la protection
// anti-rebinding ne s'y applique pas.
func (r *Router) Forwarded(name string) bool {
	_, ok := r.pick(name)
	return ok
}

// Stats renvoie les compteurs de chaque résolveur ; ceux d'un transfert
// conditionnel portent le domaine concerné.
func (r *Router) Stats() []Stat {
	rt := r.cur.Load()
	out := rt.def.Stats()
	for _, f := range rt.fwd {
		for _, s := range f.g.Stats() {
			s.Domain = strings.TrimSuffix(f.suffix, ".")
			out = append(out, s)
		}
	}
	return out
}

// CertPool ajoute des AC PEM aux racines du système. Une chaîne vide renvoie
// nil, c'est-à-dire les racines du système seules.
func CertPool(pemCAs string) (*x509.CertPool, error) {
	if strings.TrimSpace(pemCAs) == "" {
		return nil, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(pemCAs)) {
		return nil, errors.New("aucun certificat d'AC valide dans le PEM fourni")
	}
	return pool, nil
}
