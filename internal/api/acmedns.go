// acmedns.go - défi ACME dns-01 : zone locale de Rempart ou hébergeur DNS
// public (OVHcloud, Cloudflare) par son API. Identifiants scellés avec
// l'état, jamais renvoyés ; demande de certificat en arrière-plan.

package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rempart-dns/rempart/internal/acmedns"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/tlsutil"
)

// acmeJob : une seule demande de certificat à la fois, étape affichée.
type acmeJob struct {
	mu      sync.Mutex
	running bool
	step    string
}

func (j *acmeJob) start() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.running {
		return false
	}
	j.running, j.step = true, "démarrage"
	return true
}

func (j *acmeJob) done() {
	j.mu.Lock()
	j.running, j.step = false, ""
	j.mu.Unlock()
}

func (j *acmeJob) setStep(s string) {
	j.mu.Lock()
	if j.running {
		j.step = s
	}
	j.mu.Unlock()
}

func (j *acmeJob) status() (bool, string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.running, j.step
}

// localDNS01 : TXT publié dans une zone locale signée de Rempart (PKI
// interne dont l'AC interroge Rempart). La publication est immédiate.
type localDNS01 struct{ a *API }

func (l localDNS01) Present(_ context.Context, fqdn, value string) error {
	return l.a.Zones.SetChallenge(l.a.Store.Get().Zones, fqdn, value, true)
}

func (l localDNS01) CleanUp(_ context.Context, fqdn, value string) error {
	return l.a.Zones.SetChallenge(l.a.Store.Get().Zones, fqdn, value, false)
}

func (localDNS01) Wait(context.Context, map[string][]string) error { return nil }

// unavailable : configuration incomplète, l'erreur sort à la publication.
type unavailable struct{ err error }

func (u unavailable) Present(context.Context, string, string) error   { return u.err }
func (u unavailable) CleanUp(context.Context, string, string) error   { return nil }
func (u unavailable) Wait(context.Context, map[string][]string) error { return u.err }

func providerConfig(d state.ACMEDNS) acmedns.Config {
	return acmedns.Config{Provider: d.Provider, Zone: d.Zone, OVHEndpoint: d.OVHEndpoint, OVHAppKey: d.OVHAppKey,
		OVHAppSecret: d.OVHAppSecret, OVHConsumerKey: d.OVHConsumerKey, CloudflareToken: d.CloudflareToken}
}

// dns01Solver construit le solveur selon la configuration enregistrée.
func (a *API) dns01Solver() tlsutil.DNS01Solver {
	st := a.Store.Get()
	d := st.TLS.ACME.DNS
	if d.Provider == "" || d.Provider == "local" {
		return localDNS01{a}
	}
	p, err := acmedns.New(providerConfig(d))
	if err != nil {
		return unavailable{err}
	}
	res := st.Resolvers.Bootstrap
	if len(res) == 0 {
		res = a.Bootstrap
	}
	return &acmedns.Solver{P: p, Resolvers: res, Progress: a.acme.setStep}
}

// mergeACMEDNS valide la configuration reçue et garde les secrets
// enregistrés tant que le fournisseur, la zone et le compte ne changent pas :
// ils ne peuvent pas être envoyés vers un autre compte sans être ressaisis.
func mergeACMEDNS(old state.ACMEDNS, in *state.ACMEDNS, used bool) error {
	in.Provider = strings.TrimSpace(in.Provider)
	in.Zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(in.Zone)), ".")
	in.OVHEndpoint, in.OVHAppKey = strings.TrimSpace(in.OVHEndpoint), strings.TrimSpace(in.OVHAppKey)
	in.OVHAppSecret, in.OVHConsumerKey = strings.TrimSpace(in.OVHAppSecret), strings.TrimSpace(in.OVHConsumerKey)
	in.CloudflareToken = strings.TrimSpace(in.CloudflareToken)
	if in.Provider == "" {
		in.Provider = "local"
	}
	switch in.Provider {
	case "local":
		*in = state.ACMEDNS{Provider: "local"}
		return nil
	case "ovh":
		in.CloudflareToken = ""
		same := old.Provider == "ovh" && old.Zone == in.Zone && old.OVHEndpoint == in.OVHEndpoint && old.OVHAppKey == in.OVHAppKey
		for _, p := range []struct{ in, old *string }{{&in.OVHAppSecret, &old.OVHAppSecret}, {&in.OVHConsumerKey, &old.OVHConsumerKey}} {
			if *p.in == "" && *p.old != "" {
				if !same {
					return errors.New("la zone, le point d'accès ou la clé d'application OVH a changé : ressaisissez le secret et la clé consommateur")
				}
				*p.in = *p.old
			}
		}
	case "cloudflare":
		in.OVHEndpoint, in.OVHAppKey, in.OVHAppSecret, in.OVHConsumerKey = "", "", "", ""
		if in.CloudflareToken == "" && old.CloudflareToken != "" {
			if old.Provider != "cloudflare" || old.Zone != in.Zone {
				return errors.New("la zone Cloudflare a changé : ressaisissez le jeton d'API")
			}
			in.CloudflareToken = old.CloudflareToken
		}
	default:
		return errors.New("fournisseur DNS : local, ovh ou cloudflare")
	}
	if !used {
		// dns-01 n'est pas choisi : on garde la saisie si elle est complète,
		// sans l'imposer.
		if providerConfig(*in).Validate() != nil {
			*in = old
		}
		return nil
	}
	return providerConfig(*in).Validate()
}

// acmeDNSTest publie puis retire un TXT de test chez le fournisseur avec la
// configuration enregistrée : vérifie les clés et leurs droits sans
// solliciter l'AC (ni ses limites de débit).
func (a *API) acmeDNSTest(w http.ResponseWriter, r *http.Request, user string) {
	st := a.Store.Get().TLS
	d := st.ACME.DNS
	if d.Provider == "" || d.Provider == "local" {
		jsonError(w, http.StatusBadRequest, "aucun hébergeur DNS public configuré")
		return
	}
	p, err := acmedns.New(providerConfig(d))
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := "_acme-challenge." + d.Zone + "."
	for _, n := range st.Names {
		if n = strings.TrimPrefix(n, "*."); n == d.Zone || strings.HasSuffix(n, "."+d.Zone) {
			name = "_acme-challenge." + n + "."
			break
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	res := a.Store.Get().Resolvers.Bootstrap
	if len(res) == 0 {
		res = a.Bootstrap
	}
	s := &acmedns.Solver{P: p, Resolvers: res}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	val := "rempart-test-" + base64.RawURLEncoding.EncodeToString(b)
	if err := s.Present(ctx, name, val); err != nil {
		a.record(user, "acme.dns.test.échec", err.Error())
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := s.CleanUp(ctx, name, val); err != nil {
		a.record(user, "acme.dns.test.échec", "retrait : "+err.Error())
		jsonError(w, http.StatusBadGateway, "publication réussie, mais retrait refusé : "+err.Error())
		return
	}
	a.record(user, "acme.dns.test", d.Provider+" "+strings.TrimSuffix(name, "."))
	writeJSON(w, map[string]string{"name": strings.TrimSuffix(name, ".")})
}

// RenewCertificate : renouvellement automatique, sauf si une demande lancée
// depuis l'interface est déjà en cours.
func (a *API) RenewCertificate(ctx context.Context) error {
	if !a.acme.start() {
		return nil
	}
	defer a.acme.done()
	return a.IssueCertificate(ctx, "système")
}
