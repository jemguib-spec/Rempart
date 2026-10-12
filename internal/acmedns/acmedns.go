// acmedns.go - publication du TXT du défi ACME dns-01 chez un hébergeur DNS
// public (OVHcloud, Cloudflare), par son API HTTPS. Aucun port entrant :
// Rempart n'émet que des requêtes sortantes vers l'API et vers les serveurs
// faisant autorité de la zone (vérification de la propagation).
// Rempart ; bibliothèque standard et github.com/miekg/dns (vendorisé).

package acmedns

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Provider publie et retire un TXT dans une zone hébergée chez un fournisseur.
// fqdn est le nom complet, avec ou sans point final.
type Provider interface {
	Present(ctx context.Context, fqdn, value string) error
	CleanUp(ctx context.Context, fqdn, value string) error
}

// Config : fournisseur et identifiants. Les secrets viennent de l'état scellé
// et ne sont jamais renvoyés par l'API ni écrits dans les erreurs.
type Config struct {
	Provider        string // ovh | cloudflare
	Zone            string // zone hébergée chez le fournisseur (example.fr)
	OVHEndpoint     string // ovh-eu | ovh-ca | ovh-us
	OVHAppKey       string
	OVHAppSecret    string
	OVHConsumerKey  string
	CloudflareToken string

	base string // point d'accès de l'API (tests seulement ; vide = officiel)
}

// ProviderInfo décrit un fournisseur pour l'interface.
type ProviderInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Note string `json:"note"`
}

// Providers : fournisseurs pris en charge, en plus de la zone locale de Rempart.
var Providers = []ProviderInfo{
	{ID: "ovh", Name: "OVHcloud", Note: "Clé d'application, secret et clé consommateur créés sur la page createToken de l'API OVH, avec des droits limités à la zone."},
	{ID: "cloudflare", Name: "Cloudflare", Note: "Jeton d'API (pas la clé globale) avec les droits Zone → Zone → Read et Zone → DNS → Edit, limité à la zone."},
}

var ovhEndpoints = map[string]string{
	"ovh-eu": "https://eu.api.ovh.com/1.0",
	"ovh-ca": "https://ca.api.ovh.com/1.0",
	"ovh-us": "https://api.us.ovhcloud.com/1.0",
}

// OVHTokenURL : page de création des clés OVH, droits préremplis et limités
// aux enregistrements de la zone.
func OVHTokenURL(endpoint, zone string) string {
	host := map[string]string{"ovh-eu": "https://eu.api.ovh.com", "ovh-ca": "https://ca.api.ovh.com", "ovh-us": "https://api.us.ovhcloud.com"}[endpoint]
	if host == "" || !validZone(zone) {
		return ""
	}
	z := "/domain/zone/" + canon(zone)
	return host + "/createToken/?GET=" + z + "/record*&POST=" + z + "/record&POST=" + z + "/refresh&DELETE=" + z + "/record/*"
}

var (
	tokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	keyRe   = regexp.MustCompile(`^[A-Za-z0-9]{8,64}$`)
)

func canon(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func validZone(z string) bool {
	z = canon(z)
	_, ok := dns.IsDomainName(z)
	return ok && z != "" && strings.Contains(z, ".") && !strings.ContainsAny(z, "*/ ?#%&")
}

// Validate contrôle la forme des paramètres, sans contacter le fournisseur.
func (c Config) Validate() error {
	if !validZone(c.Zone) {
		return errors.New("zone DNS publique invalide (par exemple example.fr)")
	}
	switch c.Provider {
	case "ovh":
		if _, ok := ovhEndpoints[c.OVHEndpoint]; !ok {
			return errors.New("point d'accès OVH : ovh-eu, ovh-ca ou ovh-us")
		}
		if !keyRe.MatchString(c.OVHAppKey) || !keyRe.MatchString(c.OVHAppSecret) || !keyRe.MatchString(c.OVHConsumerKey) {
			return errors.New("OVH : clé d'application, secret d'application et clé consommateur requis (lettres et chiffres)")
		}
	case "cloudflare":
		if !tokenRe.MatchString(c.CloudflareToken) {
			return errors.New("Cloudflare : jeton d'API requis")
		}
	default:
		return fmt.Errorf("fournisseur DNS %q inconnu", c.Provider)
	}
	return nil
}

// New crée le client du fournisseur.
func New(c Config) (Provider, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	hc := httpClient()
	zone := canon(c.Zone)
	switch c.Provider {
	case "ovh":
		base := c.base
		if base == "" {
			base = ovhEndpoints[c.OVHEndpoint]
		}
		return &ovh{base: base, appKey: c.OVHAppKey, appSecret: c.OVHAppSecret, consumerKey: c.OVHConsumerKey,
			zone: zone, hc: hc, ids: map[string]int64{}}, nil
	default:
		base := c.base
		if base == "" {
			base = "https://api.cloudflare.com/client/v4"
		}
		return &cloudflare{base: base, token: c.CloudflareToken, zone: zone, hc: hc, ids: map[string]string{}}, nil
	}
}

// httpClient : TLS vérifié (racines du système), proxy de l'environnement,
// aucune redirection suivie (les en-têtes d'authentification ne partent pas
// ailleurs).
func httpClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirection refusée") }}
}

const maxBody = 1 << 20

// readBody lit au plus 1 Mio.
func readBody(r *http.Response) ([]byte, error) {
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBody {
		return nil, errors.New("réponse trop volumineuse")
	}
	return b, nil
}

func short(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// relName donne le sous-domaine de fqdn dans zone ("" pour l'apex).
func relName(fqdn, zone string) (string, error) {
	f := canon(fqdn)
	switch {
	case f == zone:
		return "", nil
	case strings.HasSuffix(f, "."+zone):
		return strings.TrimSuffix(f, "."+zone), nil
	}
	return "", fmt.Errorf("%s n'est pas dans la zone %s : corrigez la zone ou déléguez _acme-challenge par un CNAME vers elle", f, zone)
}

func unquote(s string) string { return strings.Trim(strings.TrimSpace(s), `"`) }

func decodeJSON(b []byte, out any) error {
	if out == nil || len(b) == 0 {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("réponse illisible : %w", err)
	}
	return nil
}
