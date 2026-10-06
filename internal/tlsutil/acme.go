// acme.go - client ACME (RFC 8555) pour le certificat TLS, toute AC compatible.
// Clé de compte et clé TLS dans le keystore, EAB non conservé, défis http-01/dns-01.
// Rempart ; golang.org/x/crypto/acme (vendorisé).

package tlsutil

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/secmem"
	"github.com/rempart-dns/rempart/internal/upstream"
	"golang.org/x/crypto/acme"
)

// ACMEAccountLabel : clé de compte ACME, dans le keystore comme les autres.
const ACMEAccountLabel = "rempart-acme-account"

// ACMEDirectory est une autorité proposée dans l'interface.
type ACMEDirectory struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`      // gabarit quand Template est vrai
	EAB      string `json:"eab"`      // required | optional | none
	Template bool   `json:"template"` // l'URL contient des parties à compléter
	Note     string `json:"note"`
}

// Directories : AC publiques et produits de PKI d'entreprise courants. Les
// gabarits suivent la documentation des éditeurs (EJBCA : Keyfactor ;
// Horizon : EverTrust) ; toute autre AC ACME (RFC 8555) s'utilise avec son URL.
var Directories = []ACMEDirectory{
	{ID: "letsencrypt", Name: "Let's Encrypt", URL: "https://acme-v02.api.letsencrypt.org/directory", EAB: "none",
		Note: "AC publique gratuite ; le nom doit être résolvable publiquement (http-01) ou délégué (dns-01)."},
	{ID: "letsencrypt-staging", Name: "Let's Encrypt (test)", URL: "https://acme-staging-v02.api.letsencrypt.org/directory", EAB: "none",
		Note: "Environnement de test : certificats non reconnus, limites de débit élevées."},
	{ID: "ejbca", Name: "EJBCA (Keyfactor)", URL: "https://<serveur>/ejbca/acme/<alias>/directory", EAB: "optional", Template: true,
		Note: "L'alias ACME est défini dans EJBCA (System Configuration → ACME). EJBCA exige DNSSEC pour dns-01."},
	{ID: "horizon", Name: "EverTrust Horizon", URL: "https://<serveur>/acme/<profil>/directory", EAB: "optional", Template: true,
		Note: "Le profil ACME est défini dans Horizon (Protocols → ACME)."},
	{ID: "custom", Name: "Autre AC ACME (RFC 8555)", URL: "", EAB: "optional", Template: true,
		Note: "Smallstep, Vault PKI, AC publique avec EAB (ZeroSSL, Google Trust Services, Sectigo…)."},
}

// ACMEOptions : paramètres d'une autorité ACME.
type ACMEOptions struct {
	DirectoryURL string
	Email        string
	AccountURL   string
	Challenge    string   // http-01 | dns-01
	CABundle     string   // AC (PEM) de confiance pour joindre une AC interne
	Names        []string // noms du certificat
	HTTPListen   string   // écoute temporaire pour http-01 (":80")
	// DNS01 publie (add) ou retire le TXT _acme-challenge dans une zone
	// locale signée de Rempart.
	DNS01 func(fqdn, value string, add bool) error
}

func (m *Manager) client(o ACMEOptions) (*acme.Client, error) {
	u, err := url.Parse(o.DirectoryURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || strings.ContainsAny(o.DirectoryURL, "<>") {
		return nil, errors.New("URL d'annuaire ACME invalide (https://…/directory attendu)")
	}
	roots, err := upstream.CertPool(o.CABundle)
	if err != nil {
		return nil, err
	}
	key, err := m.ks.Signer(ACMEAccountLabel, keystore.ECDSAP256, true)
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	c := &acme.Client{Key: key, DirectoryURL: o.DirectoryURL, UserAgent: "rempart-dns",
		HTTPClient: &http.Client{Transport: tr, Timeout: 30 * time.Second}}
	if o.AccountURL != "" {
		c.KID = acme.KeyID(o.AccountURL)
	}
	return c, nil
}

// Register crée (ou retrouve) le compte ACME. eabHMAC est la clé MAC
// d'External Account Binding (RFC 8555 §7.3.4), encodée en base64url comme
// la fournissent les AC ; elle n'est ni conservée ni journalisée.
func (m *Manager) Register(ctx context.Context, o ACMEOptions, eabKID string, eabHMAC []byte) (string, error) {
	c, err := m.client(o)
	if err != nil {
		return "", err
	}
	c.KID = ""
	acct := &acme.Account{}
	if o.Email != "" {
		acct.Contact = []string{"mailto:" + o.Email}
	}
	if eabKID != "" {
		key, err := decodeEAB(eabHMAC)
		if err != nil {
			return "", err
		}
		defer secmem.Wipe(key)
		acct.ExternalAccountBinding = &acme.ExternalAccountBinding{KID: eabKID, Key: key}
	}
	a, err := c.Register(ctx, acct, acme.AcceptTOS)
	if errors.Is(err, acme.ErrAccountAlreadyExists) {
		a, err = c.GetReg(ctx, "")
	}
	if err != nil {
		return "", fmt.Errorf("inscription ACME refusée : %w", err)
	}
	return a.URI, nil
}

func decodeEAB(raw []byte) ([]byte, error) {
	s := strings.TrimRight(strings.TrimSpace(string(raw)), "=")
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		if k, err := enc.DecodeString(s); err == nil && len(k) >= 16 {
			return k, nil
		}
	}
	return nil, errors.New("clé HMAC d'EAB invalide (base64url d'au moins 128 bits attendu)")
}

// Obtain commande un certificat pour la clé TLS du keystore et le met en
// service. La clé privée ne quitte pas le keystore : seule la CSR est envoyée.
func (m *Manager) Obtain(ctx context.Context, o ACMEOptions) (Info, error) {
	if m.fileMode {
		return Info{}, errors.New("certificat imposé par le fichier de configuration (tls.cert_file)")
	}
	if !m.issue.TryLock() {
		return Info{}, errors.New("une demande de certificat est déjà en cours")
	}
	defer m.issue.Unlock()
	if o.AccountURL == "" {
		return Info{}, errors.New("compte ACME non inscrit")
	}
	if len(o.Names) == 0 {
		return Info{}, errors.New("aucun nom à certifier")
	}
	for _, n := range o.Names {
		if net.ParseIP(n) != nil {
			return Info{}, fmt.Errorf("%s : ACME ne certifie ici que des noms DNS", n)
		}
	}
	c, err := m.client(o)
	if err != nil {
		return Info{}, err
	}
	order, err := c.AuthorizeOrder(ctx, acme.DomainIDs(o.Names...))
	if err != nil {
		return Info{}, fmt.Errorf("commande ACME : %w", err)
	}
	if o.Challenge == "http-01" {
		stop, err := m.serveHTTP01(o.HTTPListen)
		if err != nil {
			return Info{}, err
		}
		defer stop()
	}
	for _, zurl := range order.AuthzURLs {
		z, err := c.GetAuthorization(ctx, zurl)
		if err != nil {
			return Info{}, err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, ch := range z.Challenges {
			if ch.Type == o.Challenge {
				chal = ch
			}
		}
		if chal == nil {
			return Info{}, fmt.Errorf("%s : l'AC ne propose pas le défi %s", z.Identifier.Value, o.Challenge)
		}
		switch o.Challenge {
		case "http-01":
			resp, err := c.HTTP01ChallengeResponse(chal.Token)
			if err != nil {
				return Info{}, err
			}
			m.http01.Store(chal.Token, resp)
			defer m.http01.Delete(chal.Token)
		case "dns-01":
			if o.DNS01 == nil {
				return Info{}, errors.New("défi dns-01 indisponible")
			}
			rec, err := c.DNS01ChallengeRecord(chal.Token)
			if err != nil {
				return Info{}, err
			}
			name := "_acme-challenge." + strings.TrimSuffix(z.Identifier.Value, ".") + "."
			if err := o.DNS01(name, rec, true); err != nil {
				return Info{}, err
			}
			defer func() { _ = o.DNS01(name, rec, false) }()
		default:
			return Info{}, fmt.Errorf("défi %q non pris en charge", o.Challenge)
		}
		if _, err := c.Accept(ctx, chal); err != nil {
			return Info{}, fmt.Errorf("%s : %w", z.Identifier.Value, err)
		}
		if _, err := c.WaitAuthorization(ctx, z.URI); err != nil {
			return Info{}, fmt.Errorf("%s : validation refusée par l'AC : %w", z.Identifier.Value, err)
		}
	}
	ready, err := c.WaitOrder(ctx, order.URI)
	if err != nil {
		return Info{}, fmt.Errorf("commande ACME : %w", err)
	}
	csr, err := m.CSR(o.Names)
	if err != nil {
		return Info{}, err
	}
	der, _, err := c.CreateOrderCert(ctx, ready.FinalizeURL, csr, true)
	if err != nil {
		// Certaines AC (Pebble, d'autres en état « processing ») ne renvoient
		// pas d'en-tête Location à la finalisation : x/crypto/acme perd alors
		// l'URL de la commande. On la suit nous-mêmes.
		o, werr := c.WaitOrder(ctx, order.URI)
		if werr != nil || o.Status != acme.StatusValid || o.CertURL == "" {
			return Info{}, fmt.Errorf("émission refusée : %w", err)
		}
		if der, err = c.FetchCert(ctx, o.CertURL, true); err != nil {
			return Info{}, fmt.Errorf("récupération du certificat : %w", err)
		}
	}
	signer, err := m.Signer()
	if err != nil {
		return Info{}, err
	}
	if err := m.install(der, signer, "acme"); err != nil {
		return Info{}, err
	}
	if err := writeChain(m.certPath(), der); err != nil {
		return Info{}, err
	}
	return m.Info(), nil
}

// serveHTTP01 ouvre l'écoute HTTP le temps de la validation : seules les
// URL /.well-known/acme-challenge/<jeton> en attente sont servies.
func (m *Manager) serveHTTP01(addr string) (func(), error) {
	if addr == "" {
		addr = ":80"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("écoute http-01 sur %s impossible : %w", addr, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/acme-challenge/{token}", func(w http.ResponseWriter, r *http.Request) {
		v, ok := m.http01.Load(r.PathValue("token"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(v.(string)))
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10}
	go func() { _ = srv.Serve(ln) }()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}, nil
}
