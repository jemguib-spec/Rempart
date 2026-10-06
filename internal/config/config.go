// Package config loads rempart.yaml. Secrets (passphrase, PIN, admin
// password) are never read from the YAML itself: they come from environment
// variables or from files (Docker/Kubernetes secrets).
package config

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/rempart-dns/rempart/internal/keystore"
	"gopkg.in/yaml.v3"
)

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("durée invalide %q", n.Value)
	}
	d.Duration = v
	return nil
}

type Config struct {
	DataDir  string `yaml:"data_dir"`
	LogLevel string `yaml:"log_level"`

	DNS struct {
		Listen         []string `yaml:"listen"`
		AllowedClients []string `yaml:"allowed_clients"`
		RateLimit      struct {
			QPS   float64 `yaml:"qps"`
			Burst float64 `yaml:"burst"`
		} `yaml:"rate_limit"`
		Cache struct {
			Size   int      `yaml:"size"`
			MinTTL Duration `yaml:"min_ttl"`
			MaxTTL Duration `yaml:"max_ttl"`
		} `yaml:"cache"`
		RebindAllowedDomains []string `yaml:"rebind_allowed_domains"`
	} `yaml:"dns"`

	DoT struct {
		Listen string `yaml:"listen"`
	} `yaml:"dot"`
	DoH struct {
		Listen string `yaml:"listen"`
		Path   string `yaml:"path"`
	} `yaml:"doh"`
	// DoQ : DNS-over-QUIC (RFC 9250), UDP, port 853 par convention.
	DoQ struct {
		Listen string `yaml:"listen"`
	} `yaml:"doq"`
	// DNSCrypt v2 (UDP et TCP). provider_name commence par
	// « 2.dnscrypt-cert. » ; stamp_addr est l'adresse publique annoncée dans
	// le tampon sdns:// (IP:port vu des clients).
	DNSCrypt struct {
		Listen       string `yaml:"listen"`
		ProviderName string `yaml:"provider_name"`
		StampAddr    string `yaml:"stamp_addr"`
		KeyLabel     string `yaml:"key_label"`
	} `yaml:"dnscrypt"`

	TLS struct {
		CertFile        string   `yaml:"cert_file"`
		KeyFile         string   `yaml:"key_file"`
		KeyLabel        string   `yaml:"key_label"`
		SelfSignedNames []string `yaml:"self_signed_names"`
		// ACMEHTTPListen : écoute ouverte le temps d'un défi ACME http-01.
		ACMEHTTPListen string `yaml:"acme_http_listen"`
	} `yaml:"tls"`

	// DNSSEC : ancres de confiance supplémentaires (DS au format présentation)
	// pour des zones internes signées que la racine ne désigne pas. Les ancres
	// de la racine sont intégrées.
	DNSSEC struct {
		TrustAnchors []string `yaml:"trust_anchors"`
	} `yaml:"dnssec"`

	Upstreams    []string `yaml:"upstreams"`
	Bootstrap    []string `yaml:"bootstrap"`
	ListsRefresh Duration `yaml:"lists_refresh"`

	Keystore struct {
		Backend  string `yaml:"backend"`
		Software struct {
			Dir            string `yaml:"dir"`
			PassphraseFile string `yaml:"passphrase_file"`
		} `yaml:"software"`
		PKCS11 struct {
			Module     string `yaml:"module"`
			TokenLabel string `yaml:"token_label"`
			PINFile    string `yaml:"pin_file"`
			KEKLabel   string `yaml:"kek_label"`
			// ModuleDirs : seuls les modules de ces dossiers peuvent être
			// choisis depuis l'interface (charger un module exécute son code).
			ModuleDirs []string `yaml:"module_dirs"`
		} `yaml:"pkcs11"`
	} `yaml:"keystore"`

	Web struct {
		Listen        string   `yaml:"listen"`
		TLS           bool     `yaml:"tls"`
		SessionTTL    Duration `yaml:"session_ttl"`
		AllowedAdmins []string `yaml:"allowed_admins"`
	} `yaml:"web"`

	Defaults struct {
		BlockingMode  string `yaml:"blocking_mode"`
		LogMode       string `yaml:"log_mode"`
		RetentionDays int    `yaml:"retention_days"`
		ClientIDs     string `yaml:"client_ids"`
		Lists         []struct {
			Name   string `yaml:"name"`
			URL    string `yaml:"url"`
			Allow  bool   `yaml:"allow"`
			SHA256 string `yaml:"sha256"`
		} `yaml:"lists"`
		Zones []struct {
			Name      string   `yaml:"name"`
			DNSSEC    bool     `yaml:"dnssec"`
			Algorithm string   `yaml:"algorithm"`
			Records   []string `yaml:"records"`
		} `yaml:"zones"`
	} `yaml:"defaults"`

	// Parsed values.
	AllowedPrefixes []netip.Prefix `yaml:"-"`
	AdminPrefixes   []netip.Prefix `yaml:"-"`
}

// Load reads a YAML file (missing file = defaults) and validates it.
func Load(path string) (*Config, error) {
	c := &Config{}
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if err == nil {
			dec := yaml.NewDecoder(strings.NewReader(string(raw)))
			dec.KnownFields(true) // typos in the config are errors, not silent defaults
			if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
		}
	}
	c.applyDefaults()
	return c, c.validate()
}

func (c *Config) applyDefaults() {
	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if len(c.DNS.Listen) == 0 {
		c.DNS.Listen = []string{"0.0.0.0:53", "[::]:53"}
	}
	if len(c.DNS.AllowedClients) == 0 {
		c.DNS.AllowedClients = []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10"}
	}
	if c.DNS.RateLimit.QPS == 0 {
		c.DNS.RateLimit.QPS = 200
	}
	if c.DNS.RateLimit.Burst == 0 {
		c.DNS.RateLimit.Burst = 2 * c.DNS.RateLimit.QPS
	}
	if c.DNS.Cache.Size == 0 {
		c.DNS.Cache.Size = 200_000
	}
	if c.DNS.Cache.MaxTTL.Duration == 0 {
		c.DNS.Cache.MaxTTL.Duration = 24 * time.Hour
	}
	if c.DNS.RebindAllowedDomains == nil {
		c.DNS.RebindAllowedDomains = []string{"lan", "local", "home.arpa", "internal", "localdomain"}
	}
	if c.DNSCrypt.ProviderName == "" {
		c.DNSCrypt.ProviderName = "2.dnscrypt-cert.rempart"
	}
	if c.DNSCrypt.KeyLabel == "" {
		c.DNSCrypt.KeyLabel = "rempart-dnscrypt"
	}
	if c.DoH.Path == "" {
		c.DoH.Path = "/dns-query"
	}
	if c.TLS.CertFile == "" && c.TLS.KeyFile == "" && c.TLS.KeyLabel == "" {
		c.TLS.KeyLabel = "rempart-tls"
	}
	if len(c.TLS.SelfSignedNames) == 0 {
		c.TLS.SelfSignedNames = []string{"rempart.lan", "localhost"}
	}
	if len(c.Upstreams) == 0 {
		c.Upstreams = []string{"https://dns.quad9.net/dns-query", "tls://one.one.one.one", "https://dns.google/dns-query"}
	}
	if len(c.Bootstrap) == 0 {
		c.Bootstrap = []string{"9.9.9.9", "1.1.1.1"}
	}
	if c.ListsRefresh.Duration == 0 {
		c.ListsRefresh.Duration = 24 * time.Hour
	}
	if c.Keystore.Backend == "" {
		c.Keystore.Backend = "software"
	}
	if c.Keystore.Software.Dir == "" {
		c.Keystore.Software.Dir = c.DataDir + "/keystore"
	}
	if len(c.Keystore.PKCS11.ModuleDirs) == 0 {
		c.Keystore.PKCS11.ModuleDirs = keystore.DefaultModuleDirs
	}
	if c.TLS.ACMEHTTPListen == "" {
		c.TLS.ACMEHTTPListen = ":80"
	}
	if c.Keystore.PKCS11.KEKLabel == "" {
		c.Keystore.PKCS11.KEKLabel = "rempart-kek"
	}
	if c.Web.Listen == "" {
		c.Web.Listen = ":8080"
	}
	if c.Web.SessionTTL.Duration == 0 {
		c.Web.SessionTTL.Duration = 8 * time.Hour
	}
	if c.Defaults.BlockingMode == "" {
		c.Defaults.BlockingMode = "zero"
	}
	if c.Defaults.LogMode == "" {
		c.Defaults.LogMode = "stats"
	}
	if c.Defaults.RetentionDays == 0 {
		c.Defaults.RetentionDays = 7
	}
	if c.Defaults.ClientIDs == "" {
		c.Defaults.ClientIDs = "pseudonymize"
	}
}

func (c *Config) validate() error {
	for _, p := range c.DNS.AllowedClients {
		pp, err := netip.ParsePrefix(p)
		if err != nil {
			return fmt.Errorf("dns.allowed_clients: %w", err)
		}
		c.AllowedPrefixes = append(c.AllowedPrefixes, pp)
	}
	for _, p := range c.Web.AllowedAdmins {
		pp, err := netip.ParsePrefix(p)
		if err != nil {
			return fmt.Errorf("web.allowed_admins: %w", err)
		}
		c.AdminPrefixes = append(c.AdminPrefixes, pp)
	}
	// Le chemin DoH sert aussi de préfixe aux chemins des appareils.
	c.DoH.Path = "/" + strings.Trim(c.DoH.Path, "/")
	if c.DoH.Path == "/" {
		return fmt.Errorf("doh.path ne peut pas être la racine")
	}
	if c.DNS.RateLimit.QPS < 0 || c.DNS.RateLimit.Burst < 0 {
		return fmt.Errorf("dns.rate_limit : valeurs négatives")
	}
	if c.DNS.Cache.Size < 0 {
		return fmt.Errorf("dns.cache.size ne peut pas être négatif")
	}
	if c.DNS.Cache.MinTTL.Duration < 0 || c.DNS.Cache.MaxTTL.Duration < 0 || c.DNS.Cache.MinTTL.Duration > c.DNS.Cache.MaxTTL.Duration {
		return fmt.Errorf("dns.cache : min_ttl doit être positif et inférieur à max_ttl")
	}
	if c.Defaults.RetentionDays < 0 {
		return fmt.Errorf("defaults.retention_days ne peut pas être négatif")
	}
	if c.Web.SessionTTL.Duration < 0 {
		return fmt.Errorf("web.session_ttl ne peut pas être négatif")
	}
	switch c.Keystore.Backend {
	case "software", "pkcs11":
	default:
		return fmt.Errorf("keystore.backend doit valoir software ou pkcs11")
	}
	if c.Keystore.Backend == "pkcs11" && (c.Keystore.PKCS11.Module == "" || c.Keystore.PKCS11.TokenLabel == "") {
		return fmt.Errorf("keystore.pkcs11.module et token_label sont requis")
	}
	return nil
}

// Secret returns the first non-empty value among an environment variable and
// a file. Trailing newlines are removed.
func Secret(env, file string) (string, error) {
	if v := os.Getenv(env); v != "" {
		return v, nil
	}
	if f := os.Getenv(env + "_FILE"); f != "" && file == "" {
		file = f
	}
	if file == "" {
		return "", nil
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}
