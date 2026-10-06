package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rempart.yaml")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaults(t *testing.T) {
	for _, p := range []string{"", filepath.Join(t.TempDir(), "absent.yaml"), write(t, ""), write(t, "# rien\n")} {
		c, err := Load(p)
		if err != nil {
			t.Fatalf("%q : %v", p, err)
		}
		if c.DataDir != "./data" || c.Keystore.Backend != "software" || c.DoH.Path != "/dns-query" ||
			c.TLS.KeyLabel != "rempart-tls" || c.Web.SessionTTL.Duration != 8*time.Hour || c.Defaults.LogMode != "stats" {
			t.Fatalf("défauts : %+v", c)
		}
		if len(c.AllowedPrefixes) == 0 {
			t.Fatal("réseaux autorisés non analysés")
		}
		for _, pp := range c.AllowedPrefixes {
			if pp.Bits() == 0 {
				t.Fatalf("défaut ouvert à tout Internet : %v", pp)
			}
		}
	}
}

func TestExampleFilesLoad(t *testing.T) {
	for _, p := range []string{"../../rempart.example.yaml", "../../deploy/rempart.docker.yaml", "../../deploy/rempart.hsm.yaml"} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if _, err := Load(p); err != nil {
			t.Errorf("%s : %v", p, err)
		}
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	_, err := Load(write(t, "dns:\n  lisen: [\"0.0.0.0:53\"]\n"))
	if err == nil || !strings.Contains(err.Error(), "lisen") {
		t.Fatalf("faute de frappe acceptée : %v", err)
	}
}

func TestValues(t *testing.T) {
	c, err := Load(write(t, `
data_dir: /var/lib/rempart
dns:
  allowed_clients: ["192.168.1.0/24"]
  cache: { min_ttl: 30s, max_ttl: 1h }
doh: { path: "/requete/" }
web: { allowed_admins: ["10.0.0.0/8"], session_ttl: 15m }
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.DoH.Path != "/requete" || c.DNS.Cache.MinTTL.Duration != 30*time.Second || c.Web.SessionTTL.Duration != 15*time.Minute {
		t.Fatalf("%+v", c)
	}
	if c.Keystore.Software.Dir != "/var/lib/rempart/keystore" {
		t.Fatalf("keystore : %s", c.Keystore.Software.Dir)
	}
	if len(c.AllowedPrefixes) != 1 || len(c.AdminPrefixes) != 1 {
		t.Fatal("préfixes")
	}
}

func TestInvalid(t *testing.T) {
	for name, y := range map[string]string{
		"cidr":          "dns: { allowed_clients: [\"pas-un-réseau\"] }",
		"admins":        "web: { allowed_admins: [\"1.2.3.4\"] }",
		"durée":         "web: { session_ttl: \"demain\" }",
		"racine doh":    "doh: { path: \"/\" }",
		"backend":       "keystore: { backend: tpm }",
		"pkcs11 seul":   "keystore: { backend: pkcs11 }",
		"qps négatif":   "dns: { rate_limit: { qps: -1 } }",
		"cache négatif": "dns: { cache: { size: -5 } }",
		"rétention":     "defaults: { retention_days: -1 }",
		"ttl inversés":  "dns: { cache: { min_ttl: 2h, max_ttl: 1h } }",
	} {
		if _, err := Load(write(t, y)); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	if _, err := Load(write(t, "keystore: { backend: pkcs11, pkcs11: { module: /usr/lib/x.so, token_label: rempart } }")); err != nil {
		t.Fatal(err)
	}
}

func TestSecret(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "s.txt")
	_ = os.WriteFile(f, []byte("phrase\r\n"), 0o600)
	t.Setenv("REMPART_TEST_SECRET", "")
	t.Setenv("REMPART_TEST_SECRET_FILE", "")
	if v, err := Secret("REMPART_TEST_SECRET", ""); err != nil || v != "" {
		t.Fatalf("%q %v", v, err)
	}
	if v, _ := Secret("REMPART_TEST_SECRET", f); v != "phrase" {
		t.Fatalf("fichier : %q", v)
	}
	t.Setenv("REMPART_TEST_SECRET_FILE", f)
	if v, _ := Secret("REMPART_TEST_SECRET", ""); v != "phrase" {
		t.Fatalf("_FILE : %q", v)
	}
	t.Setenv("REMPART_TEST_SECRET", "env")
	if v, _ := Secret("REMPART_TEST_SECRET", f); v != "env" {
		t.Fatalf("priorité : %q", v)
	}
	t.Setenv("REMPART_TEST_SECRET", "")
	if _, err := Secret("REMPART_TEST_SECRET", filepath.Join(dir, "absent")); err == nil {
		t.Fatal("fichier absent sans erreur")
	}
}
