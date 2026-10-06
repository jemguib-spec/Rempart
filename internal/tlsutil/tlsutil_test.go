package tlsutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/testutil"
)

func newManager(t *testing.T) (*Manager, keystore.Keystore, string) {
	t.Helper()
	ks := testutil.Keystore(t)
	dir := t.TempDir()
	m, err := New(ks, Options{KeyLabel: "rempart-tls", SelfSignedNames: []string{"rempart.lan", "192.0.2.53"}, DataDir: dir}, "", nil, testutil.Logger())
	if err != nil {
		t.Fatal(err)
	}
	return m, ks, dir
}

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, name string, parent *ca) *ca {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	signCert, signKey := tmpl, crypto.Signer(k)
	if parent != nil {
		signCert, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signCert, k.Public(), signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &ca{c, k}
}

func (c *ca) issue(t *testing.T, pub crypto.PublicKey, mod func(*x509.Certificate)) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "rempart.lan"},
		DNSNames: []string{"rempart.lan"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if mod != nil {
		mod(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pemOf(ders ...[]byte) []byte {
	var out []byte
	for _, d := range ders {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	return out
}

func TestSelfSignedAtStart(t *testing.T) {
	m, _, dir := newManager(t)
	i := m.Info()
	if i.Mode != "selfsigned" || !i.SelfSigned || i.ChainLength != 1 {
		t.Fatalf("%+v", i)
	}
	leaf := m.Leaf()
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "rempart.lan" || len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("192.0.2.53")) {
		t.Fatalf("noms %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
	// La clé privée ne doit jamais être écrite sur disque.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if strings.Contains(string(b), "PRIVATE KEY") {
			t.Fatalf("clé privée dans %s", e.Name())
		}
	}
	// Le même certificat est repris au redémarrage.
	m2, err := New(m.ks, m.opts, "", nil, testutil.Logger())
	if err != nil {
		t.Fatal(err)
	}
	if m2.Info().CertSHA256 != i.CertSHA256 {
		t.Fatal("certificat auto-signé régénéré sans raison")
	}
	if err := m2.SelfSigned(true); err != nil || m2.Info().CertSHA256 == i.CertSHA256 {
		t.Fatal("régénération forcée sans effet")
	}
}

func TestSelfSignedRenewedWhenNamesChange(t *testing.T) {
	m, ks, dir := newManager(t)
	m2, err := New(ks, Options{KeyLabel: "rempart-tls", SelfSignedNames: []string{"autre.lan"}, DataDir: dir}, "", nil, testutil.Logger())
	if err != nil {
		t.Fatal(err)
	}
	if m2.Info().CertSHA256 == m.Info().CertSHA256 || m2.Leaf().DNSNames[0] != "autre.lan" {
		t.Fatal("noms changés mais certificat conservé")
	}
}

func TestHandshake(t *testing.T) {
	m, _, _ := newManager(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", m.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	pool := x509.NewCertPool()
	pool.AddCert(m.Leaf())
	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "rempart.lan"})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestInstallChain(t *testing.T) {
	m, _, dir := newManager(t)
	root := newCA(t, "racine", nil)
	inter := newCA(t, "intermédiaire", root)
	signer, _ := m.Signer()
	leaf := inter.issue(t, signer.Public(), nil)

	if _, err := m.Install(pemOf(inter.cert.Raw, leaf), "manual"); err == nil {
		t.Fatal("chaîne dans le désordre acceptée")
	}
	info, err := m.Install(pemOf(leaf, inter.cert.Raw), "manual")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode != "manual" || info.SelfSigned || info.ChainLength != 2 {
		t.Fatalf("%+v", info)
	}
	// Repris au redémarrage.
	m2, err := New(m.ks, Options{KeyLabel: "rempart-tls", SelfSignedNames: []string{"rempart.lan"}, DataDir: dir}, "manual", nil, testutil.Logger())
	if err != nil || m2.Info().CertSHA256 != info.CertSHA256 {
		t.Fatalf("certificat importé perdu au redémarrage : %v", err)
	}
}

func TestInstallRejects(t *testing.T) {
	m, _, _ := newManager(t)
	root := newCA(t, "racine", nil)
	signer, _ := m.Signer()
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(other)
	cases := map[string][]byte{
		"autre clé": pemOf(root.issue(t, other.Public(), nil)),
		"expiré": pemOf(root.issue(t, signer.Public(), func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)
		})),
		"futur": pemOf(root.issue(t, signer.Public(), func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(24 * time.Hour)
			c.NotAfter = time.Now().Add(48 * time.Hour)
		})),
		"clientAuth":  pemOf(root.issue(t, signer.Public(), func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} })),
		"keyEncipher": pemOf(root.issue(t, signer.Public(), func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment })),
		"clé privée":  append(pemOf(root.issue(t, signer.Public(), nil)), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...),
		"vide":        []byte("rien"),
		"illisible":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("xx")}),
		"mauvaise AC": pemOf(root.issue(t, signer.Public(), nil), newCA(t, "autre", nil).cert.Raw),
	}
	before := m.Info().CertSHA256
	for name, p := range cases {
		if _, err := m.Install(p, "manual"); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	if m.Info().CertSHA256 != before {
		t.Fatal("certificat en service changé par un import refusé")
	}
}

func TestCSR(t *testing.T) {
	m, _, _ := newManager(t)
	if _, err := m.CSR(nil); err == nil {
		t.Fatal("CSR sans nom")
	}
	der, err := m.CSR([]string{"dns.example", "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatal("CSR invalide")
	}
	signer, _ := m.Signer()
	if keystore.Fingerprint(csr.PublicKey) != keystore.Fingerprint(signer.Public()) {
		t.Fatal("CSR pour une autre clé")
	}
	if csr.Subject.CommonName != "dns.example" || len(csr.DNSNames) != 1 || len(csr.IPAddresses) != 1 {
		t.Fatalf("%v %v %v", csr.Subject, csr.DNSNames, csr.IPAddresses)
	}
}

func TestNeedsRenewal(t *testing.T) {
	m, _, _ := newManager(t)
	i := m.Info()
	life := i.NotAfter.Sub(i.NotBefore)
	if m.NeedsRenewal(i.NotBefore.Add(life / 2)) {
		t.Fatal("renouvellement à mi-vie")
	}
	if !m.NeedsRenewal(i.NotAfter.Add(-life / 4)) {
		t.Fatal("pas de renouvellement au dernier tiers")
	}
}

func TestFileModeLocked(t *testing.T) {
	dir := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := newCA(t, "racine", nil)
	cert := root.issue(t, k.Public(), nil)
	kd, _ := x509.MarshalECPrivateKey(k)
	cf, kf := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	_ = os.WriteFile(cf, pemOf(cert), 0o600)
	_ = os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	m, err := New(testutil.Keystore(t), Options{CertFile: cf, KeyFile: kf, SelfSignedNames: []string{"x"}, DataDir: dir}, "", nil, testutil.Logger())
	if err != nil {
		t.Fatal(err)
	}
	if !m.Locked() || m.Info().Mode != "file" {
		t.Fatal("mode fichier non verrouillé")
	}
	if _, err := m.Install(pemOf(cert), "manual"); err == nil {
		t.Fatal("import accepté en mode fichier")
	}
	if err := m.SelfSigned(true); err == nil {
		t.Fatal("auto-signé accepté en mode fichier")
	}
}

func TestDecodeEAB(t *testing.T) {
	for _, in := range []string{"c2VjcmV0LWhtYWMta2V5LTMyLW9jdGV0cy4uLi4u", "c2VjcmV0LWhtYWMta2V5LTMyLW9jdGV0cy4uLi4u\n"} {
		if b, err := decodeEAB([]byte(in)); err != nil || len(b) == 0 {
			t.Fatalf("%q : %v", in, err)
		}
	}
	if _, err := decodeEAB([]byte("!!!")); err == nil {
		t.Fatal("clé EAB invalide acceptée")
	}
}
