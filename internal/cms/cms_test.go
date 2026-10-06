package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func selfSigned(t *testing.T, key any, pub any) []byte {
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(4242), Subject: pkix.Name{CommonName: "rempart.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestSignVerifiedByOpenSSL(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl absent")
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	content := []byte("<?xml version=\"1.0\"?><plist><dict/></plist>\n")
	for name, k := range map[string]crypto.Signer{"ecdsa": ec, "rsa": rk} {
		var cert []byte
		var out []byte
		switch key := k.(type) {
		case *ecdsa.PrivateKey:
			cert = selfSigned(t, key, key.Public())
			out, err = Sign(content, [][]byte{cert}, key, time.Now())
		case *rsa.PrivateKey:
			cert = selfSigned(t, key, key.Public())
			out, err = Sign(content, [][]byte{cert}, key, time.Now())
		}
		if err != nil {
			t.Fatalf("%s : %v", name, err)
		}
		dir := t.TempDir()
		p, ca, got := filepath.Join(dir, "p.der"), filepath.Join(dir, "ca.pem"), filepath.Join(dir, "out")
		_ = os.WriteFile(p, out, 0o600)
		_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0o600)
		cmd := exec.Command(openssl, "cms", "-verify", "-inform", "DER", "-in", p, "-CAfile", ca, "-out", got, "-purpose", "any")
		if msg, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s : openssl refuse la signature : %v\n%s", name, err, msg)
		}
		if b, _ := os.ReadFile(got); !bytes.Equal(b, content) {
			t.Fatalf("%s : contenu différent après vérification", name)
		}
		// Contenu altéré : refusé.
		bad := bytes.Replace(out, []byte("dict"), []byte("DICT"), 1)
		_ = os.WriteFile(p, bad, 0o600)
		if err := exec.Command(openssl, "cms", "-verify", "-inform", "DER", "-in", p, "-CAfile", ca, "-out", got, "-purpose", "any").Run(); err == nil {
			t.Fatalf("%s : contenu altéré accepté", name)
		}
	}
}

func TestSignRejectsWrongCert(t *testing.T) {
	a, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := Sign([]byte("x"), [][]byte{selfSigned(t, a, a.Public())}, b, time.Now()); err == nil {
		t.Fatal("certificat d'une autre clé accepté")
	}
	if _, err := Sign([]byte("x"), nil, a, time.Now()); err == nil {
		t.Fatal("sans certificat")
	}
}
