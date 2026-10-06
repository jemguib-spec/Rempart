//go:build cgo

package keystore_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/zones"
)

// softHSM initialises a throw-away SoftHSM2 token, or skips the test.
func softHSM(t *testing.T) keystore.PKCS11Config {
	t.Helper()
	module := os.Getenv("REMPART_TEST_PKCS11_MODULE")
	if module == "" {
		for _, p := range []string{"/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so"} {
			if _, err := os.Stat(p); err == nil {
				module = p
				break
			}
		}
	}
	if _, err := exec.LookPath("softhsm2-util"); err != nil || module == "" {
		t.Skip("SoftHSM2 non installé")
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "softhsm2.conf")
	os.MkdirAll(filepath.Join(dir, "tokens"), 0o700)
	os.WriteFile(conf, []byte("directories.tokendir = "+filepath.Join(dir, "tokens")+"\nobjectstore.backend = file\nlog.level = ERROR\n"), 0o600)
	t.Setenv("SOFTHSM2_CONF", conf)
	out, err := exec.Command("softhsm2-util", "--init-token", "--free", "--label", "rempart-test", "--pin", "1234", "--so-pin", "5678").CombinedOutput()
	if err != nil {
		t.Fatalf("init token: %v %s", err, out)
	}
	return keystore.PKCS11Config{Module: module, TokenLabel: "rempart-test", PIN: "1234"}
}

func TestPKCS11(t *testing.T) {
	cfg := softHSM(t)
	ks, err := keystore.OpenPKCS11(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()

	// Wrap / unwrap with the AES KEK generated inside the HSM.
	secret := []byte("une clé de données de 32 octets!")
	ct, err := ks.Wrap(secret, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, secret) {
		t.Fatal("le secret apparaît en clair")
	}
	pt, err := ks.Unwrap(ct, []byte("aad"))
	if err != nil || !bytes.Equal(pt, secret) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := ks.Unwrap(ct, []byte("autre")); err == nil {
		t.Fatal("un AAD différent doit être refusé")
	}
	ct[len(ct)-1] ^= 1
	if _, err := ks.Unwrap(ct, []byte("aad")); err == nil {
		t.Fatal("un chiffré modifié doit être refusé")
	}

	msg := []byte("rempart")
	h := sha256.Sum256(msg)
	ec, err := ks.Signer("test-ec", keystore.ECDSAP256, true)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ec.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(ec.Public().(*ecdsa.PublicKey), h[:], sig) {
		t.Fatal("signature ECDSA HSM invalide")
	}
	ed, err := ks.Signer("test-ed", keystore.Ed25519, true)
	if err != nil {
		t.Skipf("Ed25519 non supporté par ce token: %v", err)
	}
	sig, err = ed.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed.Public().(ed25519.PublicKey), msg, sig) {
		t.Fatal("signature Ed25519 HSM invalide")
	}
	if n := len(ks.Keys()); n != 2 {
		t.Fatalf("2 clés attendues, %d trouvées", n)
	}

	// Re-open: keys and KEK persist in the token.
	ks.Close()
	ks2, err := keystore.OpenPKCS11(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ks2.Close()
	ct2, _ := ks2.Wrap(secret, nil)
	if _, err := ks2.Unwrap(ct2, nil); err != nil {
		t.Fatal(err)
	}
	ec2, err := ks2.Signer("test-ec", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if keystore.Fingerprint(ec2.Public()) != keystore.Fingerprint(ec.Public()) {
		t.Fatal("la clé rechargée diffère")
	}
}

func TestDNSSECWithHSM(t *testing.T) {
	cfg := softHSM(t)
	ks, err := keystore.OpenPKCS11(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()
	for _, alg := range []string{"ECDSAP256SHA256", "ED25519"} {
		name := "hsm-" + map[string]string{"ECDSAP256SHA256": "ec", "ED25519": "ed"}[alg] + ".lan"
		z, err := zones.Build(ks, state.Zone{Name: name, DNSSEC: true, Algorithm: alg, Records: []string{"nas IN A 10.0.0.2"}})
		if err != nil {
			t.Fatalf("%s: %v", alg, err) // Build self-verifies every RRSIG made by the HSM
		}
		q := new(dns.Msg)
		q.SetQuestion("nas."+name+".", dns.TypeA)
		r := z.Answer(q, true)
		if len(r.Answer) != 2 {
			t.Fatalf("%s: réponse signée attendue: %v", alg, r.Answer)
		}
		if err := r.Answer[1].(*dns.RRSIG).Verify(z.ZSK, r.Answer[:1]); err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
	}
}

// Les algorithmes proposés à la création d'une zone viennent des mécanismes
// annoncés par le token.
func TestHSMSigningAlgorithms(t *testing.T) {
	cfg := softHSM(t)
	ks, err := keystore.OpenPKCS11(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()
	algs := keystore.SigningAlgorithms(ks)
	if len(algs) != 3 || algs[0].ID != "ECDSAP256SHA256" || !algs[0].Supported || !algs[1].Supported {
		t.Fatalf("algorithmes : %+v", algs)
	}
	for _, a := range algs {
		if !a.Supported {
			continue
		}
		alg, _ := keystore.ParseAlgorithm(a.ID)
		if _, err := ks.Signer("zone-algo-"+string(alg), alg, true); err != nil {
			t.Fatalf("%s annoncé disponible mais refusé : %v", a.ID, err)
		}
	}
	if err := keystore.Supports(ks, keystore.Algorithm("RSA")); err == nil {
		t.Fatal("un algorithme inconnu doit être refusé")
	}
}
