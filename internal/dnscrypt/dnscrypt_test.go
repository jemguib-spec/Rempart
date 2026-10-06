package dnscrypt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func newServer(t *testing.T) *Server {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := New("2.dnscrypt-cert.rempart.test", priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type parsedCert struct {
	es     uint16
	pk     [32]byte
	magic  [8]byte
	serial uint32
	start  uint32
	end    uint32
}

func parseCert(t *testing.T, c []byte, provider ed25519.PublicKey) parsedCert {
	t.Helper()
	if len(c) != 124 || !bytes.Equal(c[:4], []byte("DNSC")) {
		t.Fatalf("certificat mal formé (%d octets)", len(c))
	}
	if !ed25519.Verify(provider, c[72:], c[8:72]) {
		t.Fatal("signature du certificat invalide")
	}
	var p parsedCert
	p.es = binary.BigEndian.Uint16(c[4:6])
	copy(p.pk[:], c[72:104])
	copy(p.magic[:], c[104:112])
	p.serial = binary.BigEndian.Uint32(c[112:116])
	p.start = binary.BigEndian.Uint32(c[116:120])
	p.end = binary.BigEndian.Uint32(c[120:124])
	return p
}

// client : requête chiffrée comme le ferait dnscrypt-proxy.
func query(t *testing.T, c parsedCert, msg []byte, pad int) ([]byte, [32]byte, [12]byte) {
	var sk [32]byte
	_, _ = rand.Read(sk[:])
	pk, _ := curve25519.X25519(sk[:], curve25519.Basepoint)
	var cpk [32]byte
	copy(cpk[:], pk)
	shared, err := sharedKey(c.es, &sk, &c.pk)
	if err != nil {
		t.Fatal(err)
	}
	var cn [12]byte
	_, _ = rand.Read(cn[:])
	var nonce [24]byte
	copy(nonce[:], cn[:])
	plain := append(append([]byte{}, msg...), 0x80)
	for len(plain) < pad {
		plain = append(plain, 0)
	}
	out := append([]byte{}, c.magic[:]...)
	out = append(out, cpk[:]...)
	out = append(out, cn[:]...)
	return seal(c.es, out, plain, &nonce, &shared), shared, cn
}

func TestRoundTripBothConstructions(t *testing.T) {
	s := newServer(t)
	certs := s.Certificates()
	if len(certs) != 2 {
		t.Fatalf("%d certificats", len(certs))
	}
	seen := map[uint16]bool{}
	for _, raw := range certs {
		c := parseCert(t, raw, s.ProviderKey())
		seen[c.es] = true
		now := uint32(time.Now().Unix())
		if c.start > now || c.end < now || c.end-c.start > 86400 {
			t.Fatalf("validité du certificat : %d..%d", c.start, c.end)
		}
		msg := []byte("requête-dns-de-test")
		pkt, shared, cn := query(t, c, msg, 256)
		got, sess, err := s.Decrypt(pkt)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("es %d : déchiffrement %v %q", c.es, err, got)
		}
		resp, err := sess.Encrypt([]byte("réponse"), len(pkt))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(resp[:8], serverMagic) || !bytes.Equal(resp[8:20], cn[:]) || len(resp) > len(pkt) {
			t.Fatal("en-tête de réponse")
		}
		var nonce [24]byte
		copy(nonce[:], resp[8:32])
		plain, err := open(c.es, resp[32:], &nonce, &shared)
		if err != nil {
			t.Fatal(err)
		}
		if r, err := unpad(plain); err != nil || string(r) != "réponse" || len(plain)%64 != 0 {
			t.Fatalf("réponse %q %v", r, err)
		}
		// Altération : refusée.
		bad := append([]byte{}, pkt...)
		bad[len(bad)-1] ^= 1
		if _, _, err := s.Decrypt(bad); err == nil {
			t.Fatal("requête altérée acceptée")
		}
		// Réponse plus grande que la requête : refusée (le serveur tronque).
		if _, err := sess.Encrypt(make([]byte, 1000), len(pkt)); err == nil {
			t.Fatal("réponse UDP plus grande que la requête")
		}
	}
	if !seen[XChaCha20Poly1305] || !seen[XSalsa20Poly1305] {
		t.Fatal("constructions annoncées")
	}
}

func TestRotationKeepsPrevious(t *testing.T) {
	s := newServer(t)
	old := parseCert(t, s.Certificates()[0], s.ProviderKey())
	if err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	pkt, _, _ := query(t, old, []byte("encore valable 123"), 128)
	if _, _, err := s.Decrypt(pkt); err != nil {
		t.Fatal("clé précédente refusée juste après la rotation")
	}
	_ = s.Rotate()
	if _, _, err := s.Decrypt(pkt); err == nil {
		t.Fatal("clé de deux générations acceptée")
	}
	if len(s.Certificates()) != 4 {
		t.Fatalf("%d certificats publiés", len(s.Certificates()))
	}
}

func TestNotDNSCryptAndStamp(t *testing.T) {
	s := newServer(t)
	if _, _, err := s.Decrypt(make([]byte, 100)); err != ErrNotDNSCrypt {
		t.Fatal("paquet ordinaire pris pour du DNSCrypt")
	}
	st := s.Stamp("192.0.2.53:443", true, false, false)
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(st, "sdns://"))
	if err != nil || raw[0] != 0x01 || raw[1] != 1 {
		t.Fatalf("tampon %s", st)
	}
	p := raw[9:]
	addr := string(p[1 : 1+p[0]])
	p = p[1+p[0]:]
	pk := p[1 : 1+p[0]]
	p = p[1+p[0]:]
	name := string(p[1 : 1+p[0]])
	if addr != "192.0.2.53:443" || !bytes.Equal(pk, s.ProviderKey()) || name != "2.dnscrypt-cert.rempart.test" {
		t.Fatalf("%s %x %s", addr, pk, name)
	}
	if _, err := New("rempart.test", ed25519.NewKeyFromSeed(make([]byte, 32))); err == nil {
		t.Fatal("nom de fournisseur non standard accepté")
	}
}
