package ldap

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- filtres ----

func TestEscapeAndExpand(t *testing.T) {
	got, err := Expand("(&(objectClass=person)(uid={user}))", map[string]string{"user": "a*)(uid=*"})
	if err != nil {
		t.Fatal(err)
	}
	if got != `(&(objectClass=person)(uid=a\2a\29\28uid=\2a))` {
		t.Fatalf("échappement : %s", got)
	}
	// L'injection reste une simple valeur d'égalité.
	b, err := CompileFilter(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("a*)(uid=*")) {
		t.Fatal("la valeur doit être décodée telle quelle")
	}
	if _, err := Expand("(uid={nom})", map[string]string{"user": "x"}); err == nil {
		t.Fatal("marqueur inconnu accepté")
	}
}

func TestCompileFilter(t *testing.T) {
	ok := []string{
		"(uid=alice)", "(objectClass=*)", "(cn=al*ce)", "(cn=*ice)", "(cn=al*)", "(cn=*l*c*)",
		"(&(a=1)(|(b=2)(!(c=3))))", "(age>=3)", "(age<=3)", "(cn~=x)",
		"(member:1.2.840.113556.1.4.1941:=cn=g,dc=x)", "(cn:dn:2.4.6.8.10:=Dino)", "(:1.2.3:=x)",
		`(cn=\28x\29)`,
	}
	for _, f := range ok {
		if _, err := CompileFilter(f); err != nil {
			t.Errorf("%s : %v", f, err)
		}
	}
	bad := []string{"", "uid=a", "(uid=a", "(uid=a))", "(&)", "(cn=a**b)", "(age>=*)", `(cn=\2)`, `(cn=\zz)`, "(=x)", "(cn=a(b)", "(:=x)"}
	for _, f := range bad {
		if _, err := CompileFilter(f); err == nil {
			t.Errorf("%q accepté", f)
		}
	}
	// Présence : [7] primitif.
	b, _ := CompileFilter("(objectClass=*)")
	if b[0] != 0x87 {
		t.Fatalf("présence mal encodée : %x", b)
	}
	deep := strings.Repeat("(!", 40) + "(a=b)" + strings.Repeat(")", 40)
	if _, err := CompileFilter(deep); err == nil {
		t.Fatal("imbrication excessive acceptée")
	}
}

func TestBERRoundTrip(t *testing.T) {
	for _, v := range []int64{0, 1, 127, 128, 255, 256, -1, -128, -129, 1 << 40} {
		b := encInt(tagInteger, v)
		e, err := parse(b[0], b[2:], 0)
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.int()
		if err != nil || got != v {
			t.Fatalf("%d -> %d (%v)", v, got, err)
		}
	}
	long := make([]byte, 70000)
	b := encStr(tagOctetString, string(long))
	m, err := readMessage(bufio.NewReader(bytes.NewReader(b)))
	if err != nil || len(m.value) != 70000 {
		t.Fatal("longueur longue")
	}
	// Forme indéfinie et longueur fausse refusées.
	for _, raw := range [][]byte{{0x30, 0x80, 0, 0}, {0x30, 0x05, 0x04, 0x09, 'a'}, {0x30, 0x85, 1, 1, 1, 1, 1}} {
		if _, err := readMessage(bufio.NewReader(bytes.NewReader(raw))); err == nil {
			t.Fatalf("%x accepté", raw)
		}
	}
}

func TestNormalizeDN(t *testing.T) {
	if NormalizeDN("CN=Rempart Admins, OU=Groups ,DC=corp,DC=local") != "cn=rempart admins,ou=groups,dc=corp,dc=local" {
		t.Fatal(NormalizeDN("CN=Rempart Admins, OU=Groups ,DC=corp,DC=local"))
	}
	if NormalizeDN(`cn=a\,b,dc=x`) != `cn=a\,b,dc=x` {
		t.Fatal("virgule échappée")
	}
}

func TestParseURL(t *testing.T) {
	if _, _, _, err := ParseURL("ldap://dc1", false); err == nil {
		t.Fatal("ldap:// sans StartTLS accepté")
	}
	if a, _, tlsI, err := ParseURL("ldaps://dc1.corp", false); err != nil || a != "dc1.corp:636" || !tlsI {
		t.Fatal(a, err)
	}
	if a, _, tlsI, err := ParseURL("ldap://dc1.corp", true); err != nil || a != "dc1.corp:389" || tlsI {
		t.Fatal(a, err)
	}
	for _, u := range []string{"http://x", "ldaps://", "ldaps://u:p@x", "ldaps://x/dc=a?b"} {
		if _, _, _, err := ParseURL(u, true); err == nil {
			t.Fatalf("%s accepté", u)
		}
	}
}

// ---- faux annuaire ----

type fakeEntry struct {
	dn    string
	pw    string
	attrs map[string][]string
}

type fakeDir struct {
	t        *testing.T
	tlsConf  *tls.Config
	startTLS bool
	entries  []fakeEntry
	mu       sync.Mutex
	binds    []string
	filters  [][]byte
}

func (f *fakeDir) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

func ldapResult(app byte, id int64, code int, msg string) []byte {
	return seq(tagSequence, encInt(tagInteger, id), seq(classApplication|constructed|app,
		encInt(tagEnumerated, int64(code)), encStr(tagOctetString, ""), encStr(tagOctetString, msg)))
}

func (f *fakeDir) handle(nc net.Conn) {
	defer nc.Close()
	var conn net.Conn = nc
	r := bufio.NewReader(conn)
	secured := !f.startTLS
	for {
		m, err := readMessage(r)
		if err != nil {
			return
		}
		id, _ := m.children[0].int()
		op := m.children[1]
		switch op.tag {
		case classApplication | constructed | 23: // StartTLS
			conn.Write(seq(tagSequence, encInt(tagInteger, id), seq(classApplication|constructed|24,
				encInt(tagEnumerated, 0), encStr(tagOctetString, ""), encStr(tagOctetString, ""))))
			tc := tls.Server(nc, f.tlsConf)
			if err := tc.Handshake(); err != nil {
				return
			}
			conn, r, secured = tc, bufio.NewReader(tc), true
		case classApplication | constructed | 0: // Bind
			if !secured {
				f.t.Error("liaison reçue avant TLS")
				return
			}
			dn, pw := op.children[1].str(), op.children[2].str()
			f.mu.Lock()
			f.binds = append(f.binds, dn)
			f.mu.Unlock()
			code := ResultInvalidCredentials
			for _, e := range f.entries {
				if e.dn == dn && e.pw == pw && pw != "" {
					code = 0
				}
			}
			conn.Write(ldapResult(1, id, code, ""))
		case classApplication | constructed | 3: // Search
			raw := op.children[6]
			f.mu.Lock()
			f.filters = append(f.filters, append([]byte{raw.tag}, raw.value...))
			f.mu.Unlock()
			for _, e := range f.entries {
				if match(raw, e) {
					var as [][]byte
					for k, vs := range e.attrs {
						var vals [][]byte
						for _, v := range vs {
							vals = append(vals, encStr(tagOctetString, v))
						}
						as = append(as, seq(tagSequence, encStr(tagOctetString, k), seq(tagSet, vals...)))
					}
					conn.Write(seq(tagSequence, encInt(tagInteger, id), seq(classApplication|constructed|4,
						encStr(tagOctetString, e.dn), seq(tagSequence, as...))))
				}
			}
			conn.Write(ldapResult(5, id, 0, ""))
		case classApplication | 2: // Unbind
			return
		}
	}
}

// match comprend l'égalité, le ET et la présence : assez pour les tests.
func match(f *element, e fakeEntry) bool {
	switch f.tag {
	case classContext | constructed | 0:
		for _, c := range f.children {
			if !match(c, e) {
				return false
			}
		}
		return true
	case classContext | 7:
		return len(e.attrs[strings.ToLower(string(f.value))]) > 0
	case classContext | constructed | 3:
		k, v := strings.ToLower(f.children[0].str()), f.children[1].str()
		if k == "member" {
			for _, m := range e.attrs["member"] {
				if m == v {
					return true
				}
			}
			return false
		}
		for _, x := range e.attrs[k] {
			if strings.EqualFold(x, v) {
				return true
			}
		}
	}
	return false
}

func testCert(t *testing.T) (*tls.Config, *x509.CertPool) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}, pool
}

func newFake(t *testing.T, startTLS bool) (*fakeDir, string, *x509.CertPool) {
	tc, pool := testCert(t)
	f := &fakeDir{t: t, tlsConf: tc, startTLS: startTLS, entries: []fakeEntry{
		{dn: "cn=svc,dc=corp", pw: "service-pw", attrs: map[string][]string{}},
		{dn: "uid=alice,ou=people,dc=corp", pw: "alice-pw", attrs: map[string][]string{
			"objectclass": {"person"}, "uid": {"alice"}, "displayname": {"Alice Martin"},
			"memberof": {"cn=Rempart-Admins,ou=groups,dc=corp"}}},
		{dn: "cn=readers,ou=groups,dc=corp", attrs: map[string][]string{"objectclass": {"groupOfNames"}, "member": {"uid=alice,ou=people,dc=corp"}}},
	}}
	var ln net.Listener
	var err error
	if startTLS {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	} else {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", tc)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go f.serve(ln)
	scheme := "ldaps"
	if startTLS {
		scheme = "ldap"
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return f, scheme + "://localhost:" + port, pool
}

func dirFor(url string, startTLS bool, pool *x509.CertPool) *Directory {
	return &Directory{URLs: url, Opts: Options{StartTLS: startTLS, RootCAs: pool, Timeout: 3 * time.Second},
		BindDN: "cn=svc,dc=corp", BindPassword: "service-pw", UserBase: "dc=corp",
		UserFilter: "(&(objectClass=person)(uid={user}))", UserAttr: "uid", DisplayAttr: "displayName",
		GroupAttr: "memberOf", GroupBase: "ou=groups,dc=corp", GroupFilter: "(&(objectClass=groupOfNames)(member={dn}))"}
}

func TestAuthenticate(t *testing.T) {
	for _, st := range []bool{false, true} {
		f, url, pool := newFake(t, st)
		d := dirFor(url, st, pool)
		ctx := context.Background()
		u, err := d.Authenticate(ctx, "alice", "alice-pw")
		if err != nil {
			t.Fatalf("startTLS=%v : %v", st, err)
		}
		if u.DN != "uid=alice,ou=people,dc=corp" || u.Display != "Alice Martin" || len(u.Groups) != 2 {
			t.Fatalf("%+v", u)
		}
		if _, err := d.Authenticate(ctx, "alice", "mauvais"); err != ErrInvalidCredentials {
			t.Fatalf("mauvais mot de passe : %v", err)
		}
		if _, err := d.Authenticate(ctx, "bob", "x"); err != ErrInvalidCredentials {
			t.Fatalf("inconnu : %v", err)
		}
		if _, err := d.Authenticate(ctx, "alice", ""); err != ErrInvalidCredentials {
			t.Fatal("mot de passe vide")
		}
		// Injection : « * » ne doit pas trouver alice.
		if _, err := d.Authenticate(ctx, "*", "alice-pw"); err != ErrInvalidCredentials {
			t.Fatalf("injection : %v", err)
		}
		f.mu.Lock()
		for _, b := range f.binds {
			if b == "" {
				t.Fatal("liaison anonyme envoyée")
			}
		}
		f.mu.Unlock()
		u, err = d.Lookup(ctx, "alice")
		if err != nil || len(u.Groups) != 2 {
			t.Fatal(u, err)
		}
		d.BindPassword = "faux"
		if _, err := d.Authenticate(ctx, "alice", "alice-pw"); err == nil || err == ErrInvalidCredentials {
			t.Fatalf("compte de service refusé doit être signalé : %v", err)
		}
	}
}

func TestCertificateVerified(t *testing.T) {
	_, url, _ := newFake(t, false)
	d := dirFor(url, false, x509.NewCertPool()) // AC inconnue
	if _, err := d.Authenticate(context.Background(), "alice", "alice-pw"); err == nil {
		t.Fatal("certificat non vérifié")
	}
}

func TestFailover(t *testing.T) {
	_, url, pool := newFake(t, false)
	d := dirFor("ldaps://127.0.0.1:1 "+url, false, pool)
	if _, err := d.Authenticate(context.Background(), "alice", "alice-pw"); err != nil {
		t.Fatal(err)
	}
}
