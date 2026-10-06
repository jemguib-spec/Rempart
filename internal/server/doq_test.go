package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
	"github.com/rempart-dns/rempart/internal/tlsutil"
)

func doqSetup(t *testing.T) (*Server, *Encrypted, *tls.Config) {
	s := newTestServer(t)
	tm, err := tlsutil.New(testutil.Keystore(t), tlsutil.Options{KeyLabel: "rempart-tls", SelfSignedNames: []string{"rempart.test"}, DataDir: t.TempDir()}, "selfsigned", nil, testutil.Logger())
	if err != nil {
		t.Fatal(err)
	}
	enc := NewEncrypted(s, tm.Config(), "", "", "/dns-query", "127.0.0.1:0")
	if err := enc.Apply(state.Encryption{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(enc.Close)
	pool := x509.NewCertPool()
	pool.AddCert(tm.Leaf())
	return s, enc, &tls.Config{RootCAs: pool, ServerName: "rempart.test", NextProtos: []string{"doq"}}
}

func doqQuery(t *testing.T, conn *quic.Conn, m *dns.Msg) (*dns.Msg, error) {
	t.Helper()
	st, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	wire, _ := m.Pack()
	buf := binary.BigEndian.AppendUint16(nil, uint16(len(wire)))
	if _, err := st.Write(append(buf, wire...)); err != nil {
		return nil, err
	}
	_ = st.Close() // fin de la requête (RFC 9250 §4.2)
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	var l [2]byte
	if _, err := io.ReadFull(st, l[:]); err != nil {
		return nil, err
	}
	out := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(st, out); err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	return r, r.Unpack(out)
}

func TestDoQ(t *testing.T) {
	_, enc, cc := doqSetup(t)
	st := enc.Status()
	if !st.DoQ.Running {
		t.Fatalf("DoQ arrêté : %+v", st.DoQ)
	}
	addr := enc.doq.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, cc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	if conn.ConnectionState().TLS.NegotiatedProtocol != "doq" {
		t.Fatal("ALPN doq non négocié")
	}
	// Plusieurs requêtes sur la même connexion, une par flux.
	for _, name := range []string{"nas.maison.lan.", "normal.example.", "ads.example."} {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		m.Id = 0
		r, err := doqQuery(t, conn, m)
		if err != nil {
			t.Fatalf("%s : %v", name, err)
		}
		if r.Id != 0 || len(r.Answer) == 0 {
			t.Fatalf("%s : %v", name, r)
		}
	}
	if got := enc.Listeners(); len(got) != 1 {
		t.Fatalf("écoutes : %v", got)
	}

	// Identifiant non nul : erreur de protocole, la connexion est fermée.
	m := new(dns.Msg)
	m.SetQuestion("normal.example.", dns.TypeA)
	m.Id = 1234
	if _, err := doqQuery(t, conn, m); err == nil {
		t.Fatal("identifiant DNS non nul accepté (RFC 9250 §4.2.1)")
	}

	// Arrêt à chaud.
	if err := enc.Apply(state.Encryption{DoQDisabled: true}); err != nil {
		t.Fatal(err)
	}
	if enc.Status().DoQ.Running {
		t.Fatal("DoQ toujours en service")
	}
}

func TestDoQRefusesOtherALPN(t *testing.T) {
	_, enc, cc := doqSetup(t)
	cc.NextProtos = []string{"h3"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := quic.DialAddr(ctx, enc.doq.Addr().String(), cc, nil); err == nil {
		t.Fatal("connexion acceptée sans ALPN doq")
	}
}
