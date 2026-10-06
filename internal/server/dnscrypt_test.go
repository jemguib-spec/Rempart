package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/dnscrypt"
	"github.com/rempart-dns/rempart/internal/state"
)

func TestDNSCryptListener(t *testing.T) {
	s := newTestServer(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	dc, err := dnscrypt.New("2.dnscrypt-cert.rempart.test", priv)
	if err != nil {
		t.Fatal(err)
	}
	enc := NewEncrypted(s, nil, "", "", "/dns-query", "")
	enc.SetDNSCrypt("127.0.0.1:0", dc, "203.0.113.1:443")
	if err := enc.Apply(state.Encryption{DoTDisabled: true, DoHDisabled: true, DoQDisabled: true}); err != nil {
		t.Fatal(err)
	}
	if enc.Status().DNSCrypt.Running {
		t.Fatal("DNSCrypt démarré sans être activé")
	}
	if err := enc.Apply(state.Encryption{DNSCryptEnabled: true}); err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	st := enc.Status()
	if !st.DNSCrypt.Running || st.DNSCrypt.Stamp == "" {
		t.Fatalf("%+v", st.DNSCrypt)
	}
	addr := enc.dc.Addr().String()

	// Certificats demandés en clair, comme le fait un client.
	q := new(dns.Msg)
	q.SetQuestion("2.dnscrypt-cert.rempart.test.", dns.TypeTXT)
	r, _, err := (&dns.Client{}).Exchange(q, addr)
	if err != nil || len(r.Answer) != 2 {
		t.Fatalf("certificats : %v %v", r, err)
	}
	var certs []dnscrypt.Cert
	for _, rr := range r.Answer {
		raw := []byte{}
		for _, s := range rr.(*dns.TXT).Txt {
			raw = append(raw, unescapeTXT(s)...)
		}
		c, err := dnscrypt.ParseCert(raw, dc.ProviderKey(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, c)
	}
	// Une autre requête en clair n'est pas servie.
	q.SetQuestion("normal.example.", dns.TypeA)
	if _, _, err := (&dns.Client{Timeout: 300 * time.Millisecond}).Exchange(q, addr); err == nil {
		t.Fatal("requête en clair servie sur l'écoute DNSCrypt")
	}

	for _, c := range certs {
		m := new(dns.Msg)
		m.SetQuestion("nas.maison.lan.", dns.TypeA)
		wire, _ := m.Pack()
		// UDP
		pkt, open, err := c.Seal(wire, 256)
		if err != nil {
			t.Fatal(err)
		}
		conn, _ := net.Dial("udp", addr)
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = conn.Write(pkt)
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			t.Fatalf("es %d : %v", c.ES, err)
		}
		plain, err := open(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(plain); err != nil || len(resp.Answer) != 1 {
			t.Fatalf("réponse UDP : %v %v", resp, err)
		}
		// TCP
		pkt, open, _ = c.Seal(wire, 0)
		tc, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = tc.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(pkt))), pkt...))
		var l [2]byte
		if _, err := io.ReadFull(tc, l[:]); err != nil {
			t.Fatal(err)
		}
		out := make([]byte, binary.BigEndian.Uint16(l[:]))
		_, _ = io.ReadFull(tc, out)
		tc.Close()
		if plain, err = open(out); err != nil || resp.Unpack(plain) != nil || len(resp.Answer) != 1 {
			t.Fatalf("réponse TCP : %v", err)
		}
	}
}

func unescapeTXT(s string) []byte {
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && isDigit3(s[i+1:]) {
			out = append(out, (s[i+1]-'0')*100+(s[i+2]-'0')*10+(s[i+3]-'0'))
			i += 3
			continue
		}
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		out = append(out, s[i])
	}
	return out
}

func isDigit3(s string) bool {
	return len(s) >= 3 && s[0] >= '0' && s[0] <= '9' && s[1] >= '0' && s[1] <= '9' && s[2] >= '0' && s[2] <= '9'
}
