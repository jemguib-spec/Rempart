package auditfwd

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rempart-dns/rempart/internal/audit"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

// Collecteur TCP à comptage d'octets (RFC 6587).
func collector(t *testing.T) (string, chan string) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	out := make(chan string, 100)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				r := bufio.NewReader(c)
				for {
					ln, err := r.ReadString(' ')
					if err != nil {
						return
					}
					n, _ := strconv.Atoi(strings.TrimSpace(ln))
					buf := make([]byte, n)
					if _, err := ioReadFull(r, buf); err != nil {
						return
					}
					out <- string(buf)
				}
			}()
		}
	}()
	return l.Addr().String(), out
}

func ioReadFull(r *bufio.Reader, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := r.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func TestForwardInOrderAfterOutage(t *testing.T) {
	ks := testutil.Keystore(t)
	dir := t.TempDir()
	al, err := audit.Open(ks, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Événements écrits avant que le collecteur existe.
	_ = al.Add("admin", "connexion", "depuis 10.0.0.1")
	_ = al.Add("admin", "règle.ajout", "blocage ads.example")
	f := &Forwarder{Audit: al, DataDir: dir, Log: testutil.Logger()}
	al.OnAdd = func(audit.Event) { f.Wake() }
	addr, got := collector(t)
	f.Configure(state.SyslogConfig{Enabled: true, Network: "tcp", Address: addr, Hostname: "rempart-1"})
	_ = al.Add("admin", "zone.création", "maison.lan.")
	for i, want := range []string{"connexion", "règle.ajout", "zone.création"} {
		select {
		case m := <-got:
			if !strings.HasPrefix(m, "<109>1 ") || !strings.Contains(m, " rempart-1 rempart ") || !strings.Contains(m, `"action":"`+want+`"`) || !strings.Contains(m, `"seq":`+strconv.Itoa(i+1)) {
				t.Fatalf("message %d inattendu : %s", i+1, m)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("message %d non reçu", i+1)
		}
	}
	// La position avance juste après l'écriture : le collecteur peut avoir
	// reçu le message un instant avant.
	st := f.Status()
	for i := 0; i < 100 && (st.Pending != 0 || st.LastSeq != 3); i++ {
		time.Sleep(10 * time.Millisecond)
		st = f.Status()
	}
	if st.Pending != 0 || st.LastSeq != 3 {
		t.Fatalf("état : %+v", st)
	}
	if err := Validate(state.SyslogConfig{Enabled: true, Network: "tls", Address: "pas-de-port"}); err == nil {
		t.Fatal("adresse invalide acceptée")
	}
}
