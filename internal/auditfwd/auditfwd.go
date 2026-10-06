// Package auditfwd copie le journal d'audit vers un collecteur syslog ou un
// SIEM (RFC 5424), en TLS (RFC 5425), TCP (RFC 6587, comptage d'octets) ou
// UDP (RFC 5426). La copie relit le journal signé lui-même à partir de la
// dernière position remise : un collecteur injoignable ne fait perdre aucun
// événement, qui partent dans l'ordre à son retour.
package auditfwd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rempart-dns/rempart/internal/audit"
	"github.com/rempart-dns/rempart/internal/state"
)

// Facilité 13 (log audit, RFC 5424 §6.2.1), gravité 5 (notice).
const pri = 13*8 + 5

// Status : état de la copie, pour l'interface et les métriques.
type Status struct {
	Enabled   bool      `json:"enabled"`
	Sent      uint64    `json:"sent"`
	LastSeq   uint64    `json:"last_seq"`
	Pending   uint64    `json:"pending"`
	LastOK    time.Time `json:"last_ok"`
	LastError string    `json:"last_error,omitempty"`
}

// Forwarder : voir le commentaire du paquet.
type Forwarder struct {
	Audit   *audit.Log
	DataDir string
	Log     *slog.Logger

	cfg  atomic.Pointer[state.SyslogConfig]
	wake chan struct{}
	once sync.Once

	mu     sync.Mutex // position et état ; jamais tenu pendant une écriture réseau
	pos    position
	status Status

	connMu sync.Mutex
	conn   net.Conn
	connTo string
}

type position struct {
	Seq    uint64 `json:"seq"`
	Offset int64  `json:"offset"`
}

func (f *Forwarder) posPath() string { return filepath.Join(f.DataDir, "audit-forward.json") }

// Wake signale un nouvel événement (à brancher sur audit.Log.OnAdd).
func (f *Forwarder) Wake() {
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// Configure applique une configuration ; la première démarre la boucle.
func (f *Forwarder) Configure(c state.SyslogConfig) {
	f.once.Do(func() {
		f.wake = make(chan struct{}, 1)
		if raw, err := os.ReadFile(f.posPath()); err == nil {
			_ = json.Unmarshal(raw, &f.pos)
		}
		go f.run()
	})
	old := f.cfg.Swap(&c)
	if old == nil || *old != c {
		f.closeConn()
		f.mu.Lock()
		f.status.Enabled = c.Enabled
		f.status.LastError = ""
		f.mu.Unlock()
	}
	f.Wake()
}

// Status renvoie l'état de la copie.
func (f *Forwarder) Status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.status
	s.LastSeq = f.pos.Seq
	if seq := f.Audit.Seq(); seq > f.pos.Seq {
		s.Pending = seq - f.pos.Seq
	}
	return s
}

func (f *Forwarder) closeConn() {
	f.connMu.Lock()
	defer f.connMu.Unlock()
	if f.conn != nil {
		_ = f.conn.Close()
		f.conn = nil
	}
}

func (f *Forwarder) run() {
	backoff := time.Second
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-f.wake:
		case <-tick.C:
		}
		for {
			c := f.cfg.Load()
			if c == nil || !c.Enabled {
				break
			}
			n, err := f.flush(*c)
			if err != nil {
				f.closeConn()
			}
			f.mu.Lock()
			if err != nil {
				f.status.LastError = err.Error()
			} else if n > 0 {
				f.status.LastOK, f.status.LastError = time.Now().UTC(), ""
			}
			f.mu.Unlock()
			if err != nil {
				f.Log.Warn("copie de l'audit vers le syslog en échec", "err", err)
				time.Sleep(backoff)
				backoff = min(2*backoff, time.Minute)
				continue
			}
			backoff = time.Second
			if n == 0 {
				break
			}
		}
	}
}

// flush envoie un lot d'événements non remis ; renvoie leur nombre.
func (f *Forwarder) flush(c state.SyslogConfig) (int, error) {
	f.mu.Lock()
	pos := f.pos
	f.mu.Unlock()
	evs, next, err := f.Audit.ReadFrom(pos.Offset, 200)
	if err != nil {
		return 0, err
	}
	// Position incohérente (journal remplacé, restauration) : on relit depuis
	// le début en sautant ce qui a déjà été remis ; si le journal est plus
	// court que ce qui a été remis, tout est renvoyé.
	if len(evs) > 0 && evs[0].Seq != pos.Seq+1 && pos.Offset != 0 {
		f.mu.Lock()
		f.pos.Offset = 0
		if f.Audit.Seq() < pos.Seq {
			f.pos.Seq = 0
		}
		f.mu.Unlock()
		return f.flush(c)
	}
	sent := 0
	host := c.Hostname
	if host == "" {
		host, _ = os.Hostname()
	}
	for _, e := range evs {
		if e.Seq <= pos.Seq {
			continue
		}
		if err := f.send(c, format(e, host)); err != nil {
			return sent, err
		}
		sent++
		f.mu.Lock()
		f.pos.Seq = e.Seq
		f.status.Sent++
		f.mu.Unlock()
	}
	f.mu.Lock()
	f.pos.Offset = next
	raw, _ := json.Marshal(f.pos)
	f.mu.Unlock()
	if len(evs) > 0 {
		if err := os.WriteFile(f.posPath(), raw, 0o600); err != nil {
			return sent, err
		}
	}
	return sent, nil
}

// format : message RFC 5424, corps JSON (UTF-8 précédé du BOM) qui reprend
// l'événement signé tel quel, chaînage et signature compris : le SIEM peut
// le vérifier.
func format(e audit.Event, host string) []byte {
	body, _ := json.Marshal(e)
	host = strings.Map(func(r rune) rune {
		if r < 33 || r > 126 {
			return -1
		}
		return r
	}, host)
	if len(host) > 255 { // RFC 5424 §6 : HOSTNAME de 255 caractères au plus
		host = host[:255]
	}
	if host == "" {
		host = "-"
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "<%d>1 %s %s rempart %d AUDIT - \xef\xbb\xbf", pri, e.Time.UTC().Format("2006-01-02T15:04:05.000Z"), host, os.Getpid())
	b.Write(body)
	return b.Bytes()
}

func (f *Forwarder) dial(c state.SyslogConfig) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	switch c.Network {
	case "udp":
		return d.Dial("udp", c.Address)
	case "tcp":
		return d.Dial("tcp", c.Address)
	case "tls":
		host, _, err := net.SplitHostPort(c.Address)
		if err != nil {
			return nil, err
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if c.CABundle != "" && !roots.AppendCertsFromPEM([]byte(c.CABundle)) {
			return nil, errors.New("AC du collecteur : PEM invalide")
		}
		return tls.DialWithDialer(d, "tcp", c.Address, &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12})
	}
	return nil, fmt.Errorf("transport %q inconnu", c.Network)
}

func (f *Forwarder) send(c state.SyslogConfig, msg []byte) error {
	f.connMu.Lock()
	defer f.connMu.Unlock()
	key := c.Network + "://" + c.Address
	if f.conn == nil || f.connTo != key {
		if f.conn != nil {
			_ = f.conn.Close()
			f.conn = nil
		}
		conn, err := f.dial(c)
		if err != nil {
			return err
		}
		f.conn, f.connTo = conn, key
	}
	_ = f.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	var err error
	if c.Network == "udp" {
		_, err = f.conn.Write(msg)
	} else {
		// RFC 6587 §3.4.1 / RFC 5425 §4.3 : « LONGUEUR ESPACE MESSAGE ».
		_, err = f.conn.Write(append([]byte(fmt.Sprintf("%d ", len(msg))), msg...))
	}
	return err
}

// Validate vérifie une configuration saisie.
func Validate(c state.SyslogConfig) error {
	if !c.Enabled && c.Address == "" {
		return nil
	}
	switch c.Network {
	case "tls", "tcp", "udp":
	default:
		return errors.New("transport : tls, tcp ou udp")
	}
	if _, _, err := net.SplitHostPort(c.Address); err != nil {
		return errors.New("adresse du collecteur : hôte:port attendu")
	}
	if c.CABundle != "" {
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CABundle)) {
			return errors.New("AC du collecteur : PEM invalide")
		}
	}
	return nil
}
