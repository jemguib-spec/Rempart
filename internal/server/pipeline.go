// pipeline.go - traitement en parallèle des requêtes d'une même connexion TCP ou DoT (RFC 7766 §6.2.1.1).
// Entrées : connexions acceptées par les écoutes TCP (port 53) et DNS-over-TLS (port 853).
// Contexte : la bibliothèque miekg/dns lit la requête suivante d'une connexion
// seulement après avoir répondu à la précédente. Android (« DNS privé ») envoie
// toutes ses requêtes sur une seule connexion DoT : une seule requête lente
// (cache froid, résolveur en amont lent) bloquait toutes les autres du
// téléphone. Les réponses partent ici dans l'ordre où elles sont prêtes, chacune
// avec l'identifiant de sa requête, comme le permet la RFC 7766.
package server

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// pipelineDepth : requêtes traitées en même temps par connexion. Au-delà,
	// la connexion revient au traitement une par une (pression arrière).
	pipelineDepth = 64
	// pipelineDrain : temps laissé aux réponses en cours à la fermeture.
	pipelineDrain = 6 * time.Second
)

var errPipeClosed = errors.New("connexion DNS fermée")

// pipeListener enregistre chaque connexion acceptée pour que ServeDNS
// retrouve celle d'une requête et y écrive depuis une autre goroutine.
type pipeListener struct {
	net.Listener
	s *Server
}

func (l *pipeListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	pc := &pipeConn{Conn: c, sem: make(chan struct{}, pipelineDepth), s: l.s}
	pc.key = pipeKey(c.LocalAddr(), c.RemoteAddr())
	l.s.pipes.Store(pc.key, pc)
	if tc, ok := c.(*tls.Conn); ok {
		// Seule une connexion TLS expose ConnectionState : c'est ce qui
		// distingue DoT du TCP en clair dans ServeDNS.
		return &pipeTLSConn{pipeConn: pc, tc: tc}, nil
	}
	return pc, nil
}

func pipeKey(local, remote net.Addr) string {
	if local == nil || remote == nil {
		return ""
	}
	return local.String() + "|" + remote.String()
}

// pipeConn sérialise les écritures (chaque réponse part d'un seul bloc,
// préfixe de longueur compris) et attend les réponses en cours avant de
// fermer.
type pipeConn struct {
	net.Conn
	s   *Server
	key string
	sem chan struct{}

	mu      sync.Mutex
	closed  bool
	pending sync.WaitGroup
	once    sync.Once
}

func (c *pipeConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errPipeClosed
	}
	return c.Conn.Write(b)
}

// writeMsg envoie une réponse au format TCP (longueur sur 2 octets).
func (c *pipeConn) writeMsg(m *dns.Msg) error {
	wire, err := m.Pack()
	if err != nil {
		return err
	}
	if len(wire) > dns.MaxMsgSize {
		return errors.New("réponse trop grande")
	}
	buf := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(buf, uint16(len(wire)))
	copy(buf[2:], wire)
	_, err = c.Write(buf)
	return err
}

// tryAcquire réserve une place pour une requête traitée en parallèle.
func (c *pipeConn) tryAcquire() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	select {
	case c.sem <- struct{}{}:
		c.pending.Add(1)
		return true
	default:
		return false
	}
}

func (c *pipeConn) release() {
	<-c.sem
	c.pending.Done()
}

// Close laisse aux réponses en cours le temps de partir (bornée par le
// délai de résolution), puis ferme la connexion.
func (c *pipeConn) Close() error {
	var err error
	c.once.Do(func() {
		c.s.pipes.Delete(c.key)
		done := make(chan struct{})
		go func() { c.pending.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(pipelineDrain):
		}
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		err = c.Conn.Close()
	})
	return err
}

type pipeTLSConn struct {
	*pipeConn
	tc *tls.Conn
}

func (c *pipeTLSConn) ConnectionState() tls.ConnectionState { return c.tc.ConnectionState() }

// pipeFor rend la connexion d'une requête TCP ou DoT, nil sinon.
func (s *Server) pipeFor(w dns.ResponseWriter) *pipeConn {
	k := pipeKey(w.LocalAddr(), w.RemoteAddr())
	if k == "" {
		return nil
	}
	if v, ok := s.pipes.Load(k); ok {
		return v.(*pipeConn)
	}
	return nil
}
