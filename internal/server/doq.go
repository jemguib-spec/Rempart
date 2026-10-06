// doq.go - DNS-over-QUIC (RFC 9250).

package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// DoQ : écoute DNS-over-QUIC.
type DoQ struct {
	ln     *quic.Listener
	cancel context.CancelFunc
	done   chan struct{}
}

const (
	doqIdle        = 30 * time.Second // RFC 9250 §5.5 : garder les connexions ouvertes
	doqStreamLimit = 100              // flux simultanés par connexion
	doqMaxMsg      = dns.MaxMsgSize
	// Codes d'erreur applicatifs (RFC 9250 §4.3).
	doqNoError       quic.ApplicationErrorCode = 0
	doqProtocolError quic.ApplicationErrorCode = 2
)

// ListenDoQ écoute en DNS-over-QUIC (ALPN « doq ») sur addr.
func (s *Server) ListenDoQ(addr string, tlsConf *tls.Config) (*DoQ, error) {
	tc := tlsConf.Clone()
	tc.NextProtos = []string{"doq"}
	tc.MinVersion = tls.VersionTLS13 // QUIC exige TLS 1.3
	ln, err := quic.ListenAddr(addr, tc, &quic.Config{
		MaxIdleTimeout:        doqIdle,
		MaxIncomingStreams:    doqStreamLimit,
		MaxIncomingUniStreams: -1,    // aucun flux unidirectionnel en DoQ
		Allow0RTT:             false, // pas de 0-RTT : rejouable (RFC 9250 §4.5)
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &DoQ{ln: ln, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(d.done)
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go s.serveDoQConn(ctx, conn)
		}
	}()
	return d, nil
}

// Addr renvoie l'adresse d'écoute.
func (d *DoQ) Addr() net.Addr { return d.ln.Addr() }

// Close arrête l'écoute et ferme les connexions.
func (d *DoQ) Close() error {
	d.cancel()
	err := d.ln.Close()
	<-d.done
	return err
}

func (s *Server) serveDoQConn(ctx context.Context, conn *quic.Conn) {
	ip := netip.Addr{}
	if ua, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
		ip, _ = netip.AddrFromSlice(ua.IP)
		ip = ip.Unmap()
	}
	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func() {
			if err := s.serveDoQStream(ctx, st, ip); err != nil {
				_ = conn.CloseWithError(doqProtocolError, "")
			}
		}()
	}
}

// serveDoQStream : une requête par flux, préfixée de sa longueur ; le
// client ferme son sens d'émission après la requête (RFC 9250 §4.2).
func (s *Server) serveDoQStream(ctx context.Context, st *quic.Stream, ip netip.Addr) error {
	defer st.Close()
	_ = st.SetDeadline(time.Now().Add(10 * time.Second))
	var lenBuf [2]byte
	if _, err := io.ReadFull(st, lenBuf[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n < 12 {
		return errors.New("message DoQ trop court")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(st, buf); err != nil {
		return err
	}
	req := new(dns.Msg)
	if err := req.Unpack(buf); err != nil {
		return err
	}
	// RFC 9250 §4.2.1 : l'identifiant DNS doit valoir 0.
	if req.Id != 0 {
		return errors.New("identifiant DNS non nul en DoQ")
	}
	resp := s.Handle(ctx, req, ip, "doq")
	if resp == nil {
		return nil
	}
	resp.Id = 0
	out, err := resp.Pack()
	if err != nil {
		return err
	}
	if len(out) > doqMaxMsg {
		return errors.New("réponse trop grande")
	}
	msg := make([]byte, 2+len(out))
	binary.BigEndian.PutUint16(msg, uint16(len(out)))
	copy(msg[2:], out)
	_, err = st.Write(msg)
	return err
}
