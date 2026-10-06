// dnscrypt.go - écoute DNSCrypt v2 (UDP et TCP). Les requêtes déchiffrées
// suivent le même chemin que les autres (ACL, filtrage, journal).

package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/dnscrypt"
)

// DNSCrypt : écoutes UDP et TCP d'un serveur DNSCrypt.
type DNSCrypt struct {
	srv    *Server
	dc     *dnscrypt.Server
	pc     net.PacketConn
	ln     net.Listener
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// ListenDNSCrypt écoute en DNSCrypt sur addr (UDP et TCP) ; les clés de
// résolveur sont renouvelées toutes les heures.
func (s *Server) ListenDNSCrypt(addr string, dc *dnscrypt.Server) (*DNSCrypt, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &DNSCrypt{srv: s, dc: dc, pc: pc, ln: ln, cancel: cancel}
	d.wg.Add(3)
	go d.serveUDP(ctx)
	go d.serveTCP(ctx)
	go func() {
		defer d.wg.Done()
		t := time.NewTicker(dnscrypt.KeyLifetime)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := dc.Rotate(); err != nil {
					s.Logger.Error("rotation de la clé DNSCrypt", "err", err)
				}
			}
		}
	}()
	return d, nil
}

// Addr renvoie l'adresse d'écoute.
func (d *DNSCrypt) Addr() net.Addr { return d.pc.LocalAddr() }

// Close arrête les écoutes.
func (d *DNSCrypt) Close() error {
	d.cancel()
	err := errors.Join(d.pc.Close(), d.ln.Close())
	d.wg.Wait()
	return err
}

func addrOf(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	}
	return netip.Addr{}
}

// handle traite un paquet ; maxLen : taille de la requête UDP (0 en TCP).
func (d *DNSCrypt) handle(ctx context.Context, pkt []byte, ip netip.Addr, maxLen int) []byte {
	msg, sess, err := d.dc.Decrypt(pkt)
	if errors.Is(err, dnscrypt.ErrNotDNSCrypt) {
		return d.certQuery(pkt)
	}
	if err != nil {
		return nil // paquet altéré ou clé expirée : silence
	}
	req := new(dns.Msg)
	if err := req.Unpack(msg); err != nil {
		return nil
	}
	resp := d.srv.Handle(ctx, req, ip, "dnscrypt")
	if resp == nil {
		return nil
	}
	wire, err := resp.Pack()
	if err != nil {
		return nil
	}
	out, err := sess.Encrypt(wire, maxLen)
	if err != nil {
		// Réponse plus grande que la requête : réponse tronquée, le client
		// recommence en TCP.
		tc := new(dns.Msg)
		tc.SetReply(req)
		tc.Truncated = true
		if wire, err = tc.Pack(); err == nil {
			out, _ = sess.Encrypt(wire, 0)
			if len(out) > maxLen {
				return nil
			}
		}
	}
	return out
}

// certQuery répond en clair à la seule demande de certificat (TXT du nom de
// fournisseur) ; toute autre requête en clair est ignorée.
func (d *DNSCrypt) certQuery(pkt []byte) []byte {
	req := new(dns.Msg)
	if err := req.Unpack(pkt); err != nil || len(req.Question) != 1 || req.Response {
		return nil
	}
	q := req.Question[0]
	if q.Qtype != dns.TypeTXT || !strings.EqualFold(q.Name, d.dc.ProviderName) {
		return nil
	}
	r := new(dns.Msg)
	r.SetReply(req)
	r.Authoritative = true
	for _, c := range d.dc.Certificates() {
		r.Answer = append(r.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: d.dc.ProviderName, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 600},
			Txt: []string{escapeTXT(c)}})
	}
	out, err := r.Pack()
	if err != nil {
		return nil
	}
	return out
}

// escapeTXT écrit des octets quelconques en texte de présentation (\DDD).
func escapeTXT(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x21 && c <= 0x7e && c != '"' && c != '\\' && c != ';' && c != '(' && c != ')' {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "\\%03d", c)
		}
	}
	return sb.String()
}

func (d *DNSCrypt) serveUDP(ctx context.Context) {
	defer d.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, from, err := d.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		go func() {
			if out := d.handle(ctx, pkt, addrOf(from), len(pkt)); out != nil {
				_, _ = d.pc.WriteTo(out, from)
			}
		}()
	}
}

func (d *DNSCrypt) serveTCP(ctx context.Context) {
	defer d.wg.Done()
	for {
		c, err := d.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			ip := addrOf(c.RemoteAddr())
			for {
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				pkt := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, pkt); err != nil {
					return
				}
				out := d.handle(ctx, pkt, ip, 0)
				if out == nil {
					return
				}
				msg := binary.BigEndian.AppendUint16(nil, uint16(len(out)))
				if _, err := c.Write(append(msg, out...)); err != nil {
					return
				}
			}
		}()
	}
}
