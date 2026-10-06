// Package dhcp est un serveur DHCPv4 minimal (RFC 2131, options RFC 2132)
// pour les réseaux où la box ne permet pas de changer le DNS annoncé. Il
// annonce Rempart comme serveur DNS et nomme les appareils dans un domaine
// local servi par Rempart.
package dhcp

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

// Types de message (option 53).
const (
	Discover = 1
	Offer    = 2
	Request  = 3
	Decline  = 4
	Ack      = 5
	Nak      = 6
	Release  = 7
	Inform   = 8
)

// Options utilisées (RFC 2132).
const (
	optPad        = 0
	optSubnetMask = 1
	optRouter     = 3
	optDNS        = 6
	optHostname   = 12
	optDomainName = 15
	optRequested  = 50
	optLeaseTime  = 51
	optMsgType    = 53
	optServerID   = 54
	optRenewal    = 58
	optRebinding  = 59
	optEnd        = 255
)

var magicCookie = [4]byte{99, 130, 83, 99}

const (
	headerLen = 236
	minLen    = headerLen + 4 // en-tête BOOTP + cookie magique
	maxLen    = 1500
	flagBcast = 0x8000
)

// Packet : message DHCP décodé. Seuls les champs utiles sont conservés.
type Packet struct {
	Op      byte
	XID     uint32
	Flags   uint16
	CIAddr  netip.Addr
	YIAddr  netip.Addr
	GIAddr  netip.Addr
	CHAddr  net.HardwareAddr
	Options map[byte][]byte
}

var errMalformed = errors.New("message DHCP mal formé")

func addr4(b []byte) netip.Addr { return netip.AddrFrom4([4]byte(b[:4])) }

// Parse décode une requête client. Toute longueur est vérifiée : le message
// vient de n'importe quel appareil du réseau.
func Parse(b []byte) (*Packet, error) {
	if len(b) < minLen || len(b) > maxLen {
		return nil, errMalformed
	}
	if b[0] != 1 || b[1] != 1 || b[2] != 6 { // BOOTREQUEST, Ethernet, MAC de 6 octets
		return nil, errMalformed
	}
	if [4]byte(b[headerLen:minLen]) != magicCookie {
		return nil, errMalformed
	}
	p := &Packet{Op: b[0], XID: binary.BigEndian.Uint32(b[4:8]), Flags: binary.BigEndian.Uint16(b[10:12]),
		CIAddr: addr4(b[12:16]), YIAddr: addr4(b[16:20]), GIAddr: addr4(b[24:28]),
		CHAddr: net.HardwareAddr(append([]byte{}, b[28:34]...)), Options: map[byte][]byte{}}
	opts := b[minLen:]
	for i := 0; i < len(opts); {
		code := opts[i]
		if code == optEnd {
			break
		}
		if code == optPad {
			i++
			continue
		}
		if i+1 >= len(opts) {
			return nil, errMalformed
		}
		n := int(opts[i+1])
		if i+2+n > len(opts) {
			return nil, errMalformed
		}
		// RFC 3396 (options concaténées) : une option répétée est prolongée.
		p.Options[code] = append(p.Options[code], opts[i+2:i+2+n]...)
		i += 2 + n
	}
	if t := p.Options[optMsgType]; len(t) != 1 || t[0] < Discover || t[0] > Inform {
		return nil, errMalformed
	}
	return p, nil
}

// Type renvoie le type de message (option 53).
func (p *Packet) Type() byte { return p.Options[optMsgType][0] }

// OptAddr lit une option contenant une adresse IPv4.
func (p *Packet) OptAddr(code byte) (netip.Addr, bool) {
	v := p.Options[code]
	if len(v) != 4 {
		return netip.Addr{}, false
	}
	return addr4(v), true
}

// option : une option à émettre, dans l'ordre d'ajout.
type option struct {
	code byte
	val  []byte
}

// reply construit la réponse BOOTREPLY à req.
func reply(req *Packet, typ byte, yiaddr, server netip.Addr, opts []option) []byte {
	b := make([]byte, minLen, 576)
	b[0], b[1], b[2] = 2, 1, 6
	binary.BigEndian.PutUint32(b[4:8], req.XID)
	binary.BigEndian.PutUint16(b[10:12], req.Flags)
	if typ != Nak {
		copy(b[12:16], req.CIAddr.AsSlice())
		if yiaddr.IsValid() {
			copy(b[16:20], yiaddr.AsSlice())
		}
		copy(b[20:24], server.AsSlice()) // siaddr
	}
	copy(b[24:28], req.GIAddr.AsSlice())
	copy(b[28:34], req.CHAddr)
	copy(b[headerLen:], magicCookie[:])
	b = append(b, optMsgType, 1, typ, optServerID, 4)
	b = append(b, server.AsSlice()...)
	for _, o := range opts {
		for v := o.val; ; {
			n := min(len(v), 255)
			b = append(b, o.code, byte(n))
			b = append(b, v[:n]...)
			if v = v[n:]; len(v) == 0 {
				break
			}
		}
	}
	b = append(b, optEnd)
	for len(b) < 300 { // taille minimale BOOTP attendue par certains clients
		b = append(b, optPad)
	}
	return b
}

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
