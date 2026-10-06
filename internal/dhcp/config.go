package dhcp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/rempart-dns/rempart/internal/state"
)

// Config : configuration validée et prête à servir.
type Config struct {
	Iface      string
	Server     netip.Addr
	Subnet     netip.Prefix
	Start, End netip.Addr
	Router     netip.Addr // facultatif
	ExtraDNS   netip.Addr // second serveur DNS annoncé (réplique), facultatif
	Lease      time.Duration
	Domain     string // sans point final, vide = pas de noms
	static     map[string]staticEntry
	staticIP   map[netip.Addr]string // IP → MAC
}

type staticEntry struct {
	IP   netip.Addr
	Host string
}

func parse4(field, s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !a.Is4() {
		return netip.Addr{}, fmt.Errorf("%s : adresse IPv4 attendue (%q)", field, s)
	}
	return a, nil
}

// Compile valide la configuration. zones : zones locales existantes (le
// domaine des appareils ne doit pas se confondre avec une zone signée).
func Compile(c state.DHCPConfig, zones []string) (*Config, error) {
	cfg := &Config{Iface: strings.TrimSpace(c.Interface), static: map[string]staticEntry{}, staticIP: map[netip.Addr]string{}}
	if cfg.Iface == "" {
		return nil, errors.New("interface réseau requise")
	}
	var err error
	if cfg.Server, err = parse4("adresse du serveur", c.ServerIP); err != nil {
		return nil, err
	}
	mask, err := parse4("masque", c.Netmask)
	if err != nil {
		return nil, err
	}
	ones, bits := net.IPMask(mask.AsSlice()).Size()
	if bits == 0 || ones < 8 || ones > 30 {
		return nil, errors.New("masque invalide (de /8 à /30)")
	}
	cfg.Subnet = netip.PrefixFrom(cfg.Server, ones).Masked()
	if cfg.Start, err = parse4("début de plage", c.RangeStart); err != nil {
		return nil, err
	}
	if cfg.End, err = parse4("fin de plage", c.RangeEnd); err != nil {
		return nil, err
	}
	if !cfg.Subnet.Contains(cfg.Start) || !cfg.Subnet.Contains(cfg.End) || cfg.End.Less(cfg.Start) {
		return nil, fmt.Errorf("plage invalide : elle doit être dans %s et commencer avant de finir", cfg.Subnet)
	}
	bcast := lastAddr(cfg.Subnet)
	if cfg.Start == cfg.Subnet.Addr() || cfg.End == bcast {
		return nil, errors.New("la plage ne peut pas contenir l'adresse du réseau ni celle de diffusion")
	}
	if c.Router != "" {
		if cfg.Router, err = parse4("passerelle", c.Router); err != nil {
			return nil, err
		}
		if !cfg.Subnet.Contains(cfg.Router) {
			return nil, fmt.Errorf("la passerelle doit être dans %s", cfg.Subnet)
		}
	}
	if c.ExtraDNS != "" {
		if cfg.ExtraDNS, err = parse4("second serveur DNS", c.ExtraDNS); err != nil {
			return nil, err
		}
	}
	if c.LeaseHours < 1 || c.LeaseHours > 24*30 {
		return nil, errors.New("durée de bail entre 1 h et 30 jours")
	}
	cfg.Lease = time.Duration(c.LeaseHours) * time.Hour
	cfg.Domain = strings.Trim(strings.ToLower(strings.TrimSpace(c.Domain)), ".")
	if cfg.Domain != "" {
		if !validDomain(cfg.Domain) {
			return nil, errors.New("domaine des appareils invalide")
		}
		// Un seul label détournerait tout un domaine de premier niveau
		// (« fr », « com ») : seuls les noms d'usage privé sont admis.
		if !strings.Contains(cfg.Domain, ".") && !privateTLD[cfg.Domain] {
			return nil, errors.New("domaine des appareils : utilisez home.arpa (RFC 8375), lan, home, internal ou un sous-domaine à vous")
		}
		for _, z := range zones {
			z = strings.TrimSuffix(z, ".")
			if cfg.Domain == z || strings.HasSuffix(cfg.Domain, "."+z) || strings.HasSuffix(z, "."+cfg.Domain) {
				return nil, fmt.Errorf("le domaine des appareils recouvre la zone locale %s : choisissez-en un autre", z)
			}
		}
	}
	for _, s := range c.Static {
		hw, err := net.ParseMAC(strings.TrimSpace(s.MAC))
		if err != nil || len(hw) != 6 {
			return nil, fmt.Errorf("bail statique : adresse MAC invalide %q", s.MAC)
		}
		ip, err := parse4("bail statique", s.IP)
		if err != nil {
			return nil, err
		}
		if !cfg.Subnet.Contains(ip) || ip == cfg.Server || ip == cfg.Router || ip == cfg.Subnet.Addr() || ip == bcast {
			return nil, fmt.Errorf("bail statique %s : adresse hors du réseau ou réservée", ip)
		}
		mac := hw.String()
		if _, dup := cfg.static[mac]; dup {
			return nil, fmt.Errorf("bail statique : %s apparaît deux fois", mac)
		}
		if _, dup := cfg.staticIP[ip]; dup {
			return nil, fmt.Errorf("bail statique : %s attribuée deux fois", ip)
		}
		host := ""
		if s.Hostname != "" {
			if host = sanitizeHost(s.Hostname); host == "" || host != strings.ToLower(strings.TrimSpace(s.Hostname)) {
				return nil, fmt.Errorf("bail statique : nom %q invalide (lettres, chiffres, tirets)", s.Hostname)
			}
		}
		cfg.static[mac] = staticEntry{ip, host}
		cfg.staticIP[ip] = mac
	}
	return cfg, nil
}

var privateTLD = map[string]bool{"lan": true, "home": true, "internal": true, "localdomain": true}

// PrivateTLD indique si un nom sans point est d'usage privé (lan, home…) :
// tout autre nom d'un seul label détournerait un domaine de premier niveau.
func PrivateTLD(s string) bool { return privateTLD[strings.Trim(strings.ToLower(s), ".")] }

// Overlaps indique si deux domaines se recouvrent (égaux, ou l'un sous l'autre).
func Overlaps(a, b string) bool {
	a, b = strings.Trim(strings.ToLower(a), "."), strings.Trim(strings.ToLower(b), ".")
	if a == "" || b == "" {
		return false
	}
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func validDomain(d string) bool {
	if len(d) > 200 {
		return false
	}
	for _, l := range strings.Split(d, ".") {
		if l == "" || sanitizeHost(l) != l {
			return false
		}
	}
	return true
}

// sanitizeHost réduit un nom fourni par un appareil à un label DNS sûr :
// minuscules, chiffres et tirets, 63 caractères au plus.
func sanitizeHost(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexByte(s, '.'); i >= 0 {
		s = s[:i]
	}
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < 63; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			b.WriteByte(c)
		case c == ' ' || c == '_':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
