// blockpage.go - mode de blocage « page » : les noms bloqués pointent vers Rempart, qui affiche une page d'explication.
// Entrées : adresses IPv4/IPv6 de Rempart choisies dans l'interface ; noms bloqués servis récemment.
// Contexte : Rempart ; la page est servie sur l'écoute DoH déjà ouverte (443), aucun port supplémentaire.
package server

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/policy"
)

const (
	// pageNamesMax borne la mémoire des noms bloqués servis en mode page.
	pageNamesMax = 4096
	// pageNamesTTL : un navigateur qui a reçu l'adresse de Rempart peut s'y
	// connecter bien après la réponse DNS (cache du système, onglet rouvert).
	pageNamesTTL = 15 * time.Minute
)

// blockPage : adresses annoncées pour les noms bloqués, et noms récemment
// bloqués, seuls admis à recevoir la page (jamais l'interface).
type blockPage struct {
	mu    sync.Mutex
	v4    netip.Addr
	v6    netip.Addr
	names map[string]time.Time
}

// SetBlockPage déclare les adresses de Rempart vues des clients. Sans IPv4
// valide, le mode « page » répond comme le mode « adresse nulle ».
func (s *Server) SetBlockPage(v4, v6 netip.Addr) {
	s.page.mu.Lock()
	defer s.page.mu.Unlock()
	if !v4.Is4() {
		v4 = netip.Addr{}
	}
	if !v6.Is6() || v6.Is4In6() {
		v6 = netip.Addr{}
	}
	s.page.v4, s.page.v6 = v4, v6
}

// pageAnswer rend la réponse du mode « page » ; ok faux si aucune adresse
// n'est configurée (le mode « adresse nulle » s'applique alors).
func (s *Server) pageAnswer(req *dns.Msg) (*dns.Msg, bool) {
	q := req.Question[0]
	s.page.mu.Lock()
	v4, v6 := s.page.v4, s.page.v6
	if !v4.IsValid() {
		s.page.mu.Unlock()
		return nil, false
	}
	s.rememberLocked(q.Name)
	s.page.mu.Unlock()

	r := reply(req, dns.RcodeSuccess)
	hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: blockedTTL}
	switch {
	case q.Qtype == dns.TypeA:
		hdr.Rrtype = dns.TypeA
		r.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IP(v4.AsSlice())}}
	case q.Qtype == dns.TypeAAAA && v6.IsValid():
		hdr.Rrtype = dns.TypeAAAA
		r.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.IP(v6.AsSlice())}}
	default:
		// AAAA sans IPv6, HTTPS/SVCB (qui porteraient ECH ou d'autres
		// adresses), MX… : réponse vide, le navigateur se rabat sur A.
		r.Ns = []dns.RR{blockedSOA(q.Name)}
	}
	return r, true
}

func (s *Server) rememberLocked(name string) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	now := time.Now()
	if s.page.names == nil {
		s.page.names = map[string]time.Time{}
	}
	if _, ok := s.page.names[name]; !ok && len(s.page.names) >= pageNamesMax {
		for k, t := range s.page.names {
			if now.Sub(t) > pageNamesTTL {
				delete(s.page.names, k)
			}
		}
		if len(s.page.names) >= pageNamesMax {
			for k := range s.page.names { // au pire, un nom quelconque
				delete(s.page.names, k)
				break
			}
		}
	}
	s.page.names[name] = now
}

// BlockedRecently dit si host a été bloqué en mode « page » il y a peu :
// seul un tel nom reçoit la page de blocage sur l'écoute HTTPS.
func (s *Server) BlockedRecently(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return false
	}
	s.page.mu.Lock()
	defer s.page.mu.Unlock()
	t, ok := s.page.names[host]
	if ok && time.Since(t) > pageNamesTTL {
		delete(s.page.names, host)
		return false
	}
	return ok
}

// ForgetBlocked retire un nom (et ses sous-domaines) de la page de blocage,
// une fois débloqué.
func (s *Server) ForgetBlocked(domain string) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	s.page.mu.Lock()
	defer s.page.mu.Unlock()
	for k := range s.page.names {
		if k == domain || strings.HasSuffix(k, "."+domain) {
			delete(s.page.names, k)
		}
	}
}

// Allowed dit si ip appartient aux réseaux autorisés (dns.allowed_clients).
func (s *Server) Allowed(ip netip.Addr) bool { return s.allowed(ip) }

// GroupOf rend le groupe d'appareils d'un client du réseau local, ou nil.
func (s *Server) GroupOf(ip netip.Addr) *policy.Group {
	pol := s.Policy()
	if pol == nil {
		return nil
	}
	mac := ""
	if s.Neighbors != nil && pol.UsesMAC() {
		mac = s.Neighbors.MAC(ip)
	}
	return pol.Identify(ip.Unmap(), "", mac)
}

func blockedSOA(name string) *dns.SOA {
	return &dns.SOA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: blockedTTL},
		Ns: "rempart.blocked.", Mbox: "rempart.blocked.", Serial: 1, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: blockedTTL}
}
