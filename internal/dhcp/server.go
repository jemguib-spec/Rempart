package dhcp

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/sealed"
)

const (
	offerHold   = time.Minute    // adresse réservée entre OFFER et REQUEST
	declineHold = time.Hour      // adresse signalée en conflit (DECLINE)
	keepExpired = 24 * time.Hour // un bail expiré reste préféré pour son appareil
	hostTTL     = 60             // TTL des noms d'appareils
	maxRate     = 100            // messages traités par seconde, au plus
)

// Lease : bail attribué. Les baux contiennent des adresses MAC et des noms
// d'appareils : ils sont scellés sur disque comme le reste de l'état.
type Lease struct {
	MAC      string     `json:"mac"`
	IP       netip.Addr `json:"ip"`
	Hostname string     `json:"hostname,omitempty"`
	Expires  time.Time  `json:"expires"`
	Static   bool       `json:"static,omitempty"`
}

type hold struct {
	mac   string
	until time.Time
}

// Server : serveur DHCP et table des baux. Sans configuration active, il
// ne répond à rien mais continue de servir les noms des baux statiques.
type Server struct {
	ks   keystore.Keystore
	path string
	log  *slog.Logger
	cfg  atomic.Pointer[Config]

	mu       sync.RWMutex
	leases   map[string]*Lease // par MAC
	byIP     map[netip.Addr]*Lease
	offers   map[netip.Addr]hold
	declined map[netip.Addr]time.Time

	connMu sync.Mutex
	conn   net.PacketConn
	status atomic.Value // string : erreur d'écoute, ou ""

	rateSec atomic.Int64
	rateN   atomic.Int64

	saveMu sync.Mutex  // une seule écriture du fichier à la fois
	dirty  atomic.Bool // écriture différée programmée

	arp arpCache
}

// New ouvre la table des baux (fichier scellé dans le dossier de données).
func New(ks keystore.Keystore, path string, log *slog.Logger) (*Server, error) {
	s := &Server{ks: ks, path: path, log: log, leases: map[string]*Lease{}, byIP: map[netip.Addr]*Lease{}, offers: map[netip.Addr]hold{}, declined: map[netip.Addr]time.Time{}}
	s.status.Store("")
	raw, err := sealed.ReadFile(ks, path)
	var ls []Lease
	if err == nil {
		err = json.Unmarshal(raw, &ls)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		// Des baux perdus ne justifient pas d'arrêter le DNS : le fichier est
		// mis de côté pour examen et la table repart vide.
		aside := path + ".illisible-" + time.Now().UTC().Format("20060102-150405")
		_ = os.Rename(path, aside)
		log.Error("baux DHCP illisibles, table remise à zéro", "err", err, "fichier", aside)
		ls = nil
	}
	if len(ls) > 0 {
		for i := range ls {
			if time.Since(ls[i].Expires) < keepExpired {
				s.leases[ls[i].MAC] = &ls[i]
			}
		}
		s.reindex()
	}
	return s, nil
}

// reindex reconstruit l'index par adresse (verrou tenu en écriture). Si deux
// baux portent la même adresse, le plus récent l'emporte.
func (s *Server) reindex() {
	clear(s.byIP)
	for _, l := range s.leases {
		if o := s.byIP[l.IP]; o == nil || l.Expires.After(o.Expires) {
			s.byIP[l.IP] = l
		}
	}
}

// Fail signale une configuration refusée (le serveur est arrêté).
func (s *Server) Fail(msg string) {
	s.Apply(nil)
	s.status.Store(msg)
}

// Status renvoie la dernière erreur d'écoute ("" si tout va bien).
func (s *Server) Status() string { return s.status.Load().(string) }

// Running : le serveur écoute.
func (s *Server) Running() bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.conn != nil
}

// Apply met en service une configuration (nil = arrêt). L'écoute n'est
// rouverte que si l'interface change.
func (s *Server) Apply(cfg *Config) {
	old := s.cfg.Swap(cfg)
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if cfg == nil || (old != nil && old.Iface != cfg.Iface) {
		if s.conn != nil {
			_ = s.conn.Close()
			s.conn = nil
		}
	}
	if cfg == nil {
		s.status.Store("")
		return
	}
	if s.conn != nil {
		return
	}
	conn, err := listen(cfg.Iface)
	if err != nil {
		s.status.Store("écoute DHCP sur " + cfg.Iface + " impossible : " + err.Error())
		s.log.Error("serveur DHCP", "interface", cfg.Iface, "err", err)
		return
	}
	s.status.Store("")
	s.conn = conn
	s.log.Info("serveur DHCP en écoute", "interface", cfg.Iface, "plage", cfg.Start.String()+"–"+cfg.End.String())
	go s.serve(conn)
}

func (s *Server) serve(conn net.PacketConn) {
	buf := make([]byte, maxLen+1)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.log.Error("serveur DHCP arrêté", "err", err)
				s.status.Store("serveur DHCP arrêté : " + err.Error())
			}
			return
		}
		if !s.allow() {
			continue
		}
		p, err := Parse(buf[:n])
		if err != nil {
			continue
		}
		out, dst := s.Handle(p, time.Now())
		if out != nil {
			if _, err := conn.WriteTo(out, dst); err != nil {
				s.log.Debug("réponse DHCP non envoyée", "err", err)
			}
		}
	}
}

// allow limite le débit traité : une rafale de faux DISCOVER (adresses MAC
// aléatoires) ne doit ni saturer le processeur ni réécrire le disque sans fin.
func (s *Server) allow() bool {
	now := time.Now().Unix()
	if s.rateSec.Swap(now) != now {
		s.rateN.Store(0)
	}
	return s.rateN.Add(1) <= maxRate
}

var bcast = &net.UDPAddr{IP: net.IPv4bcast, Port: 68}

// Handle traite un message et renvoie la réponse et sa destination.
func (s *Server) Handle(p *Packet, now time.Time) ([]byte, *net.UDPAddr) {
	cfg := s.cfg.Load()
	if cfg == nil {
		return nil, nil
	}
	// Les relais DHCP ne sont pas pris en charge : sans cela, giaddr ferait
	// envoyer des réponses vers une adresse choisie par l'émetteur.
	if p.GIAddr.IsValid() && !p.GIAddr.IsUnspecified() {
		return nil, nil
	}
	mac := p.CHAddr.String()
	host := sanitizeHost(string(p.Options[optHostname]))
	dest := func(nak bool) *net.UDPAddr {
		switch {
		case nak:
			return bcast
		case !p.CIAddr.IsUnspecified():
			return &net.UDPAddr{IP: p.CIAddr.AsSlice(), Port: 68}
		}
		return bcast
	}
	nak := func() ([]byte, *net.UDPAddr) { return reply(p, Nak, netip.Addr{}, cfg.Server, nil), dest(true) }

	switch p.Type() {
	case Discover:
		ip, ok := s.allocate(cfg, mac, p, now)
		if !ok {
			s.log.Warn("DHCP : plus aucune adresse libre dans la plage")
			return nil, nil
		}
		return reply(p, Offer, ip, cfg.Server, s.options(cfg, true)), dest(false)

	case Request:
		var ip netip.Addr
		sid, hasSID := p.OptAddr(optServerID)
		req, hasReq := p.OptAddr(optRequested)
		switch {
		case hasSID: // SELECTING : réponse à une offre
			if sid != cfg.Server {
				s.forgetOffer(mac) // le client a choisi un autre serveur
				return nil, nil
			}
			if !hasReq {
				return nil, nil
			}
			ip = req
		case hasReq: // INIT-REBOOT
			ip = req
		default: // RENEWING / REBINDING
			ip = p.CIAddr
		}
		if !s.grantable(cfg, mac, ip, now) {
			return nak()
		}
		s.commit(cfg, mac, ip, host, now)
		return reply(p, Ack, ip, cfg.Server, s.options(cfg, true)), dest(false)

	case Decline:
		// Seul l'appareil à qui l'adresse a été offerte ou louée peut la
		// déclarer en conflit : sinon un tiers ferait refuser le bail d'autrui.
		ip, ok := p.OptAddr(optRequested)
		if !ok {
			return nil, nil
		}
		s.mu.Lock()
		h, offered := s.offers[ip]
		l := s.leases[mac]
		owner := (offered && h.mac == mac) || (l != nil && l.IP == ip)
		if owner {
			s.declined[ip] = now.Add(declineHold)
			delete(s.offers, ip)
			if l != nil && l.IP == ip {
				delete(s.leases, mac)
				s.reindex()
			}
		}
		s.mu.Unlock()
		if owner {
			s.log.Warn("DHCP : adresse déjà utilisée sur le réseau", "ip", ip)
			s.markDirty()
		}
		return nil, nil

	case Release:
		s.mu.Lock()
		changed := false
		if l := s.leases[mac]; l != nil && l.IP == p.CIAddr && !l.Static && now.Before(l.Expires) {
			l.Expires, changed = now, true
		}
		s.mu.Unlock()
		if changed {
			s.markDirty()
		}
		return nil, nil

	case Inform: // RFC 2131 §3.4 : options seulement, sans bail
		if !cfg.Subnet.Contains(p.CIAddr) {
			return nil, nil
		}
		return reply(p, Ack, netip.Addr{}, cfg.Server, s.options(cfg, false)), &net.UDPAddr{IP: p.CIAddr.AsSlice(), Port: 68}
	}
	return nil, nil
}

func (s *Server) options(cfg *Config, lease bool) []option {
	var o []option
	if lease {
		secs := uint32(cfg.Lease / time.Second)
		o = append(o, option{optLeaseTime, u32(secs)}, option{optRenewal, u32(secs / 2)}, option{optRebinding, u32(secs / 8 * 7)})
	}
	mask := net.CIDRMask(cfg.Subnet.Bits(), 32)
	o = append(o, option{optSubnetMask, []byte(mask)})
	if cfg.Router.IsValid() {
		o = append(o, option{optRouter, cfg.Router.AsSlice()})
	}
	dnsServers := cfg.Server.AsSlice()
	if cfg.ExtraDNS.IsValid() {
		dnsServers = append(dnsServers, cfg.ExtraDNS.AsSlice()...) // réplique : les clients basculent si l'une tombe
	}
	o = append(o, option{optDNS, dnsServers})
	if cfg.Domain != "" {
		o = append(o, option{optDomainName, []byte(cfg.Domain)})
	}
	return o
}

// usable : ip peut-elle être donnée à mac ? (appelé verrou tenu)
func (s *Server) usable(cfg *Config, mac string, ip netip.Addr, now time.Time) bool {
	if !cfg.Subnet.Contains(ip) || ip == cfg.Server || ip == cfg.Router || ip == cfg.Subnet.Addr() || ip == lastAddr(cfg.Subnet) {
		return false
	}
	if owner, ok := cfg.staticIP[ip]; ok {
		return owner == mac
	}
	if st, ok := cfg.static[mac]; ok {
		return st.IP == ip // un appareil réservé ne reçoit que son adresse
	}
	if ip.Less(cfg.Start) || cfg.End.Less(ip) {
		return false
	}
	if until, ok := s.declined[ip]; ok && now.Before(until) {
		return false
	}
	if h, ok := s.offers[ip]; ok && h.mac != mac && now.Before(h.until) {
		return false
	}
	if l := s.byIP[ip]; l != nil && l.MAC != mac && now.Before(l.Expires) {
		return false
	}
	return true
}

func (s *Server) allocate(cfg *Config, mac string, p *Packet, now time.Time) (netip.Addr, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pick := func(ip netip.Addr) (netip.Addr, bool) {
		s.offers[ip] = hold{mac, now.Add(offerHold)}
		return ip, true
	}
	if st, ok := cfg.static[mac]; ok {
		return pick(st.IP)
	}
	if l := s.leases[mac]; l != nil && s.usable(cfg, mac, l.IP, now) {
		return pick(l.IP)
	}
	if req, ok := p.OptAddr(optRequested); ok && s.usable(cfg, mac, req, now) {
		return pick(req)
	}
	// Adresse jamais attribuée d'abord, puis la plus anciennement expirée.
	var expired netip.Addr
	var oldest time.Time
	for ip := cfg.Start; !cfg.End.Less(ip); ip = ip.Next() {
		if !s.usable(cfg, mac, ip, now) {
			continue
		}
		l := s.byIP[ip]
		if l == nil {
			return pick(ip)
		}
		if !expired.IsValid() || l.Expires.Before(oldest) {
			expired, oldest = ip, l.Expires
		}
	}
	if expired.IsValid() {
		return pick(expired)
	}
	return netip.Addr{}, false
}

func (s *Server) grantable(cfg *Config, mac string, ip netip.Addr, now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return ip.Is4() && s.usable(cfg, mac, ip, now)
}

func (s *Server) forgetOffer(mac string) {
	s.mu.Lock()
	for ip, h := range s.offers {
		if h.mac == mac {
			delete(s.offers, ip)
		}
	}
	s.mu.Unlock()
}

// reservedHost : noms qu'un appareil ne peut pas prendre (détournement de
// la découverte automatique de proxy, comme dnsmasq le fait par défaut).
var reservedHost = map[string]bool{"wpad": true, "isatap": true, "localhost": true}

func (s *Server) commit(cfg *Config, mac string, ip netip.Addr, host string, now time.Time) {
	s.mu.Lock()
	delete(s.offers, ip)
	if reservedHost[host] {
		host = ""
	}
	l := &Lease{MAC: mac, IP: ip, Hostname: host, Expires: now.Add(cfg.Lease)}
	if st, ok := cfg.static[mac]; ok {
		l.Static = true
		if st.Host != "" {
			l.Hostname = st.Host
		}
	}
	old := s.leases[mac]
	if old != nil && host == "" && !l.Static {
		l.Hostname = old.Hostname // un renouvellement sans nom garde le nom connu
	}
	if !l.Static && l.Hostname != "" && s.nameTaken(cfg, l.Hostname, mac, now) {
		l.Hostname = "" // le premier détenteur d'un nom le garde
	}
	changed := old == nil || old.IP != l.IP || old.Hostname != l.Hostname || old.Static != l.Static ||
		l.Expires.Sub(old.Expires) > cfg.Lease/4 // un renouvellement rapproché n'est pas réécrit sur disque
	s.leases[mac] = l
	s.prune(cfg, now)
	s.reindex()
	s.mu.Unlock()
	if changed {
		s.markDirty()
	}
}

// nameTaken : nom réservé par un bail statique ou porté par un autre bail actif.
func (s *Server) nameTaken(cfg *Config, name, mac string, now time.Time) bool {
	for m, st := range cfg.static {
		if st.Host == name && m != mac {
			return true
		}
	}
	for m, l := range s.leases {
		if m != mac && l.Hostname == name && now.Before(l.Expires) {
			return true
		}
	}
	return false
}

// prune borne la table : les baux expirés depuis plus de keepExpired sont
// retirés, puis les plus anciens expirés au-delà de deux fois la taille de la
// plage (une suite de REQUEST/RELEASE à MAC aléatoires ne la fait pas grossir
// sans fin). Verrou tenu.
func (s *Server) prune(cfg *Config, now time.Time) {
	limit := 2*rangeSize(cfg) + len(cfg.static)
	var expired []*Lease
	for m, l := range s.leases {
		switch {
		case now.Sub(l.Expires) > keepExpired:
			delete(s.leases, m)
		case !now.Before(l.Expires):
			expired = append(expired, l)
		}
	}
	if extra := len(s.leases) - limit; extra > 0 {
		slices.SortFunc(expired, func(a, b *Lease) int { return a.Expires.Compare(b.Expires) })
		for _, l := range expired[:min(extra, len(expired))] {
			delete(s.leases, l.MAC)
		}
	}
	for ip, until := range s.declined {
		if now.After(until) {
			delete(s.declined, ip)
		}
	}
	for ip, h := range s.offers {
		if now.After(h.until) {
			delete(s.offers, ip)
		}
	}
}

func rangeSize(cfg *Config) int {
	a, b := cfg.Start.As4(), cfg.End.As4()
	v := func(x [4]byte) int { return int(x[0])<<24 | int(x[1])<<16 | int(x[2])<<8 | int(x[3]) }
	return v(b) - v(a) + 1
}

// markDirty programme une écriture dans deux secondes : une rafale de
// messages ne donne qu'une écriture (et un seul appel au keystore ou au HSM).
func (s *Server) markDirty() {
	if s.dirty.CompareAndSwap(false, true) {
		time.AfterFunc(2*time.Second, func() { _ = s.Flush() })
	}
}

// Flush écrit les baux maintenant (arrêt, rotation de la KEK).
func (s *Server) Flush() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.dirty.Store(false)
	s.mu.RLock()
	ls := make([]Lease, 0, len(s.leases))
	for _, l := range s.leases {
		ls = append(ls, *l)
	}
	s.mu.RUnlock()
	slices.SortFunc(ls, func(a, b Lease) int { return a.IP.Compare(b.IP) })
	raw, _ := json.Marshal(ls)
	if err := sealed.WriteFile(s.ks, s.path, raw); err != nil {
		s.log.Error("baux DHCP non enregistrés", "err", err)
		return err
	}
	return nil
}

// Leases renvoie les baux (actifs et récemment expirés), plus les baux
// statiques jamais demandés.
func (s *Server) Leases() []Lease {
	s.mu.RLock()
	out := make([]Lease, 0, len(s.leases))
	have := map[string]bool{}
	for _, l := range s.leases {
		out = append(out, *l)
		have[l.MAC] = true
	}
	s.mu.RUnlock()
	if cfg := s.cfg.Load(); cfg != nil {
		for mac, st := range cfg.static {
			if !have[mac] {
				out = append(out, Lease{MAC: mac, IP: st.IP, Hostname: st.Host, Static: true})
			}
		}
	}
	slices.SortFunc(out, func(a, b Lease) int { return a.IP.Compare(b.IP) })
	return out
}

// Forget supprime un bail dynamique (appareil retiré du réseau).
func (s *Server) Forget(mac string) bool {
	s.mu.Lock()
	_, ok := s.leases[mac]
	delete(s.leases, mac)
	s.reindex()
	s.mu.Unlock()
	if ok {
		s.markDirty()
	}
	return ok
}

// ---- résolution des noms d'appareils ----

func (s *Server) hostIP(cfg *Config, name string, now time.Time) (netip.Addr, bool) {
	for _, st := range cfg.static {
		if st.Host == name {
			return st.IP, true
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best *Lease
	for _, l := range s.leases {
		if l.Hostname == name && now.Before(l.Expires) && (best == nil || l.Expires.After(best.Expires)) {
			best = l
		}
	}
	if best == nil {
		return netip.Addr{}, false
	}
	return best.IP, true
}

func (s *Server) ipHost(cfg *Config, ip netip.Addr, now time.Time) string {
	if mac, ok := cfg.staticIP[ip]; ok && cfg.static[mac].Host != "" {
		return cfg.static[mac].Host
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if l := s.byIP[ip]; l != nil && now.Before(l.Expires) {
		return l.Hostname
	}
	return ""
}

// Answer répond pour <appareil>.<domaine> et pour les PTR du réseau servi.
// ok=false : le nom ne relève pas du DHCP. rrs nil : le nom n'existe pas.
func (s *Server) Answer(q dns.Question) ([]dns.RR, bool) {
	cfg := s.cfg.Load()
	if cfg == nil {
		return nil, false
	}
	now := time.Now()
	name := strings.TrimSuffix(q.Name, ".")
	if cfg.Domain != "" && (name == cfg.Domain || strings.HasSuffix(name, "."+cfg.Domain)) {
		if name == cfg.Domain {
			return []dns.RR{}, true
		}
		label := strings.TrimSuffix(name, "."+cfg.Domain)
		if strings.Contains(label, ".") {
			return nil, true
		}
		ip, ok := s.hostIP(cfg, label, now)
		if !ok {
			return nil, true
		}
		if q.Qtype != dns.TypeA {
			return []dns.RR{}, true
		}
		return []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: hostTTL}, A: ip.AsSlice()}}, true
	}
	if q.Qtype == dns.TypePTR && strings.HasSuffix(name, ".in-addr.arpa") {
		ip, ok := reverse4(name)
		if !ok || !cfg.Subnet.Contains(ip) {
			return nil, false
		}
		h := s.ipHost(cfg, ip, now)
		if h == "" || cfg.Domain == "" {
			return nil, true // réseau privé servi ici : ne pas interroger l'extérieur
		}
		return []dns.RR{&dns.PTR{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: hostTTL}, Ptr: h + "." + cfg.Domain + "."}}, true
	}
	return nil, false
}

func reverse4(name string) (netip.Addr, bool) {
	parts := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	slices.Reverse(parts)
	a, err := netip.ParseAddr(strings.Join(parts, "."))
	return a, err == nil && a.Is4()
}

// Neighbors renvoie une copie de la table de voisinage du noyau (IP → MAC),
// relue au plus toutes les 30 secondes. Vide si le conteneur n'a pas le
// réseau de l'hôte.
func (s *Server) Neighbors() map[netip.Addr]string {
	s.arp.lookup(netip.Addr{}) // rafraîchit si besoin
	s.arp.mu.Lock()
	defer s.arp.mu.Unlock()
	out := make(map[netip.Addr]string, len(s.arp.byIP))
	for ip, mac := range s.arp.byIP {
		out[ip] = mac
	}
	return out
}

// MAC renvoie l'adresse MAC d'un client : bail DHCP, sinon table de voisinage.
func (s *Server) MAC(ip netip.Addr) string {
	s.mu.RLock()
	l := s.byIP[ip]
	s.mu.RUnlock()
	if l != nil && time.Now().Before(l.Expires) {
		return l.MAC
	}
	return s.arp.lookup(ip)
}
