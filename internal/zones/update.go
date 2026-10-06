package zones

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/state"
)

// Types qu'une mise à jour dynamique ne peut pas modifier : ceux que Rempart
// gère lui-même (SOA, DNSSEC).
var updateForbidden = map[uint16]bool{
	dns.TypeSOA: true, dns.TypeDNSKEY: true, dns.TypeRRSIG: true, dns.TypeNSEC: true, dns.TypeNSEC3: true,
	dns.TypeNSEC3PARAM: true, dns.TypeCDS: true, dns.TypeCDNSKEY: true,
}

// MaxDynamic : enregistrements dynamiques au plus par zone.
const MaxDynamic = 10_000

// UpdateError porte le code de réponse RFC 2136 d'une mise à jour refusée.
type UpdateError struct {
	Rcode int
	Msg   string
}

func (e *UpdateError) Error() string { return e.Msg }

func uerr(rcode int, f string, a ...any) *UpdateError {
	return &UpdateError{Rcode: rcode, Msg: fmt.Sprintf(f, a...)}
}

// ApplyUpdate vérifie les prérequis puis applique une mise à jour RFC 2136
// (déjà authentifiée) à la zone z construite depuis sz. Elle renvoie la
// nouvelle liste d'enregistrements dynamiques. Les noms portant des
// enregistrements de l'administrateur ne peuvent pas être modifiés.
func ApplyUpdate(z *Zone, sz state.Zone, m *dns.Msg) ([]string, error) {
	origin := z.Origin
	static, err := ParseRecords(origin, sz.Records)
	if err != nil {
		return nil, uerr(dns.RcodeServerFailure, "zone illisible")
	}
	staticNames := map[string]bool{origin: true}
	for _, rr := range static {
		staticNames[strings.ToLower(rr.Header().Name)] = true
	}
	dyn, err := ParseRecords(origin, sz.Dynamic)
	if err != nil {
		return nil, uerr(dns.RcodeServerFailure, "enregistrements dynamiques illisibles")
	}

	// §3.2 : prérequis, évalués sur la zone entière.
	temp := map[string][]dns.RR{}
	for _, rr := range m.Answer {
		h := rr.Header()
		name := strings.ToLower(h.Name)
		if h.Ttl != 0 {
			return nil, uerr(dns.RcodeFormatError, "prérequis avec un TTL non nul")
		}
		if !dns.IsSubDomain(origin, name) {
			return nil, uerr(dns.RcodeNotZone, "prérequis hors zone : %s", name)
		}
		switch h.Class {
		case dns.ClassANY:
			if h.Rdlength != 0 {
				return nil, uerr(dns.RcodeFormatError, "prérequis mal formé")
			}
			if h.Rrtype == dns.TypeANY {
				if !z.exists(name) {
					return nil, uerr(dns.RcodeNameError, "%s n'existe pas", name)
				}
			} else if len(z.nodes[name][h.Rrtype]) == 0 {
				return nil, uerr(dns.RcodeNXRrset, "%s %s n'existe pas", name, dns.TypeToString[h.Rrtype])
			}
		case dns.ClassNONE:
			if h.Rdlength != 0 {
				return nil, uerr(dns.RcodeFormatError, "prérequis mal formé")
			}
			if h.Rrtype == dns.TypeANY {
				if z.exists(name) {
					return nil, uerr(dns.RcodeYXDomain, "%s existe", name)
				}
			} else if len(z.nodes[name][h.Rrtype]) > 0 {
				return nil, uerr(dns.RcodeYXRrset, "%s %s existe", name, dns.TypeToString[h.Rrtype])
			}
		case dns.ClassINET:
			k := name + "/" + dns.TypeToString[h.Rrtype]
			temp[k] = append(temp[k], rr)
		default:
			return nil, uerr(dns.RcodeFormatError, "classe de prérequis inconnue")
		}
	}
	for k, want := range temp {
		name, t, _ := strings.Cut(k, "/")
		have := z.nodes[name][dns.StringToType[t]]
		if !sameSet(want, have) {
			return nil, uerr(dns.RcodeNXRrset, "%s %s ne correspond pas", name, t)
		}
	}

	// §3.4.1 : contrôle préalable de toute la section mise à jour.
	for _, rr := range m.Ns {
		h := rr.Header()
		name := strings.ToLower(h.Name)
		if !dns.IsSubDomain(origin, name) {
			return nil, uerr(dns.RcodeNotZone, "mise à jour hors zone : %s", name)
		}
		if staticNames[name] {
			return nil, uerr(dns.RcodeRefused, "%s est géré par l'administrateur", name)
		}
		if updateForbidden[h.Rrtype] || (h.Rrtype == dns.TypeNS && name == origin) {
			return nil, uerr(dns.RcodeRefused, "type %s non modifiable", dns.TypeToString[h.Rrtype])
		}
		switch h.Class {
		case dns.ClassINET:
			if h.Rrtype == dns.TypeANY || h.Rrtype == dns.TypeAXFR || h.Rrtype == dns.TypeIXFR {
				return nil, uerr(dns.RcodeFormatError, "type invalide pour un ajout")
			}
			// Un DNAME, ou une délégation (NS, DS) posée au-dessus d'un nom de
			// l'administrateur, le masquerait chez les secondaires.
			if h.Rrtype == dns.TypeDNAME {
				return nil, uerr(dns.RcodeRefused, "DNAME non modifiable par mise à jour dynamique")
			}
			if h.Rrtype == dns.TypeNS || h.Rrtype == dns.TypeDS {
				for sn := range staticNames {
					if sn != name && dns.IsSubDomain(name, sn) {
						return nil, uerr(dns.RcodeRefused, "%s %s masquerait %s, géré par l'administrateur", name, dns.TypeToString[h.Rrtype], sn)
					}
				}
			}
		case dns.ClassANY, dns.ClassNONE:
			if h.Ttl != 0 || (h.Class == dns.ClassANY && h.Rdlength != 0) {
				return nil, uerr(dns.RcodeFormatError, "suppression mal formée")
			}
		default:
			return nil, uerr(dns.RcodeFormatError, "classe inconnue")
		}
	}

	// §3.4.2 : application.
	for _, rr := range m.Ns {
		h := rr.Header()
		name := strings.ToLower(h.Name)
		switch h.Class {
		case dns.ClassINET:
			cp := dns.Copy(rr)
			cp.Header().Name = name
			hasCNAME, hasOther := false, false
			dup := false
			for _, ex := range dyn {
				if strings.ToLower(ex.Header().Name) != name {
					continue
				}
				if ex.Header().Rrtype == dns.TypeCNAME {
					hasCNAME = true
				} else {
					hasOther = true
				}
				if dns.IsDuplicate(ex, cp) {
					dup = true
				}
			}
			// RFC 2136 §3.4.2.2 : un CNAME ne côtoie pas d'autres données.
			if dup || (h.Rrtype == dns.TypeCNAME && hasOther) || (h.Rrtype != dns.TypeCNAME && hasCNAME) {
				continue
			}
			if h.Rrtype == dns.TypeCNAME {
				dyn = filterRR(dyn, func(x dns.RR) bool { return strings.ToLower(x.Header().Name) == name })
			}
			dyn = append(dyn, cp)
		case dns.ClassANY:
			dyn = filterRR(dyn, func(x dns.RR) bool {
				return strings.ToLower(x.Header().Name) == name && (h.Rrtype == dns.TypeANY || x.Header().Rrtype == h.Rrtype)
			})
		case dns.ClassNONE:
			target := dns.Copy(rr)
			target.Header().Class = dns.ClassINET
			target.Header().Name = name
			dyn = filterRR(dyn, func(x dns.RR) bool { return dns.IsDuplicate(x, target) })
		}
	}
	// Borne : un client autorisé (ou sa clé dérobée) ne peut pas faire
	// grossir sans fin l'état et la zone signée.
	if len(dyn) > MaxDynamic {
		return nil, uerr(dns.RcodeRefused, "plus de %d enregistrements dynamiques dans la zone", MaxDynamic)
	}
	out := make([]string, 0, len(dyn))
	for _, rr := range dyn {
		out = append(out, rr.String())
	}
	return out, nil
}

func filterRR(rrs []dns.RR, drop func(dns.RR) bool) []dns.RR {
	out := rrs[:0]
	for _, rr := range rrs {
		if !drop(rr) {
			out = append(out, rr)
		}
	}
	return out
}

// sameSet compare deux RRsets en ignorant TTL et ordre.
func sameSet(a, b []dns.RR) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		found := false
		for _, y := range b {
			if dns.IsDuplicate(x, y) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
