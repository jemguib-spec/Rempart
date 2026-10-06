package zones

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/keystore"
	"github.com/rempart-dns/rempart/internal/state"
)

// RecordView décrit un enregistrement lu, pour l'assistant de l'interface.
type RecordView struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
}

// LineCheck est le verdict sur une ligne saisie (numérotée à partir de 1).
type LineCheck struct {
	Line    int          `json:"line"`
	Text    string       `json:"text"`
	Error   string       `json:"error,omitempty"`
	Records []RecordView `json:"records,omitempty"`
}

// CheckReport est le résultat d'une vérification à blanc : rien n'est
// enregistré ni signé.
type CheckReport struct {
	OK    bool        `json:"ok"`
	Error string      `json:"error,omitempty"`
	Lines []LineCheck `json:"lines"`
}

// Check vérifie des lignes de fichier de zone sans rien enregistrer : chaque
// ligne d'abord seule (pour situer l'erreur), puis la zone entière avec ses
// enregistrements dynamiques (règles qui portent sur plusieurs lignes, comme
// un CNAME seul sur son nom). La zone est construite sans signature : aucune
// clé n'est utilisée.
func Check(ks keystore.Keystore, sz state.Zone, lines []string) CheckReport {
	origin := strings.ToLower(dns.Fqdn(sz.Name))
	rep := CheckReport{OK: true, Lines: []LineCheck{}}
	var clean []string
	multi := false
	for i, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		clean = append(clean, l)
		if strings.ContainsAny(l, "()") || strings.HasPrefix(l, "$") {
			multi = true // une ligne seule n'a pas de sens : vérifiée avec la zone
		}
		lc := LineCheck{Line: i + 1, Text: l}
		if !multi {
			rrs, err := ParseRecords(origin, []string{l})
			if err != nil {
				lc.Error = Explain(err)
				rep.OK = false
			}
			for _, rr := range rrs {
				lc.Records = append(lc.Records, view(origin, rr))
			}
		}
		rep.Lines = append(rep.Lines, lc)
	}
	if !rep.OK {
		rep.Error = "certaines lignes sont incorrectes"
		return rep
	}
	test := sz
	test.Name, test.Records, test.DNSSEC = origin, clean, false
	if _, err := Build(ks, test); err != nil {
		rep.OK, rep.Error = false, Explain(err)
	}
	return rep
}

func view(origin string, rr dns.RR) RecordView {
	h := rr.Header()
	full := rr.String()
	// La valeur est ce qui suit « nom TTL classe type ».
	parts := strings.SplitN(full, "\t", 5)
	val := ""
	if len(parts) == 5 {
		val = parts[4]
	}
	return RecordView{Name: strings.TrimSuffix(h.Name, "."), Type: dns.TypeToString[h.Rrtype], TTL: h.Ttl, Value: val}
}

var (
	reBadRR   = regexp.MustCompile(`bad (A|AAAA|CNAME|MX|TXT|SRV|PTR|NS|CAA)\b`)
	reBadType = regexp.MustCompile(`(?i)(unknown RR type|expecting RR type|not a TTL)`)
	reAt      = regexp.MustCompile(`"([^"]*)" at line: \d+:\d+`)
)

// Explain traduit en français les erreurs les plus courantes du lecteur de
// fichiers de zone, en gardant le message d'origine entre parenthèses pour
// qui veut le chercher.
func Explain(err error) string {
	if err == nil {
		return ""
	}
	var pe *dns.ParseError
	msg := err.Error()
	if !errors.As(err, &pe) {
		return msg
	}
	tok := ""
	if m := reAt.FindStringSubmatch(msg); m != nil {
		tok = m[1]
	}
	hint := ""
	switch m := reBadRR.FindStringSubmatch(msg); {
	case m != nil:
		hint = map[string]string{
			"A":     "adresse IPv4 invalide (attendu : 4 nombres de 0 à 255, par exemple 192.168.1.10)",
			"AAAA":  "adresse IPv6 invalide (par exemple fd00::10)",
			"CNAME": "cible d'alias invalide (un nom, par exemple nas ou www.exemple.fr.)",
			"MX":    "messagerie invalide (attendu : priorité puis serveur, par exemple 10 mail)",
			"TXT":   "texte invalide (mettez-le entre guillemets)",
			"SRV":   "service invalide (attendu : priorité poids port cible, par exemple 0 0 25565 serveur)",
			"PTR":   "nom inverse invalide",
			"NS":    "serveur de noms invalide",
			"CAA":   "CAA invalide (par exemple 0 issue \"letsencrypt.org\")",
		}[m[1]]
	case reBadType.MatchString(msg):
		hint = "type d'enregistrement inconnu ou mal placé (attendu : nom, durée facultative, IN, type, valeur)"
	case strings.Contains(msg, "bad owner name"):
		hint = "nom invalide (lettres, chiffres et tirets, sans espace ni accent)"
	}
	if hint == "" {
		return msg
	}
	if tok != "" {
		return fmt.Sprintf("%s : « %s » (%s)", hint, tok, msg)
	}
	return fmt.Sprintf("%s (%s)", hint, msg)
}

// Lookup interroge la zone chargée comme le ferait un client, sans passer par
// le réseau, le cache ni le filtrage : pour vérifier qu'un nom répond.
func (m *Manager) Lookup(zone, name string, qtype uint16) (rcode string, answers []string, ok bool) {
	z := m.Get(zone)
	if z == nil {
		return "", nil, false
	}
	q := strings.ToLower(dns.Fqdn(name))
	if !dns.IsSubDomain(z.Origin, q) {
		return "", nil, false
	}
	req := new(dns.Msg)
	req.SetQuestion(q, qtype)
	resp := z.Answer(req, false)
	answers = []string{}
	for _, rr := range resp.Answer {
		answers = append(answers, rr.String())
	}
	return dns.RcodeToString[resp.Rcode], answers, true
}
