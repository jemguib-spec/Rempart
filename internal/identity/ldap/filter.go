// filter.go - filtres de recherche LDAP (RFC 4515) : analyse de la forme
// texte et encodage BER (RFC 4511 §4.5.1). Les valeurs fournies par un
// utilisateur ne sont jamais concaténées telles quelles : EscapeFilter les
// échappe avant substitution, ce qui empêche toute injection de filtre.

package ldap

import (
	"errors"
	"fmt"
	"strings"
)

// EscapeFilter échappe une valeur pour l'insérer dans un filtre (RFC 4515 §3) :
// « * ( ) \ » et NUL, ainsi que tout octet hors ASCII imprimable.
func EscapeFilter(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '*' || c == '(' || c == ')' || c == '\\' {
			fmt.Fprintf(&b, "\\%02x", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// Expand remplace les marqueurs {nom} d'un modèle de filtre par les valeurs
// échappées. Un marqueur inconnu est une erreur (modèle mal saisi).
func Expand(tmpl string, vars map[string]string) (string, error) {
	var b strings.Builder
	for {
		i := strings.IndexByte(tmpl, '{')
		if i < 0 {
			b.WriteString(tmpl)
			break
		}
		j := strings.IndexByte(tmpl[i:], '}')
		if j < 0 {
			return "", errors.New("filtre : accolade non fermée")
		}
		name := tmpl[i+1 : i+j]
		v, ok := vars[name]
		if !ok {
			return "", fmt.Errorf("filtre : marqueur inconnu {%s}", name)
		}
		b.WriteString(tmpl[:i])
		b.WriteString(EscapeFilter(v))
		tmpl = tmpl[i+j+1:]
	}
	return b.String(), nil
}

// CompileFilter analyse un filtre texte et renvoie son encodage BER.
func CompileFilter(s string) ([]byte, error) {
	p := &fparser{s: s}
	out, err := p.filter(0)
	if err != nil {
		return nil, err
	}
	if p.i != len(p.s) {
		return nil, p.err("caractères après la fin du filtre")
	}
	return out, nil
}

type fparser struct {
	s string
	i int
}

func (p *fparser) err(msg string) error {
	return fmt.Errorf("filtre LDAP invalide (position %d) : %s", p.i, msg)
}

func (p *fparser) peek() byte {
	if p.i < len(p.s) {
		return p.s[p.i]
	}
	return 0
}

func (p *fparser) filter(depth int) ([]byte, error) {
	if depth > 16 {
		return nil, p.err("imbrication trop profonde")
	}
	if p.peek() != '(' {
		return nil, p.err("« ( » attendu")
	}
	p.i++
	var out []byte
	var err error
	switch p.peek() {
	case '&', '|':
		tag := byte(classContext | constructed | 0)
		if p.peek() == '|' {
			tag = classContext | constructed | 1
		}
		p.i++
		var parts [][]byte
		for p.peek() == '(' {
			f, err := p.filter(depth + 1)
			if err != nil {
				return nil, err
			}
			parts = append(parts, f)
		}
		if len(parts) == 0 {
			return nil, p.err("liste vide après & ou |")
		}
		out = seq(tag, parts...)
	case '!':
		p.i++
		f, err := p.filter(depth + 1)
		if err != nil {
			return nil, err
		}
		out = tlv(classContext|constructed|2, f)
	default:
		out, err = p.item()
		if err != nil {
			return nil, err
		}
	}
	if p.peek() != ')' {
		return nil, p.err("« ) » attendu")
	}
	p.i++
	return out, nil
}

func isAttrChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == ';'
}

func (p *fparser) attr() string {
	st := p.i
	for p.i < len(p.s) && isAttrChar(p.s[p.i]) {
		p.i++
	}
	return p.s[st:p.i]
}

// value lit une valeur jusqu'à « ) » ; « * » non échappé la découpe (pour les
// sous-chaînes). Renvoie les morceaux décodés.
func (p *fparser) value() ([]string, error) {
	var parts []string
	var cur []byte
	for {
		if p.i >= len(p.s) {
			return nil, p.err("valeur non terminée")
		}
		c := p.s[p.i]
		switch c {
		case ')':
			return append(parts, string(cur)), nil
		case '(':
			return nil, p.err("« ( » doit être échappé (\\28)")
		case '*':
			parts = append(parts, string(cur))
			cur = nil
			p.i++
		case '\\':
			if p.i+2 >= len(p.s) {
				return nil, p.err("échappement incomplet")
			}
			var v byte
			if _, err := fmt.Sscanf(p.s[p.i+1:p.i+3], "%02x", &v); err != nil || !isHex(p.s[p.i+1]) || !isHex(p.s[p.i+2]) {
				return nil, p.err("échappement invalide")
			}
			cur = append(cur, v)
			p.i += 3
		default:
			if c == 0 {
				return nil, p.err("octet nul")
			}
			cur = append(cur, c)
			p.i++
		}
	}
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func (p *fparser) item() ([]byte, error) {
	at := p.attr()
	// Correspondance extensible : attr[:dn][:règle]:=valeur ou [:dn]:règle:=valeur.
	if p.peek() == ':' {
		return p.extensible(at)
	}
	if at == "" {
		return nil, p.err("nom d'attribut attendu")
	}
	var op byte
	switch {
	case strings.HasPrefix(p.s[p.i:], "~="):
		op, p.i = 8, p.i+2
	case strings.HasPrefix(p.s[p.i:], ">="):
		op, p.i = 5, p.i+2
	case strings.HasPrefix(p.s[p.i:], "<="):
		op, p.i = 6, p.i+2
	case p.peek() == '=':
		op, p.i = 3, p.i+1
	default:
		return nil, p.err("opérateur attendu (=, ~=, >=, <=)")
	}
	vals, err := p.value()
	if err != nil {
		return nil, err
	}
	if len(vals) == 1 {
		return seq(classContext|constructed|op, encStr(tagOctetString, at), encStr(tagOctetString, vals[0])), nil
	}
	if op != 3 {
		return nil, p.err("« * » interdit avec cet opérateur")
	}
	if len(vals) == 2 && vals[0] == "" && vals[1] == "" {
		return encStr(classContext|7, at), nil // présence : attr=*
	}
	var subs [][]byte
	for i, v := range vals {
		switch {
		case v == "" && (i == 0 || i == len(vals)-1):
		case v == "":
			return nil, p.err("« ** » interdit")
		case i == 0:
			subs = append(subs, encStr(classContext|0, v))
		case i == len(vals)-1:
			subs = append(subs, encStr(classContext|2, v))
		default:
			subs = append(subs, encStr(classContext|1, v))
		}
	}
	return seq(classContext|constructed|4, encStr(tagOctetString, at), seq(tagSequence, subs...)), nil
}

func (p *fparser) extensible(at string) ([]byte, error) {
	dn := false
	rule := ""
	for p.peek() == ':' {
		p.i++
		if p.peek() == '=' {
			p.i++
			vals, err := p.value()
			if err != nil {
				return nil, err
			}
			if len(vals) != 1 {
				return nil, p.err("« * » doit être échappé dans une correspondance extensible")
			}
			if at == "" && rule == "" {
				return nil, p.err("règle de correspondance requise sans attribut")
			}
			var parts [][]byte
			if rule != "" {
				parts = append(parts, encStr(classContext|1, rule))
			}
			if at != "" {
				parts = append(parts, encStr(classContext|2, at))
			}
			parts = append(parts, encStr(classContext|3, vals[0]))
			if dn {
				parts = append(parts, encBool(classContext|4, true))
			}
			return seq(classContext|constructed|9, parts...), nil
		}
		w := p.attr()
		switch {
		case strings.EqualFold(w, "dn") && !dn && rule == "":
			dn = true
		case w != "" && rule == "":
			rule = w
		default:
			return nil, p.err("correspondance extensible mal formée")
		}
	}
	return nil, p.err("« := » attendu")
}
