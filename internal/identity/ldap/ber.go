// ber.go - sous-ensemble BER (X.690) nécessaire à LDAPv3 (RFC 4511).
// Le décodeur est volontairement strict : forme définie uniquement, étiquettes
// courtes uniquement, longueurs bornées. Les réponses d'un annuaire viennent
// du réseau et sont traitées comme hostiles.

package ldap

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// Classes et formes (premier octet de l'étiquette).
const (
	classUniversal   = 0x00
	classApplication = 0x40
	classContext     = 0x80
	constructed      = 0x20
)

// Étiquettes universelles utilisées.
const (
	tagBoolean     = 0x01
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagNull        = 0x05
	tagEnumerated  = 0x0a
	tagSequence    = 0x30 // constructed | 0x10
	tagSet         = 0x31 // constructed | 0x11
)

// maxMessage borne la taille d'un message LDAP reçu. Un utilisateur membre de
// milliers de groupes Active Directory tient largement dans 8 Mio.
const maxMessage = 8 << 20

// maxDepth borne l'imbrication (filtres, séquences) au décodage.
const maxDepth = 32

// element est un nœud BER décodé.
type element struct {
	tag      byte
	value    []byte     // contenu brut (primitif)
	children []*element // contenu décodé (construit)
}

func (e *element) constructed() bool { return e.tag&constructed != 0 }

// ---- encodage ----

func encLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func tlv(tag byte, content []byte) []byte {
	out := append([]byte{tag}, encLen(len(content))...)
	return append(out, content...)
}

func seq(tag byte, parts ...[]byte) []byte {
	var c []byte
	for _, p := range parts {
		c = append(c, p...)
	}
	return tlv(tag, c)
}

func encInt(tag byte, v int64) []byte {
	// Complément à deux, forme minimale.
	b := []byte{byte(v)}
	for v > 127 || v < -128 {
		v >>= 8
		b = append([]byte{byte(v)}, b...)
	}
	return tlv(tag, b)
}

func encStr(tag byte, s string) []byte { return tlv(tag, []byte(s)) }

func encBool(tag byte, v bool) []byte {
	if v {
		return tlv(tag, []byte{0xff})
	}
	return tlv(tag, []byte{0x00})
}

// ---- décodage ----

var errBER = errors.New("réponse LDAP mal formée")

// readMessage lit un élément BER complet depuis le flux.
func readMessage(r *bufio.Reader) (*element, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	n, err := readLen(r)
	if err != nil {
		return nil, err
	}
	if n > maxMessage {
		return nil, fmt.Errorf("message LDAP trop grand (%d octets)", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return parse(tag, buf, 0)
}

func readLen(r io.ByteReader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if b < 0x80 {
		return int(b), nil
	}
	k := int(b & 0x7f)
	if k == 0 || k > 4 { // 0 : forme indéfinie, interdite en LDAP
		return 0, errBER
	}
	n := 0
	for i := 0; i < k; i++ {
		c, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		n = n<<8 | int(c)
	}
	if n < 0 {
		return 0, errBER
	}
	return n, nil
}

func parse(tag byte, content []byte, depth int) (*element, error) {
	if tag&0x1f == 0x1f { // étiquette longue : jamais utilisée par LDAP
		return nil, errBER
	}
	e := &element{tag: tag, value: content}
	if !e.constructed() {
		return e, nil
	}
	if depth >= maxDepth {
		return nil, errBER
	}
	for len(content) > 0 {
		t := content[0]
		br := &sliceReader{b: content[1:]}
		n, err := readLen(br)
		if err != nil {
			return nil, errBER
		}
		rest := br.b
		if n > len(rest) {
			return nil, errBER
		}
		child, err := parse(t, rest[:n], depth+1)
		if err != nil {
			return nil, err
		}
		e.children = append(e.children, child)
		content = rest[n:]
	}
	return e, nil
}

type sliceReader struct{ b []byte }

func (s *sliceReader) ReadByte() (byte, error) {
	if len(s.b) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	c := s.b[0]
	s.b = s.b[1:]
	return c, nil
}

func (e *element) int() (int64, error) {
	if e.constructed() || len(e.value) == 0 || len(e.value) > 8 {
		return 0, errBER
	}
	v := int64(int8(e.value[0]))
	for _, c := range e.value[1:] {
		v = v<<8 | int64(c)
	}
	return v, nil
}

func (e *element) str() string { return string(e.value) }

// child renvoie le i-ème enfant ou une erreur de format.
func (e *element) child(i int) (*element, error) {
	if !e.constructed() || i >= len(e.children) {
		return nil, errBER
	}
	return e.children[i], nil
}
