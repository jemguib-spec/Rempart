// cbor.go - décodeur CBOR minimal (RFC 8949) pour les objets WebAuthn :
// entiers, chaînes d'octets, textes, tableaux, tables, booléens et null.
// Les longueurs sont bornées par les données reçues ; la profondeur aussi.

package webauthn

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var errCBOR = errors.New("CBOR invalide")

const maxDepth = 16

type cborDecoder struct {
	b []byte
	i int
}

// decodeCBOR décode une valeur et renvoie aussi le nombre d'octets lus (les
// données d'authentification contiennent une clé COSE suivie d'extensions).
func decodeCBOR(b []byte) (any, int, error) {
	d := &cborDecoder{b: b}
	v, err := d.value(0)
	return v, d.i, err
}

func (d *cborDecoder) need(n uint64) error {
	if n > uint64(len(d.b)-d.i) {
		return errCBOR
	}
	return nil
}

func (d *cborDecoder) arg(info byte) (uint64, error) {
	switch {
	case info < 24:
		return uint64(info), nil
	case info == 24:
		if err := d.need(1); err != nil {
			return 0, err
		}
		v := d.b[d.i]
		d.i++
		return uint64(v), nil
	case info == 25:
		if err := d.need(2); err != nil {
			return 0, err
		}
		v := binary.BigEndian.Uint16(d.b[d.i:])
		d.i += 2
		return uint64(v), nil
	case info == 26:
		if err := d.need(4); err != nil {
			return 0, err
		}
		v := binary.BigEndian.Uint32(d.b[d.i:])
		d.i += 4
		return uint64(v), nil
	case info == 27:
		if err := d.need(8); err != nil {
			return 0, err
		}
		v := binary.BigEndian.Uint64(d.b[d.i:])
		d.i += 8
		return v, nil
	}
	return 0, errCBOR // longueurs indéfinies refusées
}

func (d *cborDecoder) value(depth int) (any, error) {
	if depth > maxDepth {
		return nil, errCBOR
	}
	if err := d.need(1); err != nil {
		return nil, err
	}
	ib := d.b[d.i]
	d.i++
	major, info := ib>>5, ib&0x1f
	if major == 7 {
		switch info {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22, 23:
			return nil, nil
		}
		return nil, errCBOR
	}
	n, err := d.arg(info)
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		if n > 1<<62 {
			return nil, errCBOR
		}
		return int64(n), nil
	case 1:
		if n > 1<<62 {
			return nil, errCBOR
		}
		return -1 - int64(n), nil
	case 2, 3:
		if err := d.need(n); err != nil {
			return nil, err
		}
		s := d.b[d.i : d.i+int(n)]
		d.i += int(n)
		if major == 2 {
			return append([]byte(nil), s...), nil
		}
		return string(s), nil
	case 4:
		if err := d.need(n); err != nil { // au moins un octet par élément
			return nil, err
		}
		out := make([]any, 0, n)
		for k := uint64(0); k < n; k++ {
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		if n > uint64(len(d.b)) {
			return nil, errCBOR
		}
		if err := d.need(2 * n); err != nil {
			return nil, err
		}
		out := make(map[any]any, n)
		for k := uint64(0); k < n; k++ {
			key, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			switch key.(type) {
			case int64, string:
			default:
				return nil, fmt.Errorf("%w : clé de table non prise en charge", errCBOR)
			}
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if _, dup := out[key]; dup {
				return nil, fmt.Errorf("%w : clé en double", errCBOR)
			}
			out[key] = v
		}
		return out, nil
	}
	return nil, errCBOR // étiquettes (major 6) refusées
}
