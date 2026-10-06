// shamir.go - partage de secret de Shamir sur GF(2^8) pour le quorum M-sur-N.
// Entrées : un secret (clé racine de 32 octets), N et M ; sorties : N parts.
// Rempart, keystore logiciel ; arithmétique sans table ni branche (temps constant).

package keystore

import (
	"crypto/rand"
	"errors"

	"github.com/rempart-dns/rempart/internal/secmem"
)

// Corps GF(2^8) de polynôme x^8+x^4+x^3+x+1 (0x11B, celui d'AES). Les
// multiplications sont faites bit à bit, sans table indexée par le secret :
// une table de logarithmes fuirait par le cache.
func gf256Mul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		p ^= a & -(b & 1) // a si le bit de poids faible de b vaut 1
		hi := a >> 7
		a = (a << 1) ^ (0x1B & -hi)
		b >>= 1
	}
	return p
}

// gf256Inv : a^254 = a^-1 (a ≠ 0), par exponentiation à nombre d'opérations fixe.
func gf256Inv(a byte) byte {
	r := byte(1)
	x := a
	for e := 254; e > 0; e >>= 1 {
		if e&1 == 1 { // e est public : la branche ne dépend pas du secret
			r = gf256Mul(r, x)
		}
		x = gf256Mul(x, x)
	}
	return r
}

// Share est une part : abscisse X (1..255) et ordonnées, un octet par octet
// du secret.
type Share struct {
	X byte
	Y []byte
}

// shamirSplit découpe secret en n parts dont m suffisent à le reconstituer.
// Moins de m parts ne donnent aucune information sur le secret.
func shamirSplit(secret []byte, n, m int) ([]Share, error) {
	if m < 2 || n < m || n > 255 {
		return nil, errors.New("quorum invalide : il faut 2 ≤ M ≤ N ≤ 255")
	}
	shares := make([]Share, n)
	for i := range shares {
		shares[i] = Share{X: byte(i + 1), Y: make([]byte, len(secret))}
	}
	coef := make([]byte, m) // coef[0] = octet du secret, les autres aléatoires
	defer secmem.Wipe(coef)
	for j, s := range secret {
		coef[0] = s
		if _, err := rand.Read(coef[1:]); err != nil {
			return nil, err
		}
		for i := range shares {
			// Horner : P(x) = c0 + x(c1 + x(c2 + …))
			x, y := shares[i].X, byte(0)
			for k := m - 1; k >= 0; k-- {
				y = gf256Mul(y, x) ^ coef[k]
			}
			shares[i].Y[j] = y
		}
	}
	return shares, nil
}

// shamirCombine reconstitue le secret par interpolation de Lagrange en 0.
// Avec moins de M parts, ou une part fausse, le résultat est faux sans que
// rien ne le signale : l'appelant vérifie le secret obtenu.
func shamirCombine(shares []Share) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("au moins deux parts sont nécessaires")
	}
	n := len(shares[0].Y)
	seen := map[byte]bool{}
	for _, s := range shares {
		if s.X == 0 || seen[s.X] || len(s.Y) != n {
			return nil, errors.New("parts incohérentes")
		}
		seen[s.X] = true
	}
	out := make([]byte, n)
	for i, si := range shares {
		// Coefficient de Lagrange en 0 : Π xj / (xj - xi), soustraction = XOR.
		num, den := byte(1), byte(1)
		for j, sj := range shares {
			if i != j {
				num = gf256Mul(num, sj.X)
				den = gf256Mul(den, sj.X^si.X)
			}
		}
		l := gf256Mul(num, gf256Inv(den))
		for k := 0; k < n; k++ {
			out[k] ^= gf256Mul(si.Y[k], l)
		}
	}
	return out, nil
}
