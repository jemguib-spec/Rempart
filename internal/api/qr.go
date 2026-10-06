package api

// qr.go - encodeur QR code minimal (mode octet, correction M, versions 1 à
// 10), suffisant pour une URI otpauth://. Aucune dépendance : l'interface
// fonctionne hors ligne et le secret TOTP ne quitte jamais le serveur.

import (
	"errors"
	"fmt"
	"strings"
)

type qrVersion struct {
	ecPerBlock int
	groups     [][2]int // {nombre de blocs, octets de données par bloc}
	align      []int
}

var qrVersionsM = []qrVersion{
	{},
	{10, [][2]int{{1, 16}}, nil},
	{16, [][2]int{{1, 28}}, []int{6, 18}},
	{26, [][2]int{{1, 44}}, []int{6, 22}},
	{18, [][2]int{{2, 32}}, []int{6, 26}},
	{24, [][2]int{{2, 43}}, []int{6, 30}},
	{16, [][2]int{{4, 27}}, []int{6, 34}},
	{18, [][2]int{{4, 31}}, []int{6, 22, 38}},
	{22, [][2]int{{2, 38}, {2, 39}}, []int{6, 24, 42}},
	{22, [][2]int{{3, 36}, {2, 37}}, []int{6, 26, 46}},
	{26, [][2]int{{4, 43}, {1, 44}}, []int{6, 28, 50}},
}

func (v qrVersion) dataLen() int {
	n := 0
	for _, g := range v.groups {
		n += g[0] * g[1]
	}
	return n
}

type qrCode struct {
	size     int
	mod      [][]bool
	function [][]bool
}

func (q *qrCode) set(x, y int, dark bool) { q.mod[y][x] = dark; q.function[y][x] = true }

// qrEncode renvoie la matrice des modules (true = sombre).
func qrEncode(text string) ([][]bool, error) {
	data := []byte(text)
	ver := 0
	for v := 1; v < len(qrVersionsM); v++ {
		cc := 8
		if v >= 10 {
			cc = 16
		}
		if 4+cc+8*len(data) <= 8*qrVersionsM[v].dataLen() {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, errors.New("texte trop long pour le QR code")
	}
	vi := qrVersionsM[ver]

	// Flux de bits : mode octet, longueur, données, terminateur, bourrage.
	var bits []bool
	put := func(val, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, (val>>i)&1 == 1)
		}
	}
	put(0b0100, 4)
	if ver >= 10 {
		put(len(data), 16)
	} else {
		put(len(data), 8)
	}
	for _, b := range data {
		put(int(b), 8)
	}
	capBits := 8 * vi.dataLen()
	put(0, min(4, capBits-len(bits)))
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}
	for pad := 0xEC; len(bits) < capBits; pad ^= 0xEC ^ 0x11 {
		put(pad, 8)
	}
	cw := make([]byte, len(bits)/8)
	for i, b := range bits {
		if b {
			cw[i/8] |= 0x80 >> (i % 8)
		}
	}

	// Blocs, Reed-Solomon, entrelacement.
	div := rsDivisor(vi.ecPerBlock)
	var blocks, ecs [][]byte
	off := 0
	for _, g := range vi.groups {
		for i := 0; i < g[0]; i++ {
			b := cw[off : off+g[1]]
			off += g[1]
			blocks = append(blocks, b)
			ecs = append(ecs, rsRemainder(b, div))
		}
	}
	var final []byte
	for i := 0; ; i++ {
		added := false
		for _, b := range blocks {
			if i < len(b) {
				final = append(final, b[i])
				added = true
			}
		}
		if !added {
			break
		}
	}
	for i := 0; i < vi.ecPerBlock; i++ {
		for _, e := range ecs {
			final = append(final, e[i])
		}
	}

	size := 17 + 4*ver
	q := &qrCode{size: size}
	q.mod = make([][]bool, size)
	q.function = make([][]bool, size)
	for i := range q.mod {
		q.mod[i] = make([]bool, size)
		q.function[i] = make([]bool, size)
	}
	// Motifs fixes.
	for i := 0; i < size; i++ {
		q.set(6, i, i%2 == 0)
		q.set(i, 6, i%2 == 0)
	}
	for _, c := range [][2]int{{3, 3}, {size - 4, 3}, {3, size - 4}} {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x, y := c[0]+dx, c[1]+dy
				if x >= 0 && x < size && y >= 0 && y < size {
					d := max(abs(dx), abs(dy))
					q.set(x, y, d != 2 && d != 4)
				}
			}
		}
	}
	na := len(vi.align)
	for i := 0; i < na; i++ {
		for j := 0; j < na; j++ {
			if (i == 0 && j == 0) || (i == 0 && j == na-1) || (i == na-1 && j == 0) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					q.set(vi.align[i]+dx, vi.align[j]+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	q.drawFormat(0) // réserve les emplacements
	if ver >= 7 {
		rem := ver
		for i := 0; i < 12; i++ {
			rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
		}
		vb := ver<<12 | rem
		for i := 0; i < 18; i++ {
			bit := (vb>>i)&1 == 1
			a, b := size-11+i%3, i/3
			q.set(a, b, bit)
			q.set(b, a, bit)
		}
	}
	// Placement en zigzag.
	i := 0
	for right := size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < size; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = size - 1 - vert
				}
				if !q.function[y][x] && i < len(final)*8 {
					q.mod[y][x] = (final[i>>3]>>(7-uint(i&7)))&1 == 1
					i++
				}
			}
		}
	}
	// Choix du masque de moindre pénalité.
	best, bestScore := 0, -1
	for m := 0; m < 8; m++ {
		q.applyMask(m)
		q.drawFormat(m)
		if s := q.penalty(); bestScore < 0 || s < bestScore {
			best, bestScore = m, s
		}
		q.applyMask(m) // XOR : annule
	}
	q.applyMask(best)
	q.drawFormat(best)
	return q.mod, nil
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func (q *qrCode) drawFormat(mask int) {
	data := 0<<3 | mask // niveau M = 00
	rem := data
	for i := 0; i < 10; i++ {
		rem = (rem << 1) ^ ((rem >> 9) * 0x537)
	}
	bits := (data<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return (bits>>i)&1 == 1 }
	n := q.size
	for i := 0; i <= 5; i++ {
		q.set(8, i, bit(i))
	}
	q.set(8, 7, bit(6))
	q.set(8, 8, bit(7))
	q.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		q.set(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		q.set(n-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		q.set(8, n-15+i, bit(i))
	}
	q.set(8, n-8, true)
}

func (q *qrCode) applyMask(m int) {
	for y := 0; y < q.size; y++ {
		for x := 0; x < q.size; x++ {
			if q.function[y][x] {
				continue
			}
			var inv bool
			switch m {
			case 0:
				inv = (x+y)%2 == 0
			case 1:
				inv = y%2 == 0
			case 2:
				inv = x%3 == 0
			case 3:
				inv = (x+y)%3 == 0
			case 4:
				inv = (x/3+y/2)%2 == 0
			case 5:
				inv = x*y%2+x*y%3 == 0
			case 6:
				inv = (x*y%2+x*y%3)%2 == 0
			case 7:
				inv = ((x+y)%2+x*y%3)%2 == 0
			}
			if inv {
				q.mod[y][x] = !q.mod[y][x]
			}
		}
	}
}

// penalty applique les règles 1, 2 et 4 de la norme (la règle 3 ne change
// pas la validité du symbole, seulement sa robustesse).
func (q *qrCode) penalty() int {
	n, p, dark := q.size, 0, 0
	for y := 0; y < n; y++ {
		runR, runC := 1, 1
		for x := 0; x < n; x++ {
			if q.mod[y][x] {
				dark++
			}
			if x > 0 {
				if q.mod[y][x] == q.mod[y][x-1] {
					runR++
				} else {
					runR = 1
				}
				if q.mod[x][y] == q.mod[x-1][y] {
					runC++
				} else {
					runC = 1
				}
				if runR == 5 {
					p += 3
				} else if runR > 5 {
					p++
				}
				if runC == 5 {
					p += 3
				} else if runC > 5 {
					p++
				}
			}
			if x > 0 && y > 0 {
				c := q.mod[y][x]
				if c == q.mod[y][x-1] && c == q.mod[y-1][x] && c == q.mod[y-1][x-1] {
					p += 3
				}
			}
		}
	}
	k := abs(dark*20-n*n*10) / (n * n)
	return p + k*10
}

func gfMul(a, b byte) byte {
	var r byte
	for i := 7; i >= 0; i-- {
		r = (r << 1) ^ ((r >> 7) * 0x1D)
		if (b>>uint(i))&1 == 1 {
			r ^= a
		}
	}
	return r
}

func rsDivisor(deg int) []byte {
	res := make([]byte, deg)
	res[deg-1] = 1
	root := byte(1)
	for i := 0; i < deg; i++ {
		for j := 0; j < deg; j++ {
			res[j] = gfMul(res[j], root)
			if j+1 < deg {
				res[j] ^= res[j+1]
			}
		}
		root = gfMul(root, 0x02)
	}
	return res
}

func rsRemainder(data, div []byte) []byte {
	res := make([]byte, len(div))
	for _, b := range data {
		f := b ^ res[0]
		copy(res, res[1:])
		res[len(res)-1] = 0
		for i := range res {
			res[i] ^= gfMul(div[i], f)
		}
	}
	return res
}

// qrSVG dessine la matrice avec une marge de 4 modules.
func qrSVG(m [][]bool) string {
	n := len(m) + 8
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n, n, n)
	for y, row := range m {
		for x, d := range row {
			if d {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+4, y+4)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}
