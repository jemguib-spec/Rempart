// Package metrics écrit le format d'exposition texte de Prometheus (0.0.4),
// sans dépendance. Aucune métrique ne porte d'information sur un client.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Writer accumule les familles de métriques.
type Writer struct {
	w    io.Writer
	seen map[string]bool
}

func NewWriter(w io.Writer) *Writer { return &Writer{w: w, seen: map[string]bool{}} }

// Labels : paires nom, valeur.
type Labels []string

func escape(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
}

func (l Labels) String() string {
	if len(l) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i+1 < len(l); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `%s="%s"`, l[i], escape(l[i+1]))
	}
	b.WriteByte('}')
	return b.String()
}

func (w *Writer) head(name, typ, help string) {
	if w.seen[name] {
		return
	}
	w.seen[name] = true
	fmt.Fprintf(w.w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func num(v float64) string {
	if math.IsInf(v, 1) {
		return "+Inf"
	}
	if a := math.Abs(v); v == 0 || (a >= 1e-6 && a < 1e15) {
		return strconv.FormatFloat(v, 'f', -1, 64) // lisible : séries, horodatages à la milliseconde
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// Gauge écrit une jauge.
func (w *Writer) Gauge(name, help string, v float64, l ...string) {
	w.head(name, "gauge", help)
	fmt.Fprintf(w.w, "%s%s %s\n", name, Labels(l), num(v))
}

// Counter écrit un compteur (le nom doit finir par _total).
func (w *Writer) Counter(name, help string, v float64, l ...string) {
	w.head(name, "counter", help)
	fmt.Fprintf(w.w, "%s%s %s\n", name, Labels(l), num(v))
}

// Time écrit un horodatage en secondes Unix (0 si jamais).
func (w *Writer) Time(name, help string, t time.Time, l ...string) {
	v := 0.0
	if !t.IsZero() {
		v = float64(t.UnixMilli()) / 1000
	}
	w.Gauge(name, help, v, l...)
}

// Histogram : histogramme à seuils fixes, mis à jour sans verrou.
type Histogram struct {
	Bounds []float64 // secondes, croissantes
	counts []atomic.Uint64
	sumUs  atomic.Uint64
	n      atomic.Uint64
}

func NewHistogram(bounds ...float64) *Histogram {
	sort.Float64s(bounds)
	return &Histogram{Bounds: bounds, counts: make([]atomic.Uint64, len(bounds))}
}

// Observe ajoute une durée.
func (h *Histogram) Observe(d time.Duration) {
	if d < 0 {
		return // horloge qui recule : la somme non signée serait faussée
	}
	s := d.Seconds()
	for i, b := range h.Bounds {
		if s <= b {
			h.counts[i].Add(1)
			break
		}
	}
	h.sumUs.Add(uint64(d.Microseconds()))
	h.n.Add(1)
}

// Write écrit l'histogramme (seuils cumulés).
func (w *Writer) Histogram(name, help string, h *Histogram, l ...string) {
	w.head(name, "histogram", help)
	var cum uint64
	for i, b := range h.Bounds {
		cum += h.counts[i].Load()
		fmt.Fprintf(w.w, "%s_bucket%s %d\n", name, Labels(append(append([]string{}, l...), "le", num(b))), cum)
	}
	n := h.n.Load()
	fmt.Fprintf(w.w, "%s_bucket%s %d\n", name, Labels(append(append([]string{}, l...), "le", "+Inf")), n)
	fmt.Fprintf(w.w, "%s_sum%s %s\n", name, Labels(l), num(float64(h.sumUs.Load())/1e6))
	fmt.Fprintf(w.w, "%s_count%s %d\n", name, Labels(l), n)
}
