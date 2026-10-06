package metrics

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestFormat(t *testing.T) {
	var b bytes.Buffer
	w := NewWriter(&b)
	w.Gauge("rempart_x", "Aide.", 1.5, "zone", "a.example.")
	w.Gauge("rempart_x", "Aide.", 2, "zone", "b.example.")
	w.Counter("rempart_q_total", "Requêtes.", 42)
	w.Time("rempart_t", "Date.", time.Time{})
	w.Time("rempart_t2", "Date.", time.Unix(1700000000, 500e6))
	want := `# HELP rempart_x Aide.
# TYPE rempart_x gauge
rempart_x{zone="a.example."} 1.5
rempart_x{zone="b.example."} 2
# HELP rempart_q_total Requêtes.
# TYPE rempart_q_total counter
rempart_q_total 42
# HELP rempart_t Date.
# TYPE rempart_t gauge
rempart_t 0
# HELP rempart_t2 Date.
# TYPE rempart_t2 gauge
rempart_t2 1700000000.5
`
	if b.String() != want {
		t.Fatalf("obtenu :\n%s", b.String())
	}
}

func TestLabelEscaping(t *testing.T) {
	got := Labels{"a", "x\"y\\z\nw"}.String()
	if got != `{a="x\"y\\z\nw"}` {
		t.Fatalf("%s", got)
	}
	if Labels(nil).String() != "" {
		t.Fatal("étiquettes vides")
	}
	if (Labels{"a", "1", "b", "2"}).String() != `{a="1",b="2"}` {
		t.Fatal("plusieurs étiquettes")
	}
}

func TestNum(t *testing.T) {
	for v, want := range map[float64]string{0: "0", 3: "3", 1e20: "1e+20", 0.25: "0.25", -2: "-2"} {
		if got := num(v); got != want {
			t.Fatalf("num(%v) = %s, attendu %s", v, got, want)
		}
	}
}

func TestHistogram(t *testing.T) {
	h := NewHistogram(0.1, 0.001, 0.01) // désordonnés : triés
	h.Observe(500 * time.Microsecond)
	h.Observe(5 * time.Millisecond)
	h.Observe(time.Second)
	h.Observe(-time.Second) // ignoré : une horloge qui recule ne fausse pas la somme
	var b bytes.Buffer
	NewWriter(&b).Histogram("rempart_lat_seconds", "Latence.", h, "t", "udp")
	out := b.String()
	for _, line := range []string{
		`rempart_lat_seconds_bucket{t="udp",le="0.001"} 1`,
		`rempart_lat_seconds_bucket{t="udp",le="0.01"} 2`,
		`rempart_lat_seconds_bucket{t="udp",le="0.1"} 2`,
		`rempart_lat_seconds_bucket{t="udp",le="+Inf"} 3`,
		`rempart_lat_seconds_sum{t="udp"} 1.0055`,
		`rempart_lat_seconds_count{t="udp"} 3`,
	} {
		if !strings.Contains(out, line+"\n") {
			t.Fatalf("ligne absente : %s\n%s", line, out)
		}
	}
}
