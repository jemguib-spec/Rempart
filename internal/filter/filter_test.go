package filter

import (
	"strings"
	"testing"
)

const sample = `
# hosts format
0.0.0.0 ads.example.com tracker.example.net
127.0.0.1 localhost
! adblock format
||doubleclick.net^
||analytics.example.org^$important
||cosmetic.example^$third-party
@@||good.ads.example.com^
plain-domain.example
example.com/path
`

func TestParseAndMatch(t *testing.T) {
	b := NewBuilder()
	st, err := Parse(strings.NewReader(sample), b, b.AddSource(Source{ID: "t", Name: "test"}), false)
	if err != nil {
		t.Fatal(err)
	}
	if st.Block != 5 || st.Allow != 1 {
		t.Fatalf("stats inattendues: %+v", st)
	}
	m := b.Build()
	cases := map[string]bool{
		"ads.example.com.":         true,
		"sub.ads.example.com":      true,
		"good.ads.example.com":     false, // exception wins
		"x.good.ads.example.com":   false,
		"stats.g.doubleclick.net.": true,
		"doubleclick.net":          true,
		"notdoubleclick.net":       false,
		"plain-domain.example":     true,
		"example.com":              false,
		"localhost":                false,
		"cosmetic.example":         false,
		"ANALYTICS.example.org":    true,
	}
	for name, want := range cases {
		if got := m.Match(name).Blocked; got != want {
			t.Errorf("%s: bloqué=%v, attendu %v", name, got, want)
		}
	}
	if r := m.Match("good.ads.example.com"); !r.Allowed {
		t.Error("l'exception devrait être signalée")
	}
}

func BenchmarkMatch(b *testing.B) {
	bl := NewBuilder()
	src := bl.AddSource(Source{})
	for i := 0; i < 500000; i++ {
		bl.Block("host"+itoa(i)+".ads.example", src)
	}
	m := bl.Build()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Match("a.b.c.www.some-site.example.com.")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}
