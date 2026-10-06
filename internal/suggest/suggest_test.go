// suggest_test.go - tests des indices de suggestion.
// Données synthétiques.
// Rempart ; go test ./internal/suggest.

package suggest

import (
	"testing"

	"github.com/rempart-dns/rempart/internal/filter"
)

func matcher(blocked ...string) *filter.Matcher {
	b := filter.NewBuilder()
	src := b.AddSource(filter.Source{ID: "t", Name: "test"})
	for _, d := range blocked {
		b.Block(d, src)
	}
	return b.Build()
}

func find(s []Suggestion, d string) *Suggestion {
	for i := range s {
		if s[i].Domain == d {
			return &s[i]
		}
	}
	return nil
}

func TestSuggestions(t *testing.T) {
	o := New()
	o.Resolved("ignored.example.com", false, "") // désactivé : rien n'est retenu
	o.Enable(true)
	if len(o.Analyze(matcher(), nil, 0)) != 0 {
		t.Fatal("aucune observation attendue avant activation")
	}
	o.Resolved("metrics.boutique.fr.", false, "boutique.eulerian.net.")
	o.Resolved("telemetry.editeur.com", false, "")
	o.Resolved("track.com", false, "") // domaine enregistrable : pas d'indice de libellé
	for _, d := range []string{"a1.pub.example.net", "a2.pub.example.net", "a3.pub.example.net"} {
		o.Blocked(d)
	}
	o.Resolved("a4.pub.example.net", false, "")
	o.Resolved("www.xk7q2vbn9wzt4p.com", true, "")
	o.Resolved("www.bonjourlemonde.com", true, "")

	s := o.Analyze(matcher(), nil, 0)
	if x := find(s, "eulerian.net"); x == nil || x.Kind != "cname" {
		t.Fatalf("CNAME de traçage non détecté : %+v", s)
	}
	if find(s, "telemetry.editeur.com") == nil {
		t.Fatal("libellé de télémétrie non détecté")
	}
	if find(s, "track.com") != nil {
		t.Fatal("un domaine enregistrable ne doit pas être suggéré pour son seul nom")
	}
	if find(s, "a4.pub.example.net") == nil {
		t.Fatal("voisins bloqués non détectés")
	}
	if find(s, "xk7q2vbn9wzt4p.com") == nil {
		t.Fatal("nom aléatoire inexistant non détecté")
	}
	if find(s, "bonjourlemonde.com") != nil {
		t.Fatal("des mots accolés ne sont pas un nom aléatoire")
	}
	// Déjà bloqué ou ignoré : exclu.
	s = o.Analyze(matcher("eulerian.net"), []string{"telemetry.editeur.com"}, 0)
	if find(s, "eulerian.net") != nil || find(s, "telemetry.editeur.com") != nil {
		t.Fatal("domaines bloqués ou ignorés encore suggérés")
	}
	o.Enable(false)
	o.Enable(true)
	if len(o.Analyze(matcher(), nil, 0)) != 0 {
		t.Fatal("la désactivation doit tout effacer")
	}
}
