package web

import (
	"io/fs"
	"os"
	"regexp"
	"sort"
	"testing"
)

// TestAPISpecCoversRoutes vérifie que la console API (static/api-spec.js)
// décrit exactement les routes enregistrées dans internal/api/api.go, avec la
// même portée : une route ajoutée sans documentation fait échouer les tests.
func TestAPISpecCoversRoutes(t *testing.T) {
	goSrc, err := os.ReadFile("../internal/api/api.go")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := fs.ReadFile(FS(), "api-spec.js")
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]string{}
	for _, m := range regexp.MustCompile(`auth\("(\w+)", "(\w+ [^"]+)"`).FindAllStringSubmatch(string(goSrc), -1) {
		routes[m[2]] = m[1]
	}
	for _, m := range regexp.MustCompile(`mux\.HandleFunc\("(\w+ /[^"]+)"`).FindAllStringSubmatch(string(goSrc), -1) {
		routes[m[1]] = "public"
	}
	documented := map[string]string{}
	for _, m := range regexp.MustCompile(`m: "(\w+)", p: "([^"]+)", scope: "(\w+)"`).FindAllStringSubmatch(string(spec), -1) {
		documented[m[1]+" "+m[2]] = m[3]
	}
	if len(routes) < 100 {
		t.Fatalf("seulement %d routes trouvées dans api.go : expression à revoir", len(routes))
	}
	var missing, extra, scope []string
	for r, s := range routes {
		d, ok := documented[r]
		switch {
		case !ok:
			missing = append(missing, r)
		case d != s:
			scope = append(scope, r+" : "+s+" dans api.go, "+d+" dans api-spec.js")
		}
	}
	for r := range documented {
		if _, ok := routes[r]; !ok {
			extra = append(extra, r)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	sort.Strings(scope)
	for _, r := range missing {
		t.Errorf("route non documentée dans web/static/api-spec.js : %s", r)
	}
	for _, r := range extra {
		t.Errorf("route documentée mais absente d'api.go : %s", r)
	}
	for _, r := range scope {
		t.Errorf("portée différente : %s", r)
	}
}
