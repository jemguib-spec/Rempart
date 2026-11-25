package web

import (
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestTrustedTypes garde l'interface compatible avec la CSP
// « require-trusted-types-for 'script'; trusted-types rempart » : la
// politique créée par app.js porte le nom autorisé, et aucune chaîne brute
// n'est affectée à un puits HTML (le navigateur la refuserait).
func TestTrustedTypes(t *testing.T) {
	goSrc, err := os.ReadFile("../internal/api/api.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(goSrc), "trusted-types rempart") {
		t.Fatal("la CSP n'autorise plus la politique « rempart »")
	}
	app, err := fs.ReadFile(FS(), "app.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(app), `createPolicy("rempart"`) {
		t.Fatal(`app.js ne crée plus la politique « rempart »`)
	}
	// innerHTML = "..." / '...' / `...` (sans html``) ou insertAdjacentHTML(…, "…").
	raw := regexp.MustCompile("(innerHTML\\s*=\\s*[\"'`])|(insertAdjacentHTML\\([^,]+,\\s*[\"'`])|(outerHTML\\s*=)|(document\\.write)")
	for _, name := range []string{"app.js", "ui-shared.js", "docs-common.js", "aide.js", "api-explorer.js"} {
		src, err := fs.ReadFile(FS(), name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if raw.MatchString(line) {
				t.Errorf("%s:%d : chaîne brute vers un puits HTML : %s", name, i+1, strings.TrimSpace(line))
			}
		}
	}
}
