// presets.go - catalogue des résolveurs publics chiffrés proposés dans l'interface.
// Adresses vérifiées auprès des opérateurs en octobre 2026.
// Rempart ; affiché dans Réglages, Résolution DNS.

package upstream

// Preset est un résolveur public proposé dans l'interface. Les adresses
// proviennent de la documentation de chaque opérateur (vérifiées en
// octobre 2026) ; la juridiction indique le droit applicable aux journaux.
type Preset struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Operator     string   `json:"operator"`
	Jurisdiction string   `json:"jurisdiction"`
	Filtering    string   `json:"filtering"`
	Specs        []string `json:"specs"`
}

// Presets : résolveurs publics chiffrés (DoH et DoT uniquement).
var Presets = []Preset{
	{ID: "quad9", Name: "Quad9", Operator: "Quad9 Foundation", Jurisdiction: "Suisse", Filtering: "blocage des domaines malveillants",
		Specs: []string{"https://dns.quad9.net/dns-query", "tls://dns.quad9.net"}},
	{ID: "dns4eu", Name: "DNS4EU protection", Operator: "consortium DNS4EU (Commission européenne)", Jurisdiction: "Union européenne", Filtering: "blocage des domaines malveillants",
		Specs: []string{"https://protective.joindns4.eu/dns-query", "tls://protective.joindns4.eu"}},
	{ID: "dns4eu-unfiltered", Name: "DNS4EU sans filtre", Operator: "consortium DNS4EU (Commission européenne)", Jurisdiction: "Union européenne", Filtering: "aucun",
		Specs: []string{"https://unfiltered.joindns4.eu/dns-query", "tls://unfiltered.joindns4.eu"}},
	{ID: "mullvad", Name: "Mullvad", Operator: "Mullvad VPN AB", Jurisdiction: "Suède", Filtering: "aucun",
		Specs: []string{"https://dns.mullvad.net/dns-query", "tls://dns.mullvad.net"}},
	{ID: "cloudflare", Name: "Cloudflare", Operator: "Cloudflare, Inc.", Jurisdiction: "États-Unis", Filtering: "aucun",
		Specs: []string{"https://cloudflare-dns.com/dns-query", "tls://one.one.one.one"}},
	{ID: "google", Name: "Google Public DNS", Operator: "Google LLC", Jurisdiction: "États-Unis", Filtering: "aucun",
		Specs: []string{"https://dns.google/dns-query", "tls://dns.google"}},
}
