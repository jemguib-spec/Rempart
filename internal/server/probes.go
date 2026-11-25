// probes.go - noms des tests de connectivité des systèmes, jamais bloqués par les listes.
// Entrées : nom demandé (minuscules, avec point final).
// Contexte : à chaque changement de réseau (4G → Wi-Fi), Android, MIUI/HyperOS,
// iOS, Windows… interrogent une adresse fixe (generate_204, hotspot-detect) pour
// savoir si le réseau donne accès à Internet. Si une liste de blocage vise ce
// nom (les listes « Pro » visent souvent les domaines Xiaomi), le système juge
// le Wi-Fi « connecté, sans Internet », garde ou coupe les données et ne
// retente qu'après plusieurs minutes. Les règles explicites d'un groupe
// (plages horaires du contrôle parental) s'appliquent toujours.
package server

var connectivityProbes = map[string]bool{
	// Android (AOSP, Google)
	"connectivitycheck.gstatic.com.": true,
	"connectivitycheck.android.com.": true,
	"clients1.google.com.":           true,
	"clients3.google.com.":           true,
	"clients4.google.com.":           true,
	// Xiaomi (MIUI, HyperOS)
	"connect.rom.miui.com.": true,
	// Huawei, Honor
	"connectivitycheck.platform.hicloud.com.":      true,
	"connectivitycheck.platform.hihonorcloud.com.": true,
	// Apple
	"captive.apple.com.": true,
	// Windows
	"www.msftconnecttest.com.":  true,
	"ipv6.msftconnecttest.com.": true,
	"www.msftncsi.com.":         true,
	"dns.msftncsi.com.":         true,
	// Firefox, GNOME, Ubuntu
	"detectportal.firefox.com.":      true,
	"nmcheck.gnome.org.":             true,
	"connectivity-check.ubuntu.com.": true,
}

func connectivityProbe(name string) bool { return connectivityProbes[name] }
