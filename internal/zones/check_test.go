package zones

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

func TestCheckLines(t *testing.T) {
	ks := testutil.Keystore(t)
	sz := state.Zone{Name: "maison.lan"}

	rep := Check(ks, sz, []string{"nas 300 IN A 192.168.1.10", "", "photos IN CNAME nas", `@ IN TXT "bonjour"`})
	if !rep.OK || len(rep.Lines) != 3 {
		t.Fatalf("zone correcte refusée : %+v", rep)
	}
	if rep.Lines[0].Line != 1 || rep.Lines[1].Line != 3 {
		t.Fatalf("numéros de ligne : %+v", rep.Lines)
	}
	if r := rep.Lines[0].Records[0]; r.Name != "nas.maison.lan" || r.Type != "A" || r.TTL != 300 || r.Value != "192.168.1.10" {
		t.Fatalf("lecture : %+v", r)
	}

	rep = Check(ks, sz, []string{"nas IN A 192.168.1.10", "imprimante IN A 192.168.1.300"})
	if rep.OK || rep.Lines[0].Error != "" || !strings.Contains(rep.Lines[1].Error, "adresse IPv4 invalide") {
		t.Fatalf("erreur mal située ou non traduite : %+v", rep)
	}

	// Règle qui porte sur plusieurs lignes : vérifiée sur la zone entière.
	rep = Check(ks, sz, []string{"nas IN A 192.168.1.10", "nas IN CNAME autre"})
	if rep.OK || !strings.Contains(rep.Error, "CNAME") {
		t.Fatalf("conflit CNAME non détecté : %+v", rep)
	}
	// Un enregistrement dynamique existant compte dans les conflits.
	rep = Check(ks, state.Zone{Name: "maison.lan", Dynamic: []string{"pc IN A 192.168.1.20"}}, []string{"pc IN CNAME nas"})
	if rep.OK {
		t.Fatal("conflit avec un enregistrement dynamique non détecté")
	}
	if rep := Check(ks, sz, []string{"nas.autre.lan. IN A 10.0.0.1"}); rep.OK {
		t.Fatal("nom hors de la zone accepté")
	}
}

func TestLookup(t *testing.T) {
	ks := testutil.Keystore(t)
	m := NewManager(ks, nil)
	if err := m.Load([]state.Zone{{Name: "maison.lan.", Records: []string{"nas IN A 192.168.1.10", "photos IN CNAME nas"}}}); err != nil {
		t.Fatal(err)
	}
	rcode, ans, ok := m.Lookup("maison.lan", "photos.maison.lan", dns.TypeA)
	if !ok || rcode != "NOERROR" || len(ans) != 2 || !strings.Contains(ans[1], "192.168.1.10") {
		t.Fatalf("alias non suivi : %s %v", rcode, ans)
	}
	if rcode, _, _ := m.Lookup("maison.lan", "absent.maison.lan", dns.TypeA); rcode != "NXDOMAIN" {
		t.Fatalf("nom absent : %s", rcode)
	}
	if _, _, ok := m.Lookup("maison.lan", "exemple.fr", dns.TypeA); ok {
		t.Fatal("nom hors zone servi")
	}
}
