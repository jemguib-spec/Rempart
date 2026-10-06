package zones

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

func TestUpdateCannotShadowStatic(t *testing.T) {
	ks := testutil.Keystore(t)
	sz := state.Zone{Name: "corp.test.", Records: []string{"intranet.svc IN A 10.0.0.1"}}
	z, err := Build(ks, sz)
	if err != nil {
		t.Fatal(err)
	}
	up := func(rr string) error {
		m := new(dns.Msg)
		m.SetUpdate("corp.test.")
		x, _ := dns.NewRR(rr)
		m.Insert([]dns.RR{x})
		_, err := ApplyUpdate(z, sz, m)
		return err
	}
	for _, rr := range []string{"svc.corp.test. 300 IN NS ns.attacker.example.", "svc.corp.test. 300 IN DNAME attacker.example.",
		"x.corp.test. 300 IN DNAME attacker.example.", "intranet.svc.corp.test. 300 IN A 6.6.6.6"} {
		if up(rr) == nil {
			t.Errorf("mise à jour acceptée : %s", rr)
		}
	}
	if err := up("pc1.corp.test. 300 IN A 10.0.0.51"); err != nil {
		t.Fatal(err)
	}
	if err := up("lab.corp.test. 300 IN NS ns.lab.corp.test."); err != nil {
		t.Fatalf("délégation sans nom de l'administrateur dessous : %v", err)
	}
}
