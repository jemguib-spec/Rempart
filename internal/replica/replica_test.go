package replica

import (
	"testing"

	"github.com/rempart-dns/rempart/internal/state"
)

func TestApplyKeepsLocal(t *testing.T) {
	s := state.State{
		Settings:    state.Settings{LogMode: "none", RetentionDays: 3, ClientIDs: "truncate"},
		TSIGKeys:    []state.TSIGKey{{Name: "repl.", Secret: "bG9jYWw="}},
		Replication: state.Replication{Role: "replica", PrimaryDNS: "192.0.2.1"},
	}
	p := Payload{
		Settings: state.Settings{BlockingEnabled: true, LogMode: "full", RetentionDays: 90, ClientIDs: "clear"},
		Lists:    []state.List{{ID: "a", URL: "https://x.example/l.txt"}, {ID: "b", URL: "/etc/shadow"}},
		Keys:     []state.TSIGKey{{Name: "repl.", Secret: "ZGlzdGFudA=="}, {Name: "rpz.", Secret: "cnB6"}},
		Zones:    []string{"corp.lan.", "pas un nom!"},
	}
	Apply(&s, p, "repl.")
	if s.Settings.LogMode != "none" || s.Settings.RetentionDays != 3 || s.Settings.ClientIDs != "truncate" || !s.Settings.BlockingEnabled {
		t.Fatalf("réglages : %+v", s.Settings)
	}
	if len(s.Lists) != 1 || s.Lists[0].ID != "a" {
		t.Fatalf("listes locales reprises : %+v", s.Lists)
	}
	if len(s.TSIGKeys) != 2 || s.TSIGKeys[0].Secret != "bG9jYWw=" || s.TSIGKeys[1].Name != "rpz." {
		t.Fatalf("clés : %+v", s.TSIGKeys)
	}
	if len(s.Secondaries) != 1 {
		t.Fatalf("zones : %+v", s.Secondaries)
	}
}
