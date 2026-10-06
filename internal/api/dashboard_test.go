package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/rempart-dns/rempart/internal/audit"
	"github.com/rempart-dns/rempart/internal/querylog"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

// Le tableau de bord doit répondre avec les seuls composants présents, et
// garder ses compteurs anonymes quand le journal est désactivé.
func TestDashboardStatsWithoutLog(t *testing.T) {
	ks := testutil.Keystore(t)
	dir := t.TempDir()
	store, _, _ := state.Open(ks, filepath.Join(dir, "s"), state.State{})
	al, _ := audit.Open(ks, dir)
	ql, _ := querylog.New(ks, dir, testutil.Logger())
	ql.Configure(querylog.ModeNone, "pseudonymize", 7)
	ql.Record(querylog.Entry{Time: time.Now(), Name: "ads.example.", Type: "A", Status: querylog.StatusBlocked, Proto: "udp", Source: "Liste"}, netip.MustParseAddr("10.0.0.2"))
	a := &API{Store: store, Audit: al, KS: ks, QLog: ql, Started: time.Now()}

	rec := httptest.NewRecorder()
	a.stats(rec, httptest.NewRequest("GET", "/api/stats", nil), "admin")
	var out struct {
		Total    uint64          `json:"total"`
		LogMode  string          `json:"log_mode"`
		QTypes   []querylog.Top  `json:"qtypes"`
		Reasons  []querylog.Top  `json:"block_reasons"`
		Week     []querylog.Slot `json:"week"`
		TopBlock []querylog.Top  `json:"top_blocked"`
		Health   map[string]any  `json:"health"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err, rec.Body.String())
	}
	if out.Total != 1 || out.LogMode != "none" || len(out.QTypes) != 1 || len(out.Reasons) != 1 || len(out.Week) != 168 || len(out.TopBlock) != 0 {
		t.Fatalf("réponse inattendue: %s", rec.Body.String())
	}
	if aud, _ := out.Health["audit"].(map[string]any); aud["ok"] != true {
		t.Fatalf("état de l'audit absent: %v", out.Health)
	}
}
