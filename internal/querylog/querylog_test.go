package querylog

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/rempart-dns/rempart/internal/testutil"
)

func TestEncryptedLogAndShredding(t *testing.T) {
	dir := t.TempDir()
	l, err := New(testutil.Keystore(t), dir, testutil.Logger())
	if err != nil {
		t.Fatal(err)
	}
	l.Configure(ModeFull, "pseudonymize", 7)
	ip := netip.MustParseAddr("192.168.1.42")
	for i := 0; i < 50; i++ {
		l.Record(Entry{Time: time.Now(), Name: "secret-medical-site.example.", Type: "A", Status: StatusAllowed}, ip)
	}
	l.Flush()
	day := time.Now().UTC().Format(time.DateOnly)
	raw, _ := os.ReadFile(filepath.Join(dir, "querylog", day+".log"))
	if len(raw) == 0 || bytes.Contains(raw, []byte("secret-medical")) || bytes.Contains(raw, []byte("192.168")) {
		t.Fatal("le journal doit exister et être chiffré")
	}
	n := 0
	if err := l.ReadDay(day, func(e Entry) bool {
		n++
		if e.Client == "192.168.1.42" || e.Client == "" {
			t.Fatalf("IP non pseudonymisée: %q", e.Client)
		}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if n != 50 {
		t.Fatalf("50 entrées attendues, %d lues", n)
	}

	// An old day is crypto-shredded by Purge.
	old := time.Now().UTC().AddDate(0, 0, -30)
	l.Record(Entry{Time: old, Name: "old.example.", Status: StatusAllowed}, ip)
	l.Flush()
	oldDay := old.Format(time.DateOnly)
	if _, err := os.Stat(filepath.Join(dir, "querylog", oldDay+".key")); err != nil {
		t.Fatal("la clé du jour ancien devrait exister avant purge")
	}
	l.Purge()
	if _, err := os.Stat(filepath.Join(dir, "querylog", oldDay+".key")); !os.IsNotExist(err) {
		t.Fatal("la clé aurait dû être détruite")
	}
	if err := l.ReadDay(oldDay, func(Entry) bool { return true }); err == nil {
		t.Fatal("le jour purgé ne doit plus être lisible")
	}
}

func TestPrivacyModes(t *testing.T) {
	l, _ := New(testutil.Keystore(t), t.TempDir(), testutil.Logger())
	ip := netip.MustParseAddr("10.0.0.5")
	l.Configure(ModeNone, "pseudonymize", 7)
	l.Record(Entry{Time: time.Now(), Name: "ads.example.", Status: StatusBlocked}, ip)
	s := l.Stats.Snapshot()
	if s.Total != 1 || s.Blocked != 1 || len(s.TopBlocked) != 0 || len(s.TopClients) != 0 || len(l.Recent(10, "", "")) != 0 {
		t.Fatalf("le mode none ne doit rien retenir de nominatif: %+v", s)
	}
	l.Configure(ModeStats, "pseudonymize", 7)
	l.Record(Entry{Time: time.Now(), Name: "ads.example.", Status: StatusBlocked}, ip)
	l.Record(Entry{Time: time.Now(), Name: "private.example.", Status: StatusAllowed}, ip)
	s = l.Stats.Snapshot()
	if len(s.TopBlocked) != 1 || len(s.TopDomains) != 0 || len(s.TopClients) != 0 {
		t.Fatalf("le mode stats ne garde que les domaines bloqués: %+v", s)
	}
	if got := (&Logger{clientIDs: "truncate"}).ClientID(netip.MustParseAddr("192.168.7.99")); got != "192.168.7.0/24" {
		t.Fatalf("troncature: %s", got)
	}
}

func TestAnonymousStats(t *testing.T) {
	l, _ := New(testutil.Keystore(t), t.TempDir(), testutil.Logger())
	ip := netip.MustParseAddr("10.0.0.5")
	l.Configure(ModeNone, "pseudonymize", 7)
	l.Record(Entry{Time: time.Now(), Name: "ads.example.", Type: "A", Status: StatusBlocked, Rcode: "NOERROR", Proto: "udp", Source: "HaGeZi, groupe Enfants", Group: "Enfants", Millis: 0.4}, ip)
	l.Record(Entry{Time: time.Now(), Name: "ok.example.", Type: "AAAA", Status: StatusAllowed, Rcode: "NOERROR", Proto: "doh", Upstream: "quad9", Millis: 30}, ip)
	l.Record(Entry{Time: time.Now(), Name: "x.example.", Type: "HTTPS", Status: StatusCached, Rcode: "NXDOMAIN", Proto: "dot", Millis: 0.2}, ip)
	s := l.Stats.Snapshot()
	if len(s.QTypes) != 3 || len(s.Protocols) != 3 || len(s.Rcodes) != 2 || len(s.Reasons) != 1 || s.Reasons[0].Key != "HaGeZi" {
		t.Fatalf("compteurs anonymes attendus même sans journal: %+v", s)
	}
	if len(s.Groups) != 0 || len(s.TopBlocked) != 0 {
		t.Fatalf("le mode none ne garde ni groupe ni domaine: %+v", s)
	}
	if s.Latency.Measured != 3 || s.Latency.Counts[0] != 2 || s.Latency.UpAvgMs != 30 {
		t.Fatalf("latences: %+v", s.Latency)
	}
	if len(s.LastHour) != minuteCount || len(s.Week) != hourCount || s.LastHour[minuteCount-1].Queries != 3 || s.Series[bucketCount-1].Cached != 1 || s.PeakMinute != 3 {
		t.Fatalf("séries: %d %d %+v", len(s.LastHour), len(s.Week), s.LastHour[minuteCount-1])
	}

	l.Configure(ModeStats, "pseudonymize", 7)
	l.Record(Entry{Time: time.Now(), Name: "ads.example.", Type: "A", Status: StatusBlocked, Source: "services bloqués, groupe Enfants", Group: "Enfants"}, ip)
	s = l.Stats.Snapshot()
	if len(s.Groups) != 1 || s.Groups[0].Name != "Enfants" || s.Groups[0].Blocked != 1 {
		t.Fatalf("activité par groupe attendue en mode stats: %+v", s.Groups)
	}
	l.Configure(ModeNone, "pseudonymize", 7)
	if s = l.Stats.Snapshot(); len(s.Groups) != 0 || len(s.TopBlocked) != 0 {
		t.Fatalf("passer en mode none doit effacer groupes et domaines: %+v", s)
	}

	// Des types inventés ne font pas grossir la mémoire.
	for i := 0; i < 500; i++ {
		l.Record(Entry{Time: time.Now(), Name: "a.", Type: "TYPE" + strconv.Itoa(1000+i), Status: StatusAllowed}, ip)
	}
	if s = l.Stats.Snapshot(); len(l.Stats.qtypes) > maxLabels {
		t.Fatalf("étiquettes non bornées: %d", len(l.Stats.qtypes))
	}
}
