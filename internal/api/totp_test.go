package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/rempart-dns/rempart/internal/audit"
	"github.com/rempart-dns/rempart/internal/state"
	"github.com/rempart-dns/rempart/internal/testutil"
)

// Vecteurs de la RFC 6238, annexe B (SHA-1), tronqués à 6 chiffres.
func TestTOTPVectors(t *testing.T) {
	sec := []byte("12345678901234567890")
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		if got := totpCode(sec, ts/30); got != want {
			t.Errorf("T=%d: %s, attendu %s", ts, got, want)
		}
	}
	s := b32.EncodeToString(sec)
	now := time.Unix(1234567890, 0)
	if totpVerify(s, "005924", now, 0) == 0 {
		t.Fatal("code courant refusé")
	}
	if totpVerify(s, "005924", now, 1234567890/30) != 0 {
		t.Fatal("rejeu accepté")
	}
	if totpVerify(s, "000000", now, 0) != 0 {
		t.Fatal("mauvais code accepté")
	}
}

// Écrit un QR code que le test Python de CI décode (voir QR_OUT).
func TestQREncodeSizes(t *testing.T) {
	for _, n := range []int{1, 14, 50, 120, 200} {
		m, err := qrEncode(strings.Repeat("a", n))
		if err != nil || len(m) < 21 {
			t.Fatalf("%d octets: %v", n, err)
		}
	}
	if _, err := qrEncode(strings.Repeat("a", 300)); err == nil {
		t.Fatal("texte trop long accepté")
	}
	if out := os.Getenv("QR_OUT"); out != "" {
		for i, s := range []string{otpURI("admin", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"), "HELLO", strings.Repeat("x", 100), strings.Repeat("0123456789", 21)} {
			m, _ := qrEncode(s)
			_ = os.WriteFile(filepath.Join(out, string(rune('a'+i))+".svg"), []byte(qrSVG(m)), 0o644)
			_ = os.WriteFile(filepath.Join(out, string(rune('a'+i))+".txt"), []byte(s), 0o644)
		}
	}
}

func TestLoginWithOTP(t *testing.T) {
	ks := testutil.Keystore(t)
	dir := t.TempDir()
	const pw = "un-mot-de-passe-solide"
	store, _, _ := state.Open(ks, filepath.Join(dir, "s"), state.State{Admin: state.Admin{Username: "admin", PasswordHash: HashPassword(pw)}})
	al, _ := audit.Open(ks, dir)
	a := &API{Store: store, Audit: al, KS: ks, Web: fstest.MapFS{"index.html": {Data: []byte("ok")}}}
	srv := httptest.NewServer(a.Handler(time.Hour))
	defer srv.Close()

	var ck *http.Cookie
	do := func(method, path, body string, out any) int {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("X-Rempart", "1")
		if ck != nil {
			req.AddCookie(ck)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		for _, c := range res.Cookies() {
			if c.Name == cookieName {
				ck = c
			}
		}
		if out != nil {
			_ = json.NewDecoder(res.Body).Decode(out)
		}
		return res.StatusCode
	}
	login := `{"username":"admin","password":"` + pw + `"}`
	if c := do("POST", "/api/login", login, nil); c != 200 || ck == nil {
		t.Fatalf("login: %d", c)
	}
	var setup struct{ Secret, URI, QR string }
	if c := do("POST", "/api/otp/setup", "", &setup); c != 200 || setup.Secret == "" || !strings.HasPrefix(setup.QR, "data:image/svg+xml;base64,") {
		t.Fatalf("setup: %d %+v", c, setup)
	}
	sec, _ := b32.DecodeString(setup.Secret)
	code := func(off int64) string { return totpCode(sec, time.Now().Unix()/30+off) }
	if c := do("POST", "/api/otp/enable", `{"code":"`+code(0)+`","password":"faux"}`, nil); c != 403 {
		t.Fatalf("activation sans mot de passe: %d", c)
	}
	var en struct{ Recovery []string }
	actStep := time.Now().Unix() / 30
	actCode := totpCode(sec, actStep) // code de l'activation, rejoué plus bas
	if c := do("POST", "/api/otp/enable", `{"code":"`+actCode+`","password":"`+pw+`"}`, &en); c != 200 || len(en.Recovery) != recoveryN {
		t.Fatalf("enable: %d %+v", c, en)
	}
	if strings.Contains(string(mustRead(t, filepath.Join(dir, "s"))), setup.Secret) {
		t.Fatal("le secret TOTP apparaît en clair sur disque")
	}

	// Connexion : le mot de passe seul ne donne pas de session.
	ck = nil
	var step1 struct {
		OTPRequired bool `json:"otp_required"`
		Challenge   string
	}
	if c := do("POST", "/api/login", login, &step1); c != 200 || !step1.OTPRequired || ck != nil {
		t.Fatalf("étape 1: %d %+v cookie=%v", c, step1, ck)
	}
	if c := do("GET", "/api/me", "", nil); c != 401 {
		t.Fatal("session ouverte sans second facteur")
	}
	// Le code qui a servi à l'activation ne peut pas être rejoué.
	if c := do("POST", "/api/login/otp", `{"challenge":"`+step1.Challenge+`","code":"`+actCode+`"}`, nil); c != 401 {
		t.Fatalf("rejeu du code d'activation accepté: %d", c)
	}
	if c := do("POST", "/api/login/otp", `{"challenge":"`+step1.Challenge+`","code":"`+totpCode(sec, actStep+1)+`"}`, nil); c != 200 || ck == nil {
		t.Fatalf("étape 2: %d", c)
	}
	// Code de secours, une seule fois.
	ck = nil
	do("POST", "/api/login", login, &step1)
	var ok struct {
		Method       string
		RecoveryLeft int `json:"recovery_left"`
	}
	if c := do("POST", "/api/login/otp", `{"challenge":"`+step1.Challenge+`","code":"`+strings.ToUpper(en.Recovery[3])+`"}`, &ok); c != 200 || ok.RecoveryLeft != recoveryN-1 {
		t.Fatalf("code de secours: %d %+v", c, ok)
	}
	ck = nil
	do("POST", "/api/login", login, &step1)
	if c := do("POST", "/api/login/otp", `{"challenge":"`+step1.Challenge+`","code":"`+en.Recovery[3]+`"}`, nil); c != 401 {
		t.Fatalf("code de secours réutilisé: %d", c)
	}
	// Défi invalidé après 5 essais.
	for i := 0; i < 4; i++ {
		do("POST", "/api/login/otp", `{"challenge":"`+step1.Challenge+`","code":"000000"}`, nil)
	}
	a.guard.success(netip.MustParseAddr("127.0.0.1")) // isole la limite du défi de celle par adresse
	if c := do("POST", "/api/login/otp", `{"challenge":"`+step1.Challenge+`","code":"`+code(1)+`"}`, nil); c != 401 {
		t.Fatalf("défi encore utilisable après 5 échecs: %d", c)
	}
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
