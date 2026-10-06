//go:build !cgo

package keystore

import "errors"

// PKCS11Available reports whether this binary was built with HSM support.
// PKCS#11 needs cgo to load the vendor library: build with CGO_ENABLED=1.
const PKCS11Available = false

// PKCS11Config configures the HSM backend.
type PKCS11Config struct {
	Module     string
	TokenLabel string
	PIN        string
	KEKLabel   string
}

// OpenPKCS11 is unavailable in builds without cgo.
func OpenPKCS11(PKCS11Config) (Keystore, error) {
	return nil, errors.New("ce binaire a été compilé sans support HSM (CGO_ENABLED=0) ; utilisez l'image Docker officielle ou recompilez avec CGO_ENABLED=1")
}

var errNoCgo = errors.New("ce binaire a été compilé sans support HSM (CGO_ENABLED=0)")

// MigrateKeys est indisponible sans cgo.
func MigrateKeys(*Software, Keystore) ([]string, error) { return nil, errNoCgo }

// ProbeModule est indisponible sans cgo.
func ProbeModule(string) (ModuleInfo, []TokenInfo, error) { return ModuleInfo{}, nil, errNoCgo }

// TestToken est indisponible sans cgo.
func TestToken(string, string, []byte, bool) (TestReport, error) { return TestReport{}, errNoCgo }

// CloneCheck : résultat du contrôle d'une clé.
type CloneCheck struct {
	Label string `json:"label"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// CloneReport : résultat de VerifyClone.
type CloneReport struct {
	Token string       `json:"token"`
	Keys  []CloneCheck `json:"keys"`
	KEK   CloneCheck   `json:"kek"`
	OK    bool         `json:"ok"`
}

// VerifyClone est indisponible sans cgo.
func VerifyClone(Keystore, PKCS11Config, [][2][]byte) (CloneReport, error) {
	return CloneReport{}, errNoCgo
}
