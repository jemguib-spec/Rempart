// Package testutil provides helpers shared by tests.
package testutil

import (
	"io"
	"log/slog"
	"testing"

	"github.com/rempart-dns/rempart/internal/keystore"
)

// Logger discards logs.
func Logger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// Keystore returns a software keystore in a temporary directory.
func Keystore(t testing.TB) keystore.Keystore {
	t.Helper()
	ks, _, err := keystore.OpenSoftware(t.TempDir(), "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ks.Close() })
	return ks
}
