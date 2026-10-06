// modules_other.go - contrôle du propriétaire d'un module PKCS#11 (hors Unix, sans effet).
// Aucun contrôle possible via syscall.Stat_t.
// Rempart ; build !unix.

//go:build !unix

package keystore

import "os"

func ownedByRoot(os.FileInfo) error { return nil }
