// modules_unix.go - contrôle du propriétaire d'un module PKCS#11 (Unix).
// Refuse un module qui n'appartient pas à root.
// Rempart ; build unix.

//go:build unix

package keystore

import (
	"errors"
	"os"
	"syscall"
)

// ownedByRoot : un module appartenant à un autre utilisateur (celui de
// Rempart, par exemple) pourrait être remplacé par ce dernier.
func ownedByRoot(fi os.FileInfo) error {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		return errors.New("le module doit appartenir à root")
	}
	return nil
}
