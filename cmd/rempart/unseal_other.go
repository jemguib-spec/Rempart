// unseal_other.go - hors Linux, le déverrouillage par socket n'est pas proposé.
// Rempart est déployé en conteneur Linux (Podman) : ce fichier ne sert qu'à compiler ailleurs.
// Rempart.

//go:build !linux

package main

import (
	"bufio"
	"errors"
	"net"
	"os"
)

func umask(int) int { return 0 }

func isTerminal(*os.File) bool { return false }

func checkPeer(net.Conn) error { return errors.New("déverrouillage disponible sous Linux seulement") }

func readSecret(*bufio.Reader, string) (string, error) {
	return "", errors.New("déverrouillage disponible sous Linux seulement")
}
