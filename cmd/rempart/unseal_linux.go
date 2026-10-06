// unseal_linux.go - primitives Linux du déverrouillage : umask, identité du pair, saisie sans écho.
// SO_PEERCRED garantit que seul l'utilisateur de Rempart (ou root) parle au socket.
// Rempart ; golang.org/x/sys/unix (déjà vendorisé).

//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func umask(m int) int { return syscall.Umask(m) }

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

func checkPeer(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return errors.New("connexion non Unix")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	if int(cred.Uid) != os.Getuid() && cred.Uid != 0 {
		return fmt.Errorf("uid %d refusé", cred.Uid)
	}
	return nil
}

// readSecret lit une ligne sans écho quand l'entrée est un terminal. Hors
// terminal (fichier 0600 redirigé), la ligne est lue telle quelle.
func readSecret(in *bufio.Reader, prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err == nil {
		fmt.Print(prompt)
		noEcho := *t
		noEcho.Lflag &^= unix.ECHO
		if err := unix.IoctlSetTermios(fd, unix.TCSETS, &noEcho); err != nil {
			return "", err
		}
		defer func() {
			_ = unix.IoctlSetTermios(fd, unix.TCSETS, t)
			fmt.Println()
		}()
	}
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("phrase de passe non saisie")
	}
	return strings.TrimRight(line, "\r\n"), nil
}
