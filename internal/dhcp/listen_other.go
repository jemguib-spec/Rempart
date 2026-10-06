//go:build !linux

package dhcp

import (
	"errors"
	"net"
)

func listen(string) (net.PacketConn, error) {
	return nil, errors.New("le serveur DHCP n'est disponible que sous Linux")
}
