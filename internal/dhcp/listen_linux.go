//go:build linux

package dhcp

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// listen ouvre le port 67 lié à une seule interface (SO_BINDTODEVICE) : les
// réponses en diffusion partent sur ce réseau et pas sur les autres.
func listen(iface string) (net.PacketConn, error) {
	if _, err := net.InterfaceByName(iface); err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1); serr != nil {
				return
			}
			serr = unix.BindToDevice(int(fd), iface)
		})
		if err != nil {
			return err
		}
		return serr
	}}
	return lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:67")
}
