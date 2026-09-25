//go:build linux

package tun

import (
	"log/slog"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// newBoundDialer returns a dialer whose sockets are bound to the physical
// interface (SO_BINDTODEVICE) so outbound traffic does not loop back into the
// tun device. Falls back to a plain dialer when iface is empty.
func newBoundDialer(iface string) *net.Dialer {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if iface == "" {
		slog.Warn("tun: could not detect physical interface, outbound binding disabled (risk of routing loop)")
		return d
	}
	d.Control = func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return sockErr
	}
	slog.Info("tun: outbound connections bound to interface", "iface", iface)
	return d
}
