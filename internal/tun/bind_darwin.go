//go:build darwin

package tun

import (
	"log/slog"
	"net"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// newBoundDialer returns a dialer whose sockets are pinned to the physical
// interface (IP_BOUND_IF) so outbound traffic does not loop back into the tun
// device. Unlike Windows' IP_UNICAST_IF, macOS expects the interface index in
// host byte order. Falls back to a plain dialer when iface is empty or the
// lookup fails.
func newBoundDialer(ifaceName string) *net.Dialer {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if ifaceName == "" {
		slog.Warn("tun: could not detect physical interface, outbound binding disabled (risk of routing loop)")
		return d
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		slog.Warn("tun: physical interface lookup failed, outbound binding disabled", "iface", ifaceName, "err", err)
		return d
	}
	idx := iface.Index
	d.Control = func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, idx)
			} else {
				sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, idx)
			}
		})
		if err != nil {
			return err
		}
		return sockErr
	}
	slog.Info("tun: outbound connections bound to interface", "iface", ifaceName, "index", idx)
	return d
}
