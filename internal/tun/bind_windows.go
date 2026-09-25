//go:build windows

package tun

import (
	"log/slog"
	"net"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// ipUnicastIf is IP_UNICAST_IF / IPV6_UNICAST_IF. IP_UNICAST_IF expects the
// interface index in network byte order; IPV6_UNICAST_IF wants host order.
// https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
const ipUnicastIf = 31

// newBoundDialer returns a dialer whose sockets are pinned to the physical
// interface (IP_UNICAST_IF) so outbound traffic does not loop back into the
// tun device. Falls back to a plain dialer when iface is empty or the lookup
// fails.
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
			h := windows.Handle(fd)
			if strings.HasSuffix(network, "6") {
				sockErr = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipUnicastIf, idx)
			} else {
				sockErr = windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIf, int(htonl(uint32(idx))))
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

func htonl(x uint32) uint32 {
	return x<<24 | (x&0xff00)<<8 | (x>>8)&0xff00 | x>>24
}
