//go:build !windows && !linux

package tun

import (
	"errors"
	"net"
	"time"
)

func setupRoutes(name string) (func() error, error) {
	return nil, errors.New("tun: system route setup is not supported on this platform")
}

// Reset is a no-op on unsupported platforms.
func Reset(name string) error { return nil }

// defaultRouteInterface is unsupported on this platform.
func defaultRouteInterface(tunName string) string { return "" }

// newBoundDialer is unsupported on this platform; outbound binding is a
// no-op, which may cause routing loops in tun mode.
func newBoundDialer(ifaceName string) *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second}
}
