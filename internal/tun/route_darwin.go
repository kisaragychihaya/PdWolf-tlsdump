//go:build darwin

package tun

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

const (
	tunIP   = "198.19.0.1"
	tunPeer = "198.19.0.1"
)

// setupRoutes configures the utun interface address and adds two broad
// default routes through it. Requires root.
func setupRoutes(name string) (func() error, error) {
	run := func(args ...string) error {
		cmd := exec.Command(args[0], args[1:]...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v failed: %v: %s", args, err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	// utun is point-to-point; using our own address as the destination is the
	// conventional macOS configuration.
	if err := run("ifconfig", name, "inet", tunIP, tunPeer, "up"); err != nil {
		return nil, fmt.Errorf("configure %s address (run as root?): %w", name, err)
	}
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := run("route", "-n", "add", "-net", cidr, "-interface", name); err != nil {
			cleanupRoutes(run, name)
			return nil, fmt.Errorf("add route %s (run as root?): %w", cidr, err)
		}
	}

	return func() error { return cleanupRoutes(run, name) }, nil
}

func cleanupRoutes(run func(...string) error, name string) error {
	var firstErr error
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := run("route", "-n", "delete", "-net", cidr, "-interface", name); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// notFound reports whether a delete failure just means the entry was already
// absent. macOS says "not in table".
func notFound(msg string) bool {
	m := strings.ToLower(msg)
	for _, kw := range []string{
		"not in table", "not found", "no such",
	} {
		if strings.Contains(m, kw) {
			return true
		}
	}
	return false
}

// Reset removes routes a tun session may have left behind after an
// ungraceful exit. Best-effort: already-absent entries are not errors. The
// routes are matched without -interface because the configured device name
// ("tlsdump") differs from the actual utunN the kernel assigned.
func Reset(name string) error {
	run := func(args ...string) error {
		cmd := exec.Command(args[0], args[1:]...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if notFound(msg) {
				return nil
			}
			return fmt.Errorf("%v failed: %v: %s", args, err, msg)
		}
		return nil
	}

	var firstErr error
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := run("route", "-n", "delete", "-net", cidr); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// defaultRouteInterface returns the name of the physical interface that owns
// the system default route, skipping the tun device itself.
func defaultRouteInterface(tunName string) string {
	out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "interface:" {
				iface := fields[1]
				if iface != tunName && !strings.HasPrefix(iface, "utun") {
					return iface
				}
			}
		}
	}
	// Fallback: first up, non-loopback, non-utun interface with an IPv4 addr.
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Name == tunName || strings.HasPrefix(iface.Name, "utun") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		for _, addr := range addrs {
			if ip, _, err := net.ParseCIDR(addr.String()); err == nil && ip.To4() != nil {
				return iface.Name
			}
		}
	}
	return ""
}
