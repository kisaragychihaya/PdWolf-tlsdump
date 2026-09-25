//go:build linux

package tun

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	tunIP   = "198.19.0.1"
	tunCIDR = "198.19.0.1/30"
)

// setupRoutes configures the tun interface address and adds two broad default
// routes through it. Requires root (CAP_NET_ADMIN).
func setupRoutes(name string) (func() error, error) {
	run := func(args ...string) error {
		cmd := exec.Command(args[0], args[1:]...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v failed: %v: %s", args, err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	if err := run("ip", "addr", "add", tunCIDR, "dev", name); err != nil {
		return nil, fmt.Errorf("configure %s address (run as root?): %w", name, err)
	}
	if err := run("ip", "link", "set", name, "up"); err != nil {
		return nil, fmt.Errorf("bring up %s (run as root?): %w", name, err)
	}
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := run("ip", "route", "add", cidr, "dev", name); err != nil {
			return nil, fmt.Errorf("add route %s (run as root?): %w", cidr, err)
		}
	}

	cleanup := func() error {
		var firstErr error
		for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			if err := run("ip", "route", "del", cidr); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if err := run("ip", "addr", "del", tunCIDR, "dev", name); err != nil && firstErr == nil {
			firstErr = err
		}
		return firstErr
	}
	return cleanup, nil
}

// notFound reports whether a delete failure just means the entry was
// already absent (locale-tolerant keyword match).
func notFound(msg string) bool {
	m := strings.ToLower(msg)
	for _, kw := range []string{
		"not find", "not found", "not exist", "no such",
		"cannot assign", "element not found",
		"找不到", "不存在",
	} {
		if strings.Contains(m, kw) {
			return true
		}
	}
	return false
}

// Reset removes routes and address configuration a tun session may have left
// behind after an ungraceful exit. Best-effort: already-absent entries are not
// errors.
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
		if err := run("ip", "route", "del", cidr, "dev", name); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := run("ip", "addr", "del", tunCIDR, "dev", name); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// defaultRouteInterface finds the interface that owns the default route by
// reading /proc/net/route, skipping tun devices.
func defaultRouteInterface(tunName string) string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[1] != "00000000" {
			continue
		}
		iface := fields[0]
		if iface == tunName || strings.HasPrefix(iface, "tun") || strings.HasPrefix(iface, "wg") {
			continue
		}
		return iface
	}
	return ""
}
