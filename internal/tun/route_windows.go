//go:build windows

package tun

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

const (
	tunIP      = "198.19.0.1"
	tunNetmask = "255.255.255.252"
)

// setupRoutes configures the wintun adapter address and adds two broad
// default routes through it. Requires administrator privileges.
func setupRoutes(name string) (func() error, error) {
	run := func(args ...string) error {
		cmd := exec.Command("cmd", append([]string{"/c"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v failed: %v: %s", args, err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	if err := run("netsh", "interface", "ipv4", "set", "address", name, "static", tunIP, tunNetmask, "store=active"); err != nil {
		return nil, fmt.Errorf("configure %s address (run as administrator?): %w", name, err)
	}

	// On-link routes via netsh: route.exe's "if <idx>" form is unreliable on
	// wintun adapters. store=active keeps routes from surviving a reboot.
	routes := [][2]string{{"0.0.0.0", "1"}, {"128.0.0.0", "1"}}
	for _, r := range routes {
		prefix := r[0] + "/" + r[1]
		if err := run("netsh", "interface", "ipv4", "add", "route", "prefix="+prefix, "interface="+name, "store=active"); err != nil {
			cleanupRoutes(run, name, routes)
			return nil, fmt.Errorf("add route %s (run as administrator?): %w", prefix, err)
		}
	}

	cleanup := func() error { return cleanupRoutes(run, name, routes) }
	// Stale negative/fake DNS entries (e.g. from a previously running TUN
	// tool) must not outlive route setup.
	_ = exec.Command("ipconfig", "/flushdns").Run()
	return cleanup, nil
}

func cleanupRoutes(run func(...string) error, name string, routes [][2]string) error {
	var firstErr error
	for _, r := range routes {
		prefix := r[0] + "/" + r[1]
		if err := run("netsh", "interface", "ipv4", "delete", "route", "prefix="+prefix, "interface="+name); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
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

// existsErr reports whether an add failure just means the route already
// exists (locale-tolerant keyword match).
func existsErr(err error) bool {
	m := strings.ToLower(err.Error())
	for _, kw := range []string{
		"already exists", "object already exists", "already present",
		"已存在",
	} {
		if strings.Contains(m, kw) {
			return true
		}
	}
	return false
}

// Reset removes routes and address configuration a tun session may have left
// behind after an ungraceful exit. Best-effort: already-absent entries are not
// errors; failures are logged per command.
func Reset(name string) error {
	run := func(args ...string) error {
		cmd := exec.Command("cmd", append([]string{"/c"}, args...)...)
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
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := run("netsh", "interface", "ipv4", "delete", "route", "prefix="+prefix, "interface="+name); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := run("netsh", "interface", "ipv4", "delete", "address", name, tunIP); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// defaultRouteInterface returns the name of the physical interface that owns
// the system default route, skipping the tun device itself.
func defaultRouteInterface(tunName string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Name == tunName || strings.Contains(strings.ToLower(iface.Name), "wintun") {
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
