//go:build darwin

package tun

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
)

// addExcludes resolves domains and pins their IPv4 addresses to the physical
// interface via host routes through the default gateway, so matching traffic
// never enters the tun. A /32 prefix always wins over the tun's /1 catch
// routes. Route additions are best-effort; failures are logged, not fatal.
func addExcludes(domains []string, physIface string) (func() error, error) {
	noop := func() error { return nil }
	if len(domains) == 0 || physIface == "" {
		return noop, nil
	}
	gw, err := interfaceGateway(physIface)
	if err != nil {
		return nil, fmt.Errorf("tun: find gateway of %s: %w", physIface, err)
	}

	seen := map[string]bool{}
	var ips []string
	for _, d := range domains {
		addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), d)
		if err != nil {
			slog.Warn("tun: exclude domain resolve failed", "domain", d, "err", err)
			continue
		}
		for _, a := range addrs {
			ip4 := a.IP.To4()
			if ip4 == nil {
				continue
			}
			ip := ip4.String()
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		return noop, nil
	}

	run := func(args ...string) error {
		cmd := exec.Command(args[0], args[1:]...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v failed: %v: %s", args, err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	for _, ip := range ips {
		if err := run("route", "-n", "add", "-host", ip, gw); err != nil {
			slog.Warn("tun: exclude route add failed (run as root?)", "ip", ip, "err", err)
			continue
		}
		slog.Info("tun: excluded from capture", "ip", ip, "iface", physIface)
	}

	return func() error {
		var firstErr error
		for _, ip := range ips {
			err := run("route", "-n", "delete", "-host", ip)
			if err != nil && firstErr == nil && !notFound(err.Error()) {
				firstErr = err
			}
		}
		return firstErr
	}, nil
}

// interfaceGateway reads the IPv4 default gateway from the system routing
// table via `route -n get default`.
func interfaceGateway(iface string) (string, error) {
	out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("route get default: %v: %s", err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "gateway:" {
			return fields[1], nil
		}
	}
	return "", fmt.Errorf("no default gateway for %s", iface)
}
