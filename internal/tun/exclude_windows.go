//go:build windows

package tun

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// addExcludes resolves domains and pins their IPv4 addresses to the physical
// interface via /32 host routes, so matching traffic never enters the tun.
// A /32 prefix always wins over the tun's /1 catch routes. Route additions
// are best-effort; failures are logged, not fatal.
func addExcludes(domains []string, physIface string) (func() error, error) {
	noop := func() error { return nil }
	if len(domains) == 0 || physIface == "" {
		return noop, nil
	}
	gw, err := defaultGateway(physIface)
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

	for _, ip := range ips {
		if err := runNetsh("interface", "ipv4", "add", "route",
			"prefix="+ip+"/32", "interface="+physIface, "nexthop="+gw, "metric=1", "store=active"); err != nil {
			if existsErr(err) {
				slog.Debug("tun: exclude route already present", "ip", ip)
				continue
			}
			slog.Warn("tun: exclude route add failed (run as administrator?)", "ip", ip, "err", err)
			continue
		}
		slog.Info("tun: excluded from capture", "ip", ip, "iface", physIface)
	}

	return func() error {
		var firstErr error
		for _, ip := range ips {
			err := runNetsh("interface", "ipv4", "delete", "route", "prefix="+ip+"/32", "interface="+physIface)
			if err != nil && firstErr == nil && !notFound(err.Error()) {
				firstErr = err
			}
		}
		return firstErr
	}, nil
}

// defaultGateway returns the IPv4 next hop of the default route on iface,
// read directly from the IP helper API (no shelling out).
func defaultGateway(iface string) (string, error) {
	const initialBufSize = 15000
	size := uint32(initialBufSize)
	buf := make([]byte, size)
	for {
		err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_INCLUDE_GATEWAYS, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil || err == windows.ERROR_SUCCESS {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return "", err
		}
		buf = make([]byte, size)
	}
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if a.OperStatus != windows.IfOperStatusUp || a.FriendlyName == nil {
			continue
		}
		if !strings.EqualFold(windows.UTF16PtrToString(a.FriendlyName), iface) {
			continue
		}
		for g := a.FirstGatewayAddress; g != nil; g = g.Next {
			if ip := g.Address.IP(); ip != nil {
				if ip4 := ip.To4(); ip4 != nil {
					return ip4.String(), nil
				}
			}
		}
	}
	return "", fmt.Errorf("no IPv4 gateway on interface %s", iface)
}

func runNetsh(args ...string) error {
	cmd := exec.Command("cmd", append([]string{"/c", "netsh"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %v failed: %v: %s", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
