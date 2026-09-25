//go:build linux

package tun

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
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
		if err := run("ip", "route", "add", ip+"/32", "via", gw, "dev", physIface); err != nil {
			slog.Warn("tun: exclude route add failed (run as root?)", "ip", ip, "err", err)
			continue
		}
		slog.Info("tun: excluded from capture", "ip", ip, "iface", physIface)
	}

	return func() error {
		var firstErr error
		for _, ip := range ips {
			err := run("ip", "route", "del", ip+"/32")
			if err != nil && firstErr == nil && !notFound(err.Error()) {
				firstErr = err
			}
		}
		return firstErr
	}, nil
}

// interfaceGateway reads the IPv4 default-gateway of iface from the kernel
// routing table.
func interfaceGateway(iface string) (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || fields[0] != iface || fields[1] != "00000000" {
			continue
		}
		gw := binary.LittleEndian.Uint32(mustHex(fields[2]))
		return net.IP(binary.BigEndian.AppendUint32(nil, gw)).String(), nil
	}
	return "", fmt.Errorf("no default gateway for %s", iface)
}

func mustHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		fmt.Sscanf(s[2*i:2*i+2], "%02x", &b[i])
	}
	return b
}
