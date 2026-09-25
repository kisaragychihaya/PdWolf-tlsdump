// Package filter decides whether a host is subject to MITM inspection based
// on a whitelist of domain suffixes.
package filter

import (
	"net"
	"strings"
)

// Filter matches hosts against a list of domain entries. An entry matches the
// host itself or any of its sub-domains ("example.com" matches
// "example.com" and "www.example.com").
type Filter struct {
	entries []string
}

// Parse builds a Filter from raw entries. Lines may contain "#" comments and
// empty lines; everything after '#' is dropped.
func Parse(entries []string) *Filter {
	f := &Filter{}
	for _, e := range entries {
		if i := strings.IndexByte(e, '#'); i >= 0 {
			e = e[:i]
		}
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		f.entries = append(f.entries, strings.ToLower(strings.TrimSuffix(e, ".")))
	}
	return f
}

// Match reports whether hostport (host, host:port or [ipv6]:port) is in the
// whitelist. Matching is case-insensitive and ignores a trailing dot.
func (f *Filter) Match(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	} else {
		// SplitHostPort fails for bare hosts and bare IPv6 without brackets.
		if strings.Count(hostport, ":") > 1 {
			host = strings.Trim(hostport, "[]")
		}
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, e := range f.entries {
		if host == e || strings.HasSuffix(host, "."+e) {
			return true
		}
	}
	return false
}

// Len returns the number of effective whitelist entries.
func (f *Filter) Len() int { return len(f.entries) }
