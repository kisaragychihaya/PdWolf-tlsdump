//go:build darwin

package tun

// preparePlatform is a no-op on macOS: utun devices are provided by the
// kernel, so there is no driver DLL to bundle.
func preparePlatform(name string) error { return nil }

// tunCreateName maps the configured device name to one the macOS utun
// backend accepts: CreateTUN only allows "utun" or "utunN", and a bare
// "utun" lets the kernel assign the first free unit (returned by dev.Name()).
func tunCreateName(name string) string { return "utun" }
