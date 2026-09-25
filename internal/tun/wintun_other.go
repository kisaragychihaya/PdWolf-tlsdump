//go:build !windows

package tun

// preparePlatform is a no-op on non-Windows platforms: Linux TUN devices are
// provided by the kernel, so there is no driver DLL to bundle.
func preparePlatform(name string) error { return nil }
