//go:build !windows && !linux && !darwin

package tun

// addExcludes is a no-op on unsupported platforms.
func addExcludes(domains []string, physIface string) (func() error, error) {
	return func() error { return nil }, nil
}
