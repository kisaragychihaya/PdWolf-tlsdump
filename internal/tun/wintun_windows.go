package tun

import (
	"crypto/md5"
	_ "embed"
	"log/slog"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

//go:embed wintun.dll
var wintunDLL []byte

// preparePlatform extracts the embedded wintun.dll next to the executable and
// pins a deterministic adapter GUID derived from the interface name, so the
// same adapter is reused across runs instead of accumulating orphans.
func preparePlatform(name string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	p := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if _, err := os.Stat(p); err != nil {
		slog.Info("extracting embedded wintun.dll", "path", p)
		if err := os.WriteFile(p, wintunDLL, 0o644); err != nil {
			return err
		}
	}

	sum := md5.Sum(append([]byte("wintun"), []byte(name)...))
	tun.WintunStaticRequestedGUID = (*windows.GUID)(unsafe.Pointer(&sum[0]))
	return nil
}
