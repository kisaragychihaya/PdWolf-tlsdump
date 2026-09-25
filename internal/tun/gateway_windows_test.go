//go:build windows

package tun

import "testing"

func TestDefaultGateway(t *testing.T) {
	gw, err := defaultGateway("WLAN")
	if err != nil {
		t.Fatalf("defaultGateway(WLAN): %v", err)
	}
	t.Logf("WLAN gateway = %s", gw)
	if gw == "" {
		t.Fatal("empty gateway")
	}
}
