package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	p := writeTemp(t, `
mode: tun
listen: 127.0.0.1:9090
domains:
  - example.com
  - api.example.com
record: rec.jsonl
ca_dir: /tmp/ca
insecure_skip_verify: true
body_limit: 4096
verbose: true
tun:
  name: tlsdump
  mtu: 1400
  no_route: true
  physical_iface: en0
  exclude_domains:
    - internal.corp
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Mode != "tun" || cfg.Listen != "127.0.0.1:9090" {
		t.Errorf("mode/listen = %q/%q", cfg.Mode, cfg.Listen)
	}
	if len(cfg.Domains) != 2 || cfg.Domains[1] != "api.example.com" {
		t.Errorf("domains = %v", cfg.Domains)
	}
	if cfg.BodyLimit != 4096 || !cfg.InsecureSkipVerify || !cfg.Verbose {
		t.Errorf("scalar fields = %+v", cfg)
	}
	if cfg.Tun.MTU != 1400 || !cfg.Tun.NoRoute || cfg.Tun.PhysicalIface != "en0" {
		t.Errorf("tun = %+v", cfg.Tun)
	}
	if len(cfg.Tun.ExcludeDomains) != 1 || cfg.Tun.ExcludeDomains[0] != "internal.corp" {
		t.Errorf("exclude_domains = %v", cfg.Tun.ExcludeDomains)
	}
}

func TestLoadUnknownFieldRejected(t *testing.T) {
	p := writeTemp(t, "mode: proxy\nbogus_field: 1\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	p := writeTemp(t, "mode: [unclosed\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"empty is fine", Config{}, true},
		{"proxy", Config{Mode: "proxy"}, true},
		{"tun", Config{Mode: "tun"}, true},
		{"bad mode", Config{Mode: "socks"}, false},
		{"negative body limit", Config{BodyLimit: -1}, false},
		{"negative mtu", Config{Tun: TunConfig{MTU: -1}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err == nil) != tc.ok {
				t.Errorf("Validate() = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestDiffClassifiesFields(t *testing.T) {
	old := &Config{
		Mode: "proxy", Listen: "127.0.0.1:8080", CADir: "./ca",
		Domains: []string{"example.com"}, Record: "a.jsonl",
		BodyLimit: 16384,
		Tun:       TunConfig{Name: "tlsdump", MTU: 1420},
	}
	nw := &Config{
		Mode: "tun", Listen: "127.0.0.1:9090", CADir: "/other/ca",
		Domains: []string{"example.org"}, Record: "b.jsonl",
		BodyLimit: 4096, Verbose: true, InsecureSkipVerify: true,
		Tun: TunConfig{Name: "other", MTU: 1400},
	}

	r, ignored := Diff(old, nw)

	if r.Domains == nil || (*r.Record) != "b.jsonl" || *r.BodyLimit != 4096 ||
		r.Verbose == nil || !*r.Verbose || r.InsecureSkipVerify == nil || !*r.InsecureSkipVerify {
		t.Errorf("reloadable = %+v", r)
	}
	if !r.Any() {
		t.Error("Any() should be true")
	}
	wantIgnored := []string{"mode", "listen", "ca_dir", "tun"}
	if len(ignored) != len(wantIgnored) {
		t.Fatalf("ignored = %v, want %v", ignored, wantIgnored)
	}
	for i, f := range wantIgnored {
		if ignored[i] != f {
			t.Errorf("ignored[%d] = %q, want %q", i, ignored[i], f)
		}
	}
}

func TestDiffIdentical(t *testing.T) {
	cfg := &Config{Domains: []string{"example.com"}, Record: "a.jsonl", BodyLimit: 100}
	r, ignored := Diff(cfg, cfg)
	if r.Any() {
		t.Errorf("expected no reloadable changes, got %+v", r)
	}
	if len(ignored) != 0 {
		t.Errorf("expected no ignored fields, got %v", ignored)
	}
}
