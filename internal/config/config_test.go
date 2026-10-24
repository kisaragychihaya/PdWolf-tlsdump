package config

import (
	"fmt"
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

// writeTempFile creates content under a fresh temp dir and returns its path.
func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadScriptBlock(t *testing.T) {
	js := writeTempFile(t, "rules.js", "var rules = [];\n")
	// Single quotes keep Windows backslashes literal in YAML.
	p := writeTemp(t, fmt.Sprintf(`
domains:
  - example.com
script:
  path: '%s'
  timeout: 250ms
`, js))
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Script.Enabled {
		t.Error("script.enabled should be auto-enabled when path is set")
	}
	if cfg.Script.Path != js || cfg.Script.Timeout != "250ms" {
		t.Errorf("script = %+v", cfg.Script)
	}
}

func TestValidateScript(t *testing.T) {
	js := writeTempFile(t, "rules.js", "var rules = [];\n")
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.js")

	cases := []struct {
		name   string
		script ScriptConfig
		ok     bool
	}{
		{"disabled and no path", ScriptConfig{}, true},
		{"enabled with existing file", ScriptConfig{Enabled: true, Path: js}, true},
		{"enabled with timeout", ScriptConfig{Enabled: true, Path: js, Timeout: "2s"}, true},
		{"path only auto-enables", ScriptConfig{Path: js}, true},
		{"path only with bad timeout", ScriptConfig{Path: js, Timeout: "soon"}, false},
		{"enabled without path", ScriptConfig{Enabled: true}, false},
		{"enabled with missing file", ScriptConfig{Enabled: true, Path: missing}, false},
		{"enabled with directory", ScriptConfig{Enabled: true, Path: dir}, false},
		{"bad timeout", ScriptConfig{Enabled: true, Path: js, Timeout: "5"}, false},
		{"negative timeout parses", ScriptConfig{Enabled: true, Path: js, Timeout: "-1s"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Script: tc.script}
			err := cfg.Validate()
			if (err == nil) != tc.ok {
				t.Fatalf("Validate() = %v, want ok=%v", err, tc.ok)
			}
			if err == nil && tc.script.Path != "" && !cfg.Script.Enabled {
				t.Error("Validate() should auto-enable script when path is set")
			}
		})
	}
}

func TestDiffScriptIsStartupOnly(t *testing.T) {
	base := ScriptConfig{Enabled: true, Path: "a.js", Timeout: "5s"}
	cases := []struct {
		name string
		nw   ScriptConfig
		want bool // script expected in ignored
	}{
		{"unchanged", base, false},
		{"enabled toggled", ScriptConfig{Enabled: false, Path: "a.js", Timeout: "5s"}, true},
		{"path changed", ScriptConfig{Enabled: true, Path: "b.js", Timeout: "5s"}, true},
		{"timeout changed", ScriptConfig{Enabled: true, Path: "a.js", Timeout: "10s"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, ignored := Diff(&Config{Script: base}, &Config{Script: tc.nw})
			if r.Any() {
				t.Errorf("script changes must not be reloadable, got %+v", r)
			}
			if got := len(ignored) > 0; got != tc.want {
				t.Fatalf("ignored = %v, want script reported=%v", ignored, tc.want)
			}
			if tc.want && (len(ignored) != 1 || ignored[0] != "script") {
				t.Errorf("ignored = %v, want [script]", ignored)
			}
		})
	}
}
