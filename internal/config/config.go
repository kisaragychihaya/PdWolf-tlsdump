// Package config loads tlsdump's YAML configuration file and classifies
// which fields can be applied at runtime (hot reload) versus which require a
// process restart.
package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"time"

	"gopkg.in/yaml.v3"
)

// Config mirrors the command-line flags. Only the fields documented as
// reloadable may change at runtime; everything else is startup-only.
type Config struct {
	Mode               string       `yaml:"mode"`                 // proxy | tun
	Listen             string       `yaml:"listen"`               // proxy listen address
	Domains            []string     `yaml:"domains"`              // reloadable; each entry: domain or list-file path
	Record             string       `yaml:"record"`               // reloadable; JSONL output file ("" = stdout)
	CADir              string       `yaml:"ca_dir"`               // root CA directory
	InsecureSkipVerify bool         `yaml:"insecure_skip_verify"` // reloadable
	BodyLimit          int64        `yaml:"body_limit"`           // reloadable
	Verbose            bool         `yaml:"verbose"`              // reloadable
	Script             ScriptConfig `yaml:"script"`               // startup-only
	Tun                TunConfig    `yaml:"tun"`
}

// ScriptConfig groups the JS rule-engine options; all of them are
// startup-only. Timeout stays a string in YAML so expressions like "5s" work;
// empty, zero or negative durations all fall back to the engine's default.
type ScriptConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`    // script file, resolved relative to the working directory
	Timeout string `yaml:"timeout"` // duration string, e.g. "5s"
}

// TunConfig groups the tun-mode options; all of them are startup-only.
type TunConfig struct {
	Name           string   `yaml:"name"`
	MTU            int      `yaml:"mtu"`
	NoRoute        bool     `yaml:"no_route"`
	PhysicalIface  string   `yaml:"physical_iface"`
	ExcludeDomains []string `yaml:"exclude_domains"`
}

// Load reads and parses the YAML file at path. Unknown field names are
// rejected so typos surface immediately instead of being silently ignored.
func Load(path string) (*Config, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	var cfg Config
	dec := yaml.NewDecoder(fh)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate rejects configurations that cannot start a useful session. It also
// normalizes the script block: a non-empty script.path implies enabled, so
// setting only the path in YAML is enough to turn the rule engine on.
func (c *Config) Validate() error {
	if c.Mode != "" && c.Mode != "proxy" && c.Mode != "tun" {
		return fmt.Errorf("config: invalid mode %q (proxy|tun)", c.Mode)
	}
	if c.BodyLimit < 0 {
		return errors.New("config: body_limit must be >= 0")
	}
	if c.Tun.MTU < 0 {
		return errors.New("config: tun.mtu must be >= 0")
	}
	if !c.Script.Enabled && c.Script.Path != "" {
		c.Script.Enabled = true
	}
	if c.Script.Enabled {
		if c.Script.Path == "" {
			return errors.New("config: script.path is required when script is enabled")
		}
		st, err := os.Stat(c.Script.Path)
		if err != nil {
			return fmt.Errorf("config: script.path: %w", err)
		}
		if st.IsDir() {
			return fmt.Errorf("config: script.path %s is a directory, want a file", c.Script.Path)
		}
		if c.Script.Timeout != "" {
			if _, err := time.ParseDuration(c.Script.Timeout); err != nil {
				return fmt.Errorf("config: script.timeout: %w", err)
			}
		}
	}
	return nil
}

// Reloadable holds the fields that can be swapped at runtime.
type Reloadable struct {
	Domains            []string // nil means "unchanged"
	Record             *string  // nil means "unchanged"
	InsecureSkipVerify *bool
	BodyLimit          *int64
	Verbose            *bool
}

// Any reports whether at least one reloadable field changed.
func (r *Reloadable) Any() bool {
	return r.Domains != nil || r.Record != nil || r.InsecureSkipVerify != nil ||
		r.BodyLimit != nil || r.Verbose != nil
}

// Diff compares old and new configurations: it returns the reloadable
// changes and the names of startup-only fields that changed and will be
// ignored until the next restart.
func Diff(old, new *Config) (Reloadable, []string) {
	var r Reloadable
	if !slices.Equal(old.Domains, new.Domains) {
		r.Domains = new.Domains
	}
	if old.Record != new.Record {
		r.Record = &new.Record
	}
	if old.InsecureSkipVerify != new.InsecureSkipVerify {
		r.InsecureSkipVerify = &new.InsecureSkipVerify
	}
	if old.BodyLimit != new.BodyLimit {
		r.BodyLimit = &new.BodyLimit
	}
	if old.Verbose != new.Verbose {
		r.Verbose = &new.Verbose
	}

	var ignored []string
	if old.Mode != new.Mode {
		ignored = append(ignored, "mode")
	}
	if old.Listen != new.Listen {
		ignored = append(ignored, "listen")
	}
	if old.CADir != new.CADir {
		ignored = append(ignored, "ca_dir")
	}
	if !reflect.DeepEqual(old.Tun, new.Tun) {
		ignored = append(ignored, "tun")
	}
	if old.Script.Enabled != new.Script.Enabled ||
		old.Script.Path != new.Script.Path ||
		old.Script.Timeout != new.Script.Timeout {
		ignored = append(ignored, "script")
	}
	return r, ignored
}
