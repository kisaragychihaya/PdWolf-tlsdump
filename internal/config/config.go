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

	"gopkg.in/yaml.v3"
)

// Config mirrors the command-line flags. Only the fields documented as
// reloadable may change at runtime; everything else is startup-only.
type Config struct {
	Mode               string    `yaml:"mode"`                 // proxy | tun
	Listen             string    `yaml:"listen"`               // proxy listen address
	Domains            []string  `yaml:"domains"`              // reloadable; each entry: domain or list-file path
	Record             string    `yaml:"record"`               // reloadable; JSONL output file ("" = stdout)
	CADir              string    `yaml:"ca_dir"`               // root CA directory
	InsecureSkipVerify bool      `yaml:"insecure_skip_verify"` // reloadable
	BodyLimit          int64     `yaml:"body_limit"`           // reloadable
	Verbose            bool      `yaml:"verbose"`              // reloadable
	Tun                TunConfig `yaml:"tun"`
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

// Validate rejects configurations that cannot start a useful session.
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
	return r, ignored
}
