// Command tlsdump decrypts HTTPS traffic for whitelisted domains and records
// it as JSONL; everything else is forwarded untouched.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"tlsdump/internal/certmgr"
	"tlsdump/internal/config"
	"tlsdump/internal/filter"
	"tlsdump/internal/mitm"
	"tlsdump/internal/proxy"
	"tlsdump/internal/record"
	"tlsdump/internal/tun"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "tlsdump:", err)
		os.Exit(1)
	}
}

// options holds the fully resolved runtime parameters after merging defaults,
// the YAML config file, and explicitly set command-line flags.
type options struct {
	mode             string
	listen           string
	domains          []string
	record           string
	caDir            string
	insecure         bool
	bodyLimit        int64
	verbose          bool
	tunName          string
	tunMTU           int
	tunNoRoute       bool
	tunPhysicalIface string
	tunExclude       []string
}

func run() error {
	var (
		configPath       = flag.String("config", "", "YAML config file; when set, the file is watched and reloadable fields are hot-applied")
		mode             = flag.String("mode", "proxy", "proxy | tun")
		listen           = flag.String("listen", "127.0.0.1:8080", "proxy listen address")
		domains          = flag.String("domains", "", "comma-separated domains, or path to a domain list file (# comments allowed)")
		recordPath       = flag.String("record", "", "JSONL output file (default stdout)")
		caDir            = flag.String("ca-dir", "./ca", "CA certificate directory")
		insecure         = flag.Bool("insecure-skip-verify", false, "skip upstream TLS verification (pinning/self-signed upstreams)")
		bodyLimit        = flag.Int64("body-limit", 16384, "max body bytes recorded per request/response")
		tunName          = flag.String("tun-name", "tlsdump", "tun interface name")
		tunMTU           = flag.Int("tun-mtu", 1420, "tun interface MTU")
		tunNoRoute       = flag.Bool("tun-no-route", false, "do not modify system routes (manual debugging)")
		tunReset         = flag.Bool("tun-reset", false, "remove tun routes/address left by a previous run, then exit")
		tunPhysicalIface = flag.String("tun-physical-iface", "", "physical interface for outbound traffic (default auto-detect)")
		tunExclude       = flag.String("tun-exclude-domains", "", "extra domains whose traffic bypasses the tun entirely (comma-separated or file path)")
		verbose          = flag.Bool("v", false, "debug logging")
	)
	flag.Parse()

	// The YAML file is loaded first; explicitly set flags take precedence over
	// it, which in turn overrides flag defaults.
	fileCfg := &config.Config{}
	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		fileCfg = cfg
	}
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	pickStr := func(name, flagVal, yamlVal string) string {
		if explicit[name] || yamlVal == "" {
			return flagVal
		}
		return yamlVal
	}
	pickBool := func(name string, flagVal, yamlVal bool) bool {
		if explicit[name] {
			return flagVal
		}
		return flagVal || yamlVal // all bool defaults are false
	}
	pickInt64 := func(name string, flagVal, yamlVal int64) int64 {
		if explicit[name] || yamlVal <= 0 {
			return flagVal
		}
		return yamlVal
	}
	pickInt := func(name string, flagVal, yamlVal int) int {
		if explicit[name] || yamlVal <= 0 {
			return flagVal
		}
		return yamlVal
	}
	pickList := func(name, flagSpec string, yamlList []string) []string {
		if explicit[name] || yamlList == nil {
			return loadDomainEntries(flagSpec)
		}
		return expandDomainList(yamlList)
	}

	opts := options{
		mode:             pickStr("mode", *mode, fileCfg.Mode),
		listen:           pickStr("listen", *listen, fileCfg.Listen),
		domains:          pickList("domains", *domains, fileCfg.Domains),
		record:           pickStr("record", *recordPath, fileCfg.Record),
		caDir:            pickStr("ca-dir", *caDir, fileCfg.CADir),
		insecure:         pickBool("insecure-skip-verify", *insecure, fileCfg.InsecureSkipVerify),
		bodyLimit:        pickInt64("body-limit", *bodyLimit, fileCfg.BodyLimit),
		verbose:          pickBool("v", *verbose, fileCfg.Verbose),
		tunName:          pickStr("tun-name", *tunName, fileCfg.Tun.Name),
		tunMTU:           pickInt("tun-mtu", *tunMTU, fileCfg.Tun.MTU),
		tunNoRoute:       pickBool("tun-no-route", *tunNoRoute, fileCfg.Tun.NoRoute),
		tunPhysicalIface: pickStr("tun-physical-iface", *tunPhysicalIface, fileCfg.Tun.PhysicalIface),
		tunExclude:       pickList("tun-exclude-domains", *tunExclude, fileCfg.Tun.ExcludeDomains),
	}

	setLogLevel(opts.verbose)

	if *tunReset {
		slog.Info("resetting tun configuration", "name", opts.tunName)
		if err := tun.Reset(opts.tunName); err != nil {
			return fmt.Errorf("tun reset (run as administrator/root?): %w", err)
		}
		slog.Info("tun reset done", "name", opts.tunName)
		return nil
	}

	if len(opts.domains) == 0 {
		return fmt.Errorf("no domains given; use -domains or domains in the config file")
	}
	f := filter.Parse(opts.domains)

	ca, err := certmgr.LoadOrCreate(opts.caDir)
	if err != nil {
		return err
	}
	slog.Info("CA ready", "dir", opts.caDir)

	handler := &mitm.Handler{
		CertMgr:     ca,
		DialTimeout: 10 * time.Second,
	}

	// Runtime state shared with the config watcher. Every opened record file
	// is tracked and closed at shutdown; replaced files stay open until then
	// so in-flight Log calls cannot race a Close.
	rec, recFile, err := openLogger(opts.record, opts.bodyLimit)
	if err != nil {
		return err
	}
	cur := &runtimeState{filter: f, logger: rec, bodyLimit: opts.bodyLimit, insecure: opts.insecure, record: opts.record}
	if recFile != nil {
		cur.files = append(cur.files, recFile)
	}
	defer cur.closeFiles()
	cur.apply(handler)
	slog.Info("runtime config applied", "domains", f.Len(), "record", displayPath(opts.record), "body_limit", opts.bodyLimit)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *configPath != "" {
		config.Watch(ctx, *configPath, 2*time.Second, func(newCfg *config.Config) {
			// An absent (zero) body_limit in the file means "unset": keep the
			// previous value so removing the field doesn't silently zero it.
			if newCfg.BodyLimit <= 0 {
				newCfg.BodyLimit = fileCfg.BodyLimit
			}
			reload, ignored := config.Diff(fileCfg, newCfg)
			fileCfg = newCfg
			if len(ignored) > 0 {
				slog.Warn("config: changed fields require restart, ignored", "fields", ignored)
			}
			if !reload.Any() {
				return
			}
			if err := cur.applyReload(handler, reload); err != nil {
				slog.Error("config: reload failed, keeping previous values", "err", err)
				return
			}
			slog.Info("config reloaded",
				"domains", cur.filter.Len(), "record", displayPath(cur.record),
				"body_limit", cur.bodyLimit, "insecure", cur.insecure)
		})
	}

	switch opts.mode {
	case "proxy":
		s := &proxy.Server{Addr: opts.listen, H: handler}
		slog.Info("starting proxy mode", "listen", opts.listen, "domains", f.Len())
		if err := s.ListenAndServe(ctx); err != nil {
			return err
		}
	case "tun":
		slog.Info("starting tun mode", "name", opts.tunName)
		if err := tun.Run(ctx, tun.Config{
			Name:           opts.tunName,
			MTU:            opts.tunMTU,
			Handler:        handler,
			NoRoute:        opts.tunNoRoute,
			PhysicalIface:  opts.tunPhysicalIface,
			ExcludeDomains: opts.tunExclude,
		}); err != nil && ctx.Err() == nil {
			return err
		}
	default:
		return fmt.Errorf("unknown mode %q (proxy|tun)", opts.mode)
	}
	slog.Info("tlsdump stopped")
	return nil
}

// runtimeState is the hot-reloadable subset of the runtime configuration.
type runtimeState struct {
	mu        sync.Mutex
	filter    *filter.Filter
	logger    *record.Logger
	bodyLimit int64
	insecure  bool
	record    string
	files     []*os.File // every record file ever opened; closed at shutdown
}

// apply pushes the current state into the handler.
func (s *runtimeState) apply(h *mitm.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h.SetRuntime(s.filter, s.logger, s.bodyLimit, s.insecure)
}

// closeFiles closes all record files opened over the process lifetime.
func (s *runtimeState) closeFiles() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, fh := range s.files {
		fh.Close()
	}
}

// applyReload applies a reloadable diff, swapping the handler's runtime
// configuration atomically. A replaced record file stays open until shutdown
// (it is already tracked in s.files).
func (s *runtimeState) applyReload(h *mitm.Handler, r config.Reloadable) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if r.Verbose != nil {
		setLogLevel(*r.Verbose)
	}
	if r.Domains != nil {
		nf := filter.Parse(expandDomainList(r.Domains))
		if nf.Len() == 0 {
			return errors.New("domains must not be empty")
		}
		s.filter = nf
	}
	if r.Record != nil && *r.Record != s.record {
		nl, fh, err := openLogger(*r.Record, s.bodyLimit)
		if err != nil {
			return err
		}
		if fh != nil {
			s.files = append(s.files, fh)
		}
		s.logger = nl
		s.record = *r.Record
	}
	if r.BodyLimit != nil {
		s.bodyLimit = *r.BodyLimit
	}
	if r.InsecureSkipVerify != nil {
		s.insecure = *r.InsecureSkipVerify
	}
	h.SetRuntime(s.filter, s.logger, s.bodyLimit, s.insecure)
	return nil
}

// openLogger returns a record.Logger writing to path ("" means stdout) and
// the underlying file handle when one was opened.
func openLogger(path string, bodyLimit int64) (*record.Logger, *os.File, error) {
	if path == "" {
		return record.New(os.Stdout, bodyLimit), nil, nil
	}
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("open record file: %w", err)
	}
	return record.New(fh, bodyLimit), fh, nil
}

func setLogLevel(verbose bool) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
}

func displayPath(p string) string {
	if p == "" {
		return "stdout"
	}
	return p
}

// loadDomainEntries expands -domains: a value pointing to an existing file is
// read line by line; otherwise the value is split on commas.
func loadDomainEntries(spec string) []string {
	if spec == "" {
		return nil
	}
	if st, err := os.Stat(spec); err == nil && !st.IsDir() {
		data, err := os.ReadFile(spec)
		if err != nil {
			slog.Warn("read domains file failed, treating as literal", "path", spec, "err", err)
			return strings.Split(spec, ",")
		}
		var lines []string
		for _, ln := range strings.Split(string(data), "\n") {
			lines = append(lines, strings.TrimRight(ln, "\r"))
		}
		return lines
	}
	return strings.Split(spec, ",")
}

// expandDomainList flattens YAML list entries, each of which follows the same
// rules as -domains (a domain or a path to a domain list file).
func expandDomainList(items []string) []string {
	var out []string
	for _, it := range items {
		out = append(out, loadDomainEntries(it)...)
	}
	return out
}
