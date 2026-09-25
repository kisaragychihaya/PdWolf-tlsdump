// Command tlsdump decrypts HTTPS traffic for whitelisted domains and records
// it as JSONL; everything else is forwarded untouched.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tlsdump/internal/certmgr"
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

func run() error {
	var (
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

	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	if *tunReset {
		slog.Info("resetting tun configuration", "name", *tunName)
		if err := tun.Reset(*tunName); err != nil {
			return fmt.Errorf("tun reset (run as administrator/root?): %w", err)
		}
		slog.Info("tun reset done", "name", *tunName)
		return nil
	}

	entries := loadDomainEntries(*domains)
	if len(entries) == 0 {
		return fmt.Errorf("no domains given; use -domains (comma-separated or file path)")
	}
	f := filter.Parse(entries)

	ca, err := certmgr.LoadOrCreate(*caDir)
	if err != nil {
		return err
	}
	slog.Info("CA ready", "dir", *caDir)

	var rec *record.Logger
	if *recordPath != "" {
		fh, err := os.OpenFile(*recordPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("open record file: %w", err)
		}
		defer fh.Close()
		rec = record.New(fh, *bodyLimit)
	} else {
		rec = record.New(os.Stdout, *bodyLimit)
	}

	handler := &mitm.Handler{
		CertMgr:            ca,
		Filter:             f,
		Log:                rec,
		BodyLimit:          *bodyLimit,
		DialTimeout:        10 * time.Second,
		InsecureSkipVerify: *insecure,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch *mode {
	case "proxy":
		s := &proxy.Server{Addr: *listen, H: handler}
		slog.Info("starting proxy mode", "listen", *listen, "domains", f.Len())
		if err := s.ListenAndServe(ctx); err != nil {
			return err
		}
	case "tun":
		slog.Info("starting tun mode", "name", *tunName)
		if err := tun.Run(ctx, tun.Config{
			Name:           *tunName,
			MTU:            *tunMTU,
			Handler:        handler,
			NoRoute:        *tunNoRoute,
			PhysicalIface:  *tunPhysicalIface,
			ExcludeDomains: loadDomainEntries(*tunExclude),
		}); err != nil && ctx.Err() == nil {
			return err
		}
	default:
		return fmt.Errorf("unknown mode %q (proxy|tun)", *mode)
	}
	slog.Info("tlsdump stopped")
	return nil
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
