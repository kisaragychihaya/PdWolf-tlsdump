package config

import (
	"context"
	"log/slog"
	"os"
	"time"
)

// Watch polls path for modifications and invokes onChange with the freshly
// parsed configuration. A parse or validation failure is logged and the
// previous configuration stays in effect; the next poll retries, which also
// covers editors that write the file non-atomically. Watch returns when ctx
// is cancelled.
func Watch(ctx context.Context, path string, interval time.Duration, onChange func(*Config)) {
	go func() {
		var lastMod time.Time
		var lastSize int64 = -1
		if st, err := os.Stat(path); err == nil {
			lastMod, lastSize = st.ModTime(), st.Size()
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			st, err := os.Stat(path)
			if err != nil {
				slog.Error("config: stat failed, keeping previous config", "path", path, "err", err)
				continue
			}
			if st.ModTime().Equal(lastMod) && st.Size() == lastSize {
				continue
			}
			lastMod, lastSize = st.ModTime(), st.Size()

			cfg, err := Load(path)
			if err != nil {
				slog.Error("config: reload failed, keeping previous config", "path", path, "err", err)
				continue
			}
			slog.Info("config: file changed, reloading", "path", path)
			onChange(cfg)
		}
	}()
}
