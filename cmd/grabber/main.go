package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/xadv404/shxhdjd/internal/check"
	"github.com/xadv404/shxhdjd/internal/config"
	"github.com/xadv404/shxhdjd/internal/ct"
	"github.com/xadv404/shxhdjd/internal/dashboard"
	"github.com/xadv404/shxhdjd/internal/spam"
	"github.com/xadv404/shxhdjd/internal/throttle"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "grab":
		os.Exit(runGrab())
	case "check":
		os.Exit(runCheck())
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  ./grabber grab    # CT → output/domains.txt (temps réel, Ctrl+C pour stop)
  ./grabber check   # TCP 80/443 sur output/domains.txt → output/alive.txt

config.yaml = toutes les options (pas d'autres flags)`)
}

func loadCfg() (*config.Config, error) {
	return config.Load("config.yaml")
}

func runGrab() int {
	cfg, err := loadCfg()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	outFile := filepath.Join(cfg.Output.Directory, cfg.Output.File)
	if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	th := throttle.New(
		cfg.Throttle.Enabled,
		cfg.Throttle.CPUPercent,
		cfg.Throttle.RAMPercent,
		cfg.Throttle.CheckIntervalMs,
		cfg.Throttle.SleepMs,
	)
	defer th.Stop()

	filter := func(string) bool { return true }
	if cfg.Filters.ZeroSpam {
		filter = spam.IsClean
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	g := ct.NewGrabber(cfg, th, filter)
	g.Run(ctx)

	f, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 64*1024)

	live := dashboard.New()
	start := time.Now()
	seen := make(map[string]struct{}, 1<<20)
	sources := len(cfg.Sources.Logs)
	if cfg.Performance.MaxLogs > 0 && sources > cfg.Performance.MaxLogs {
		sources = cfg.Performance.MaxLogs
	}

	flushEvery := time.Duration(cfg.Performance.LogIntervalMs) * time.Millisecond
	if flushEvery <= 0 {
		flushEvery = time.Second
	}
	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()
	syncTicker := time.NewTicker(time.Second)
	defer syncTicker.Stop()

	var written int64
	finish := func() {
		_ = w.Flush()
		_ = f.Sync()
		fmt.Fprintf(os.Stderr, "\nstopped — %d domains → %s\n", written, outFile)
	}

	for {
		select {
		case <-ctx.Done():
			finish()
			return 0
		case d, ok := <-g.Out:
			if !ok {
				finish()
				return 0
			}
			if _, exists := seen[d]; exists {
				continue
			}
			seen[d] = struct{}{}
			fmt.Fprintln(w, d)
			_ = w.Flush() // temps réel dans domains.txt
			written++
			live.AddRecent(d)
		case <-syncTicker.C:
			_ = f.Sync()
		case <-ticker.C:
			elapsed := time.Since(start).Seconds()
			rate := 0.0
			if elapsed > 0 {
				rate = float64(g.Stats.Filtered.Load()) / elapsed
			}
			live.Render(dashboard.Snapshot{
				Uptime:    time.Since(start),
				Rate:      rate,
				Raw:       g.Stats.Raw.Load(),
				Filtered:  g.Stats.Filtered.Load(),
				Rejected:  g.Stats.Rejected.Load(),
				Bytes:     g.Stats.Bytes.Load(),
				Sources:   sources,
				File:      outFile,
				CPU:       th.CPU(),
				RAM:       th.RAM(),
				Throttled: th.Active(),
				Recent:    live.Recent(),
				Extra:     fmt.Sprintf("pages=%d err=%d unique=%d", g.Stats.Pages.Load(), g.Stats.Errors.Load(), written),
			})
		}
	}
}

func runCheck() int {
	cfg, err := loadCfg()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	inPath := filepath.Join(cfg.Output.Directory, cfg.Output.File)
	outPath := filepath.Join(cfg.Output.Directory, "alive.txt")
	if err := os.MkdirAll(cfg.Output.Directory, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if _, err := os.Stat(inPath); err != nil {
		fmt.Fprintf(os.Stderr, "input manquant: %s (lance d'abord ./grabber grab)\n", inPath)
		return 1
	}

	th := throttle.New(
		cfg.Throttle.Enabled,
		cfg.Throttle.CPUPercent,
		cfg.Throttle.RAMPercent,
		cfg.Throttle.CheckIntervalMs,
		cfg.Throttle.SleepMs,
	)
	defer th.Stop()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	c := check.New(cfg, th)
	live := dashboard.New()
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- c.RunFile(ctx, inPath, outPath) }()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			elapsed := time.Since(start).Seconds()
			rate := 0.0
			if elapsed > 0 {
				rate = float64(c.Stats.Total.Load()) / elapsed
			}
			live.Render(dashboard.Snapshot{
				Uptime:    time.Since(start),
				Rate:      rate,
				Raw:       c.Stats.Total.Load(),
				Filtered:  c.Stats.Alive.Load(),
				Rejected:  c.Stats.Dead.Load(),
				File:      outPath,
				CPU:       th.CPU(),
				RAM:       th.RAM(),
				Throttled: th.Active(),
				Extra:     fmt.Sprintf("TCP 80/443 input=%s", inPath),
			})
			if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			fmt.Fprintf(os.Stderr, "\ndone — alive=%d dead=%d → %s\n",
				c.Stats.Alive.Load(), c.Stats.Dead.Load(), outPath)
			return 0
		case <-ticker.C:
			elapsed := time.Since(start).Seconds()
			rate := 0.0
			if elapsed > 0 {
				rate = float64(c.Stats.Total.Load()) / elapsed
			}
			live.Render(dashboard.Snapshot{
				Uptime:    time.Since(start),
				Rate:      rate,
				Raw:       c.Stats.Total.Load(),
				Filtered:  c.Stats.Alive.Load(),
				Rejected:  c.Stats.Dead.Load(),
				File:      outPath,
				CPU:       th.CPU(),
				RAM:       th.RAM(),
				Throttled: th.Active(),
				Extra:     fmt.Sprintf("TCP 80/443 workers=%d", cfg.Performance.CheckWorkers),
			})
		}
	}
}
