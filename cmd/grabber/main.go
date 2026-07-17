package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
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
		os.Exit(runGrab(os.Args[2:]))
	case "check":
		os.Exit(runCheck(os.Args[2:]))
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `domain-grabber (Go) — max perf 6c/6Go/1.7G

Usage:
  grabber grab  [-c config.yaml] [-t seconds] [-o output/domains.txt]
  grabber check [-c config.yaml] -i domains.txt -o alive.txt

Throttle: ralentit automatiquement si CPU > 80%% ou RAM > 80%%.
`)
}

func loadCfg(path string) (*config.Config, error) {
	if path == "" {
		path = "config.yaml"
	}
	return config.Load(path)
}

func runGrab(args []string) int {
	fs := flag.NewFlagSet("grab", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "config file")
	outPath := fs.String("o", "", "output file (overrides config)")
	secs := fs.Int("t", 0, "stop after N seconds (0 = run until Ctrl+C)")
	_ = fs.Parse(args)

	cfg, err := loadCfg(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	outFile := *outPath
	if outFile == "" {
		outFile = filepath.Join(cfg.Output.Directory, cfg.Output.File)
	}
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
	if *secs > 0 {
		var tcancel context.CancelFunc
		ctx, tcancel = context.WithTimeout(ctx, time.Duration(*secs)*time.Second)
		defer tcancel()
	}

	g := ct.NewGrabber(cfg, th, filter)
	g.Run(ctx)

	f, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<20)
	defer w.Flush()

	live := dashboard.New()
	start := time.Now()
	seen := make(map[string]struct{}, 1<<20)
	batch := make([]string, 0, cfg.Performance.BatchWrite)
	flushEvery := time.Duration(cfg.Performance.LogIntervalMs) * time.Millisecond
	if flushEvery <= 0 {
		flushEvery = time.Second
	}
	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()

	flush := func() {
		for _, d := range batch {
			fmt.Fprintln(w, d)
		}
		batch = batch[:0]
		_ = w.Flush()
	}

	var written int64
	for {
		select {
		case <-ctx.Done():
			flush()
			fmt.Fprintf(os.Stderr, "\nstopped — %d domains → %s\n", written, outFile)
			return 0
		case d, ok := <-g.Out:
			if !ok {
				flush()
				fmt.Fprintf(os.Stderr, "\ndone — %d domains → %s\n", written, outFile)
				return 0
			}
			if _, exists := seen[d]; exists {
				continue
			}
			seen[d] = struct{}{}
			batch = append(batch, d)
			written++
			live.AddRecent(d)
			if len(batch) >= cfg.Performance.BatchWrite {
				flush()
			}
		case <-ticker.C:
			flush()
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
				Sources:   min(len(cfg.Sources.Logs), cfg.Performance.MaxLogs),
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

func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "config file")
	inPath := fs.String("i", "", "input domains file")
	outPath := fs.String("o", "alive.txt", "output alive domains")
	secs := fs.Int("t", 0, "stop after N seconds")
	_ = fs.Parse(args)
	if strings.TrimSpace(*inPath) == "" {
		fmt.Fprintln(os.Stderr, "-i input file required")
		return 2
	}

	cfg, err := loadCfg(*cfgPath)
	if err != nil {
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

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *secs > 0 {
		var tcancel context.CancelFunc
		ctx, tcancel = context.WithTimeout(ctx, time.Duration(*secs)*time.Second)
		defer tcancel()
	}

	c := check.New(cfg, th)
	live := dashboard.New()
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- c.RunFile(ctx, *inPath, *outPath) }()

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
				Sources:   0,
				File:      *outPath,
				CPU:       th.CPU(),
				RAM:       th.RAM(),
				Throttled: th.Active(),
				Recent:    nil,
				Extra:     fmt.Sprintf("TCP 80/443 probes=%d", c.Stats.Probes.Load()),
			})
			if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			fmt.Fprintf(os.Stderr, "\ncheck done — alive=%d dead=%d → %s\n",
				c.Stats.Alive.Load(), c.Stats.Dead.Load(), *outPath)
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
				Sources:   0,
				File:      *outPath,
				CPU:       th.CPU(),
				RAM:       th.RAM(),
				Throttled: th.Active(),
				Extra:     fmt.Sprintf("TCP 80/443 workers=%d", cfg.Performance.CheckWorkers),
			})
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	if b <= 0 {
		return a
	}
	return b
}
