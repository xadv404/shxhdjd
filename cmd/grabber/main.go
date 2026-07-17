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

	"github.com/xadv404/shxhdjd/internal/config"
	"github.com/xadv404/shxhdjd/internal/ct"
	"github.com/xadv404/shxhdjd/internal/dashboard"
	"github.com/xadv404/shxhdjd/internal/spam"
	"github.com/xadv404/shxhdjd/internal/throttle"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	cfg, err := config.Load("config.yaml")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	outFile := filepath.Join(cfg.Output.Directory, cfg.Output.File)
	if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
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
		os.Exit(1)
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

	sources := len(cfg.Sources.Logs)
	if cfg.Performance.MaxLogs > 0 && sources > cfg.Performance.MaxLogs {
		sources = cfg.Performance.MaxLogs
	}

	var written int64
	for {
		select {
		case <-ctx.Done():
			flush()
			fmt.Fprintf(os.Stderr, "\nstopped — %d domains → %s\n", written, outFile)
			return
		case d, ok := <-g.Out:
			if !ok {
				flush()
				fmt.Fprintf(os.Stderr, "\ndone — %d domains → %s\n", written, outFile)
				return
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
