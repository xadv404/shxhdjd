package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/xadv404/shxhdjd/internal/check"
	"github.com/xadv404/shxhdjd/internal/config"
	"github.com/xadv404/shxhdjd/internal/dashboard"
	"github.com/xadv404/shxhdjd/internal/throttle"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("grabber", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "config file")
	inPath := fs.String("i", "", "input domains .txt (one domain per line)")
	outPath := fs.String("o", "alive.txt", "output alive domains")
	secs := fs.Int("t", 0, "stop after N seconds (0 = until done / Ctrl+C)")
	_ = fs.Parse(args)

	if strings.TrimSpace(*inPath) == "" {
		fmt.Fprintln(os.Stderr, "usage: grabber -i domains.txt [-o alive.txt] [-c config.yaml] [-t seconds]")
		fmt.Fprintln(os.Stderr, "check TCP 80/443 — throttle auto si CPU/RAM > 80%")
		return 2
	}

	cfg, err := config.Load(*cfgPath)
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
				File:      *outPath,
				CPU:       th.CPU(),
				RAM:       th.RAM(),
				Throttled: th.Active(),
				Extra:     fmt.Sprintf("TCP 80/443 probes=%d input=%s", c.Stats.Probes.Load(), *inPath),
			})
			if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			fmt.Fprintf(os.Stderr, "\ndone — alive=%d dead=%d → %s\n",
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
				File:      *outPath,
				CPU:       th.CPU(),
				RAM:       th.RAM(),
				Throttled: th.Active(),
				Extra:     fmt.Sprintf("TCP 80/443 workers=%d input=%s", cfg.Performance.CheckWorkers, *inPath),
			})
		}
	}
}
