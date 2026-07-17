package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
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
	os.Exit(run())
}

func run() int {
	cfg, err := config.Load("config.yaml")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	outDir := cfg.Output.Directory
	alivePath := filepath.Join(outDir, cfg.Output.File)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
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

	aliveFile, err := os.OpenFile(alivePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer aliveFile.Close()
	aliveW := bufio.NewWriterSize(aliveFile, 64*1024)
	var aliveMu sync.Mutex

	workers := cfg.Performance.CheckWorkers
	if workers <= 0 {
		workers = 4000
	}
	timeout := time.Duration(cfg.Performance.CheckTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 600 * time.Millisecond
	}
	checkJobs := make(chan string, workers*2)

	var (
		checked atomic.Int64
		aliveN  atomic.Int64
		deadN   atomic.Int64
		probes  atomic.Int64
	)

	var checkWG sync.WaitGroup
	for i := 0; i < workers; i++ {
		checkWG.Add(1)
		go func() {
			defer checkWG.Done()
			dialer := net.Dialer{Timeout: timeout}
			for domain := range checkJobs {
				th.Wait()
				ok := false
				for _, p := range []int{80, 443} {
					probes.Add(1)
					conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(domain, fmt.Sprintf("%d", p)))
					if err == nil {
						_ = conn.Close()
						ok = true
						break
					}
				}
				checked.Add(1)
				if ok {
					aliveN.Add(1)
					aliveMu.Lock()
					fmt.Fprintln(aliveW, domain)
					_ = aliveW.Flush()
					aliveMu.Unlock()
				} else {
					deadN.Add(1)
				}
			}
		}()
	}

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

	finish := func() {
		close(checkJobs)
		checkWG.Wait()
		aliveMu.Lock()
		_ = aliveW.Flush()
		_ = aliveFile.Sync()
		aliveMu.Unlock()
		fmt.Fprintf(os.Stderr, "\nstopped — alive=%d → %s\n", aliveN.Load(), alivePath)
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
			live.AddRecent(d)
			select {
			case <-ctx.Done():
				finish()
				return 0
			case checkJobs <- d:
			}
		case <-syncTicker.C:
			aliveMu.Lock()
			_ = aliveFile.Sync()
			aliveMu.Unlock()
		case <-ticker.C:
			elapsed := time.Since(start).Seconds()
			rate := 0.0
			if elapsed > 0 {
				rate = float64(aliveN.Load()) / elapsed
			}
			live.Render(dashboard.Snapshot{
				Uptime:    time.Since(start),
				Rate:      rate,
				Raw:       g.Stats.Raw.Load(),
				Filtered:  g.Stats.Filtered.Load(),
				Rejected:  g.Stats.Rejected.Load(),
				Bytes:     g.Stats.Bytes.Load(),
				Sources:   sources,
				File:      alivePath,
				CPU:       th.CPU(),
				RAM:       th.RAM(),
				Throttled: th.Active(),
				Recent:    live.Recent(),
				Extra: fmt.Sprintf("checked=%d alive=%d dead=%d probes=%d",
					checked.Load(), aliveN.Load(), deadN.Load(), probes.Load()),
			})
		}
	}
}
