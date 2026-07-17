package check

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xadv404/shxhdjd/internal/config"
	"github.com/xadv404/shxhdjd/internal/throttle"
)

type Stats struct {
	Total  atomic.Int64
	Alive  atomic.Int64
	Dead   atomic.Int64
	Errors atomic.Int64
	Probes atomic.Int64
}

type Checker struct {
	cfg      *config.Config
	throttle *throttle.Guard
	Stats    Stats
}

func New(cfg *config.Config, th *throttle.Guard) *Checker {
	return &Checker{cfg: cfg, throttle: th}
}

func (c *Checker) RunFile(ctx context.Context, inPath, outPath string) error {
	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()

	workers := c.cfg.Performance.CheckWorkers
	if workers <= 0 {
		workers = 4000
	}
	timeout := time.Duration(c.cfg.Performance.CheckTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 600 * time.Millisecond
	}
	ports := []int{80, 443}

	jobs := make(chan string, workers*2)
	var mu sync.Mutex
	w := bufio.NewWriterSize(out, 1<<20)
	defer w.Flush()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {
				c.throttle.Wait()
				ok := c.probe(ctx, domain, ports, timeout)
				c.Stats.Total.Add(1)
				if ok {
					c.Stats.Alive.Add(1)
					mu.Lock()
					fmt.Fprintln(w, domain)
					_ = w.Flush() // temps réel
					mu.Unlock()
				} else {
					c.Stats.Dead.Add(1)
				}
			}
		}()
	}

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		d := sc.Text()
		if d == "" {
			continue
		}
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return ctx.Err()
		case jobs <- d:
		}
	}
	close(jobs)
	wg.Wait()
	return sc.Err()
}

func (c *Checker) probe(ctx context.Context, domain string, ports []int, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	for _, p := range ports {
		c.Stats.Probes.Add(1)
		addr := net.JoinHostPort(domain, fmt.Sprintf("%d", p))
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return true
		}
		c.Stats.Errors.Add(1)
	}
	return false
}
