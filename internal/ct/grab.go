package ct

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xadv404/shxhdjd/internal/config"
	"github.com/xadv404/shxhdjd/internal/throttle"
)

type Stats struct {
	Raw      atomic.Int64
	Filtered atomic.Int64
	Rejected atomic.Int64
	Bytes    atomic.Int64
	Pages    atomic.Int64
	Errors   atomic.Int64
}

type Grabber struct {
	cfg      *config.Config
	client   *http.Client
	throttle *throttle.Guard
	Filter   func(string) bool
	Out      chan string
	Stats    Stats
}

func NewGrabber(cfg *config.Config, th *throttle.Guard, filter func(string) bool) *Grabber {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   8 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   128,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	buf := cfg.Performance.BatchWrite
	if buf < 4096 {
		buf = 65536
	}
	return &Grabber{
		cfg: cfg,
		client: &http.Client{
			Timeout:   45 * time.Second,
			Transport: tr,
		},
		throttle: th,
		Filter:   filter,
		Out:      make(chan string, buf),
	}
}

func (g *Grabber) Run(ctx context.Context) {
	logs := g.cfg.Sources.Logs
	max := g.cfg.Performance.MaxLogs
	if max > 0 && len(logs) > max {
		logs = logs[:max]
	}
	var wg sync.WaitGroup
	for _, base := range logs {
		base = strings.TrimRight(base, "/")
		wg.Add(1)
		go func(logURL string) {
			defer wg.Done()
			g.pumpLog(ctx, logURL)
		}(base)
	}
	go func() {
		wg.Wait()
		close(g.Out)
	}()
}

func (g *Grabber) pumpLog(ctx context.Context, base string) {
	page := int64(1024)
	workers := g.cfg.Performance.InflightPerLog
	if workers <= 0 {
		workers = 64
	}
	window := int64(g.cfg.Performance.StartOffset)
	if window <= 0 {
		window = 800000
	}

	jobs := make(chan [2]int64, workers*2)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rangePair := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				g.fetchPage(ctx, base, rangePair[0], rangePair[1])
			}
		}()
	}

	// Track tip for live follow; walk history in successive windows.
	var tip int64
	var cursor int64 = -1 // next index to fetch backward (exclusive end)

	enqueue := func(start, end int64) bool {
		if start < 0 {
			start = 0
		}
		if end < start {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case jobs <- [2]int64{start, end}:
			return true
		}
	}

	for {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		default:
		}
		g.throttle.Wait()
		sth, err := g.getSTH(ctx, base)
		if err != nil || sth < 1000 {
			g.Stats.Errors.Add(1)
			select {
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}

		// New tip entries
		if tip > 0 && sth > tip {
			for tip < sth {
				end := tip + page - 1
				if end >= sth {
					end = sth - 1
				}
				if !enqueue(tip, end) {
					close(jobs)
					wg.Wait()
					return
				}
				tip = end + 1
			}
		}
		if tip == 0 {
			tip = sth
		} else if sth > tip {
			tip = sth
		}

		if cursor < 0 {
			cursor = sth
		}

		// Walk further back in history while running
		if cursor > 0 {
			target := cursor - window
			if target < 0 {
				target = 0
			}
			pos := target
			for pos < cursor {
				end := pos + page - 1
				if end >= cursor {
					end = cursor - 1
				}
				if !enqueue(pos, end) {
					close(jobs)
					wg.Wait()
					return
				}
				pos = end + 1
			}
			cursor = target
		} else {
			// Caught up on history — wait for new tip
			select {
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				return
			case <-time.After(2 * time.Second):
			}
		}
	}
}

func (g *Grabber) getSTH(ctx context.Context, base string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/ct/v1/get-sth", nil)
	if err != nil {
		return 0, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, err
	}
	g.Stats.Bytes.Add(int64(len(body)))
	var m struct {
		TreeSize int64 `json:"tree_size"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return 0, err
	}
	return m.TreeSize, nil
}

func (g *Grabber) fetchPage(ctx context.Context, base string, start, end int64) {
	g.throttle.Wait()
	url := fmt.Sprintf("%s/ct/v1/get-entries?start=%d&end=%d", base, start, end)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		g.Stats.Errors.Add(1)
		return
	}
	resp, err := g.client.Do(req)
	if err != nil {
		g.Stats.Errors.Add(1)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		g.Stats.Errors.Add(1)
		return
	}
	g.Stats.Bytes.Add(int64(len(body)))
	if resp.StatusCode != 200 {
		g.Stats.Errors.Add(1)
		return
	}
	domains := domainsFromEntriesJSON(body)
	g.Stats.Pages.Add(1)
	g.Stats.Raw.Add(int64(len(domains)))
	for _, d := range domains {
		if g.Filter != nil && !g.Filter(d) {
			g.Stats.Rejected.Add(1)
			continue
		}
		g.Stats.Filtered.Add(1)
		select {
		case <-ctx.Done():
			return
		case g.Out <- d:
		}
	}
}
