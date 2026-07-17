package dashboard

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type Snapshot struct {
	Uptime    time.Duration
	Rate      float64
	Raw       int64
	Filtered  int64
	Rejected  int64
	Bytes     int64
	Sources   int
	File      string
	CPU       float64
	RAM       float64
	Throttled bool
	Recent    []string
	Extra     string
}

type Live struct {
	mu     sync.Mutex
	start  time.Time
	recent []string
	maxRec int
	last   Snapshot
}

func New() *Live {
	return &Live{start: time.Now(), maxRec: 8, recent: make([]string, 0, 8)}
}

func (l *Live) AddRecent(d string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recent = append(l.recent, d)
	if len(l.recent) > l.maxRec {
		l.recent = l.recent[len(l.recent)-l.maxRec:]
	}
}

func (l *Live) Recent() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.recent))
	copy(out, l.recent)
	return out
}

func (l *Live) Render(s Snapshot) {
	l.last = s
	var b strings.Builder
	b.WriteString("\033[H\033[2J")
	b.WriteString("╔══════════════════════════════════════════════════════════╗\n")
	b.WriteString("║           PORT CHECK 80/443 — GO / MAX PERF              ║\n")
	b.WriteString("╚══════════════════════════════════════════════════════════╝\n\n")
	b.WriteString(fmt.Sprintf("  Time       %s\n", time.Now().Format("15:04:05")))
	b.WriteString(fmt.Sprintf("  Uptime     %s\n", fmtDur(s.Uptime)))
	b.WriteString(fmt.Sprintf("  Domaines/s %.0f\n", s.Rate))
	b.WriteString(fmt.Sprintf("  Scannés    %s\n", itoa(s.Raw)))
	b.WriteString(fmt.Sprintf("  Alive      %s\n", itoa(s.Filtered)))
	b.WriteString(fmt.Sprintf("  Dead       %s\n", itoa(s.Rejected)))
	if s.File != "" {
		b.WriteString(fmt.Sprintf("  Fichier    %s\n", s.File))
	}
	th := "ok"
	if s.Throttled {
		th = "THROTTLE"
	}
	b.WriteString(fmt.Sprintf("  CPU/RAM    %.0f%% / %.0f%%  [%s]\n", s.CPU, s.RAM, th))
	if s.Extra != "" {
		b.WriteString("  " + s.Extra + "\n")
	}
	if len(s.Recent) > 0 {
		b.WriteString("\n  Derniers:\n")
		for _, d := range s.Recent {
			b.WriteString("    · " + d + "\n")
		}
	}
	fmt.Fprint(os.Stderr, b.String())
}

func fmtDur(d time.Duration) string {
	s := int(d.Seconds())
	h := s / 3600
	m := (s % 3600) / 60
	sec := s % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, sec)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, sec)
	}
	return fmt.Sprintf("%ds", sec)
}

func itoa(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1_000_000 {
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	return fmt.Sprintf("%.2fM", float64(n)/1_000_000)
}
