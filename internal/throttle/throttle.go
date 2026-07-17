package throttle

import (
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

// Guard ralentit le pipeline si CPU ou RAM > limite.
type Guard struct {
	enabled    bool
	cpuLimit   float64
	ramLimit   float64
	interval   time.Duration
	sleep      time.Duration
	cpuPct     atomic.Uint64 // x100
	ramPct     atomic.Uint64 // x100
	throttling atomic.Bool
	stop       chan struct{}
}

func New(enabled bool, cpuLimit, ramLimit float64, intervalMs, sleepMs int) *Guard {
	if intervalMs <= 0 {
		intervalMs = 500
	}
	if sleepMs <= 0 {
		sleepMs = 50
	}
	g := &Guard{
		enabled:  enabled,
		cpuLimit: cpuLimit,
		ramLimit: ramLimit,
		interval: time.Duration(intervalMs) * time.Millisecond,
		sleep:    time.Duration(sleepMs) * time.Millisecond,
		stop:     make(chan struct{}),
	}
	if enabled {
		go g.loop()
	}
	return g
}

func (g *Guard) loop() {
	ticker := time.NewTicker(g.interval)
	defer ticker.Stop()
	for {
		select {
		case <-g.stop:
			return
		case <-ticker.C:
			g.sample()
		}
	}
}

func (g *Guard) sample() {
	pcts, err := cpu.Percent(0, false)
	if err == nil && len(pcts) > 0 {
		g.cpuPct.Store(uint64(pcts[0] * 100))
	}
	vm, err := mem.VirtualMemory()
	if err == nil {
		g.ramPct.Store(uint64(vm.UsedPercent * 100))
	}
	cpuH := float64(g.cpuPct.Load())/100 >= g.cpuLimit
	ramH := float64(g.ramPct.Load())/100 >= g.ramLimit
	g.throttling.Store(cpuH || ramH)
}

// Wait bloque brièvement si CPU/RAM trop hauts.
func (g *Guard) Wait() {
	if !g.enabled {
		return
	}
	for g.throttling.Load() {
		time.Sleep(g.sleep)
		// re-check after sleep without waiting full interval
		g.sample()
		if !g.throttling.Load() {
			return
		}
	}
}

func (g *Guard) CPU() float64 { return float64(g.cpuPct.Load()) / 100 }
func (g *Guard) RAM() float64 { return float64(g.ramPct.Load()) / 100 }
func (g *Guard) Active() bool { return g.throttling.Load() }

func (g *Guard) Stop() {
	select {
	case <-g.stop:
	default:
		close(g.stop)
	}
}
