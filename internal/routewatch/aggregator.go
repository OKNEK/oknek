// Package routewatch aggregates R10 route-around detections into a rolling
// window, surfaces them for `oknek routes`, and emits a Warn soft-cap event
// when estimated route-around spend in the window crosses the budget.
//
// It is stateful (unlike the stateless rules) and mirrors gpuwatch's
// emit-directly pattern: the soft-cap event is written straight to the store
// via EmitFunc, not routed back through the rule engine. All methods are
// safe on a nil *Aggregator (the detector is opt-in).
package routewatch

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

// EmitFunc records one event to the store. Matches store.Store.InsertEvent.
type EmitFunc func(id string, ts int64, agentID, ruleID, verdict, payloadJSON string) error

type sample struct {
	provider string
	process  string
	pid      int
	cost     float64
	at       time.Time
}

// Aggregator holds a rolling window of route-around detections.
type Aggregator struct {
	window    time.Duration
	budgetUSD float64
	emit      EmitFunc
	now       func() time.Time
	logger    *log.Logger

	mu         sync.Mutex
	samples    []sample
	lifetime   int
	overBudget bool // debounce: true while the window is over budget
}

// New builds an Aggregator. emit may be nil (soft-cap events are then dropped).
func New(windowSeconds int, budgetUSD float64, emit EmitFunc, now func() time.Time, logger *log.Logger) *Aggregator {
	if now == nil {
		now = time.Now
	}
	return &Aggregator{
		window:    time.Duration(windowSeconds) * time.Second,
		budgetUSD: budgetUSD,
		emit:      emit,
		now:       now,
		logger:    logger,
	}
}

// Record ingests one R10 route-around detection and checks the soft cap.
func (a *Aggregator) Record(provider, process string, pid int, estCostUSD float64) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.samples = append(a.samples, sample{provider, process, pid, estCostUSD, now})
	a.lifetime++
	a.prune(now)
	a.checkSoftCap(now)
}

// prune drops samples older than the window. Caller holds the lock.
func (a *Aggregator) prune(now time.Time) {
	cut := now.Add(-a.window)
	i := 0
	for i < len(a.samples) && a.samples[i].at.Before(cut) {
		i++
	}
	if i > 0 {
		a.samples = append(a.samples[:0], a.samples[i:]...)
	}
}

// windowUSD sums estimated cost in the current window. Caller holds the lock.
func (a *Aggregator) windowUSD() float64 {
	var sum float64
	for _, s := range a.samples {
		sum += s.cost
	}
	return sum
}

// checkSoftCap emits one Warn when the window first crosses budget, and re-arms
// after it drops back to/below budget. Caller holds the lock.
func (a *Aggregator) checkSoftCap(now time.Time) {
	sum := a.windowUSD()
	switch {
	case sum > a.budgetUSD && !a.overBudget:
		a.overBudget = true
		a.emitSoftCap(now, sum)
	case sum <= a.budgetUSD && a.overBudget:
		a.overBudget = false
	}
}

func (a *Aggregator) emitSoftCap(now time.Time, sum float64) {
	if a.emit != nil {
		payload, _ := json.Marshal(map[string]interface{}{
			"soft_cap_exceeded": true,
			"window_usd":        sum,
			"budget_usd":        a.budgetUSD,
			"window_seconds":    int(a.window.Seconds()),
			"route_arounds":     len(a.samples),
		})
		id := fmt.Sprintf("ra_softcap_%d", now.UnixNano())
		if err := a.emit(id, now.UnixNano(), "", "R10", "warn", string(payload)); err != nil && a.logger != nil {
			a.logger.Printf("route_around: soft-cap emit: %v", err)
		}
	}
	if a.logger != nil {
		a.logger.Printf("route_around: SOFT CAP exceeded · est ~$%.2f in window > $%.2f budget", sum, a.budgetUSD)
	}
}

// ProcStat is one process's route-around tally in the window.
type ProcStat struct {
	Process  string  `json:"process"`
	Provider string  `json:"provider"`
	Count    int     `json:"count"`
	EstUSD   float64 `json:"est_usd"`
	LastSeen int64   `json:"last_seen"` // unix nanos
}

// Status is the current window snapshot, for `oknek routes`.
type Status struct {
	Enabled       bool       `json:"enabled"`
	WindowSeconds int        `json:"window_seconds"`
	WindowUSD     float64    `json:"window_usd"`
	BudgetUSD     float64    `json:"budget_usd"`
	OverBudget    bool       `json:"over_budget"`
	Lifetime      int        `json:"lifetime"`
	Processes     []ProcStat `json:"processes"`
}

// Status returns the current window snapshot (nil-safe).
func (a *Aggregator) Status() Status {
	if a == nil {
		return Status{Enabled: false}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prune(a.now())
	type key struct{ proc, prov string }
	groups := map[key]*ProcStat{}
	var order []key
	for _, s := range a.samples {
		k := key{s.process, s.provider}
		ps, ok := groups[k]
		if !ok {
			ps = &ProcStat{Process: s.process, Provider: s.provider}
			groups[k] = ps
			order = append(order, k)
		}
		ps.Count++
		ps.EstUSD += s.cost
		if n := s.at.UnixNano(); n > ps.LastSeen {
			ps.LastSeen = n
		}
	}
	procs := make([]ProcStat, 0, len(order))
	for _, k := range order {
		procs = append(procs, *groups[k])
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].EstUSD > procs[j].EstUSD })
	return Status{
		Enabled:       true,
		WindowSeconds: int(a.window.Seconds()),
		WindowUSD:     a.windowUSD(),
		BudgetUSD:     a.budgetUSD,
		OverBudget:    a.windowUSD() > a.budgetUSD,
		Lifetime:      a.lifetime,
		Processes:     procs,
	}
}
