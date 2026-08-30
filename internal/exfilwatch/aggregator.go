// Package exfilwatch turns R11's off-gateway connect stream into R12 exfil/C2
// alerts: beaconing (regular-interval phone-home) and velocity (burst egress).
// Stateful, driven entirely by the kernel-stamped tsNano per connect; emits
// straight to the store via EmitFunc (the routewatch/gpuwatch emit-directly
// pattern). All methods are safe on a nil *Aggregator (the watcher is opt-in).
// Alert-only — it never blocks; R11 owns any blocking.
package exfilwatch

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"sync"

	"github.com/oknek/oknek/internal/config"
	"github.com/oknek/oknek/internal/rules"
)

// EmitFunc records one event to the store. Matches store.Store.InsertEvent.
type EmitFunc func(id string, ts int64, agentID, ruleID, verdict, payloadJSON string) error

type beaconKey struct {
	agent, dest string
}

type beaconState struct {
	ts   []int64 // recent connect timestamps (nanos), capped at beaconRing
	port uint16
}

const beaconRing = 16 // keep at most this many timestamps per dest

// Aggregator detects beaconing + velocity over observed connects.
type Aggregator struct {
	cfg    config.ExfilWatchConfig
	emit   EmitFunc
	logger *log.Logger

	mu       sync.Mutex
	beacons  map[beaconKey]*beaconState // per (agent,dest): recent timestamps
	velocity map[string][]int64         // per agent: tsNano sliding window
	lastProc map[string]string          // agent → last process comm (evidence)
	lastPID  map[string]int             // agent → last pid (evidence)
	cooldown map[string]int64           // dedup key → last-fired tsNano
}

// New builds an Aggregator. cfg must be normalized. emit may be nil (drops events).
func New(cfg config.ExfilWatchConfig, emit EmitFunc, logger *log.Logger) *Aggregator {
	return &Aggregator{
		cfg:      cfg,
		emit:     emit,
		logger:   logger,
		beacons:  map[beaconKey]*beaconState{},
		velocity: map[string][]int64{},
		lastProc: map[string]string{},
		lastPID:  map[string]int{},
		cooldown: map[string]int64{},
	}
}

// Observe ingests one off-gateway connect and checks the detectors. process+pid
// are recorded as the latest evidence for the agent (surfaced in alerts).
func (a *Aggregator) Observe(agentID, process string, pid int, destIP string, destPort uint16, tsNano int64) {
	if a == nil || agentID == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if process != "" {
		a.lastProc[agentID] = process
	}
	if pid != 0 {
		a.lastPID[agentID] = pid
	}
	a.checkBeacon(agentID, destIP, destPort, tsNano)
	a.checkVelocity(agentID, tsNano)
}

// checkVelocity slides a per-agent window of connect timestamps and fires when
// the count exceeds the configured max in the window.
func (a *Aggregator) checkVelocity(agentID string, tsNano int64) {
	win := int64(a.cfg.VelocityWindowSeconds) * 1_000_000_000
	cut := tsNano - win
	ts := append(a.velocity[agentID], tsNano)
	i := 0
	for i < len(ts) && ts[i] < cut {
		i++
	}
	ts = ts[i:]
	a.velocity[agentID] = ts
	if len(ts) <= a.cfg.VelocityMaxConnects {
		return
	}
	if a.onCooldown("velocity", agentID, "", tsNano) {
		return
	}
	p := rules.ExfilAnomalyPayload{
		Pattern:         "velocity",
		AgentIdentifier: agentID,
		ConnectsWindow:  len(ts),
		WindowSeconds:   a.cfg.VelocityWindowSeconds,
		Process:         a.lastProc[agentID],
		PID:             a.lastPID[agentID],
		Rule:            "exfil-c2-watch",
	}
	a.emitEvent(agentID, p, tsNano)
	if a.logger != nil {
		a.logger.Printf("exfil_watch: VELOCITY · agent %s · %d off-gateway connects in %ds",
			agentID, len(ts), a.cfg.VelocityWindowSeconds)
	}
}

// checkBeacon updates the per-dest ring and fires when the cadence is regular.
func (a *Aggregator) checkBeacon(agentID, destIP string, destPort uint16, tsNano int64) {
	k := beaconKey{agentID, fmt.Sprintf("%s:%d", destIP, destPort)}
	st := a.beacons[k]
	if st == nil {
		st = &beaconState{port: destPort}
		a.beacons[k] = st
	}
	st.ts = append(st.ts, tsNano)
	if len(st.ts) > beaconRing {
		st.ts = st.ts[len(st.ts)-beaconRing:]
	}
	intervals := len(st.ts) - 1
	if intervals < a.cfg.BeaconMinCount {
		return
	}
	mean, cv := meanCV(st.ts)
	meanSec := mean / 1e9
	if meanSec < a.cfg.BeaconMinIntervalSeconds {
		return // too fast to be a beacon — that's velocity's job
	}
	if cv > a.cfg.BeaconJitterTolerance {
		return // too jittery
	}
	if a.onCooldown("beacon", agentID, k.dest, tsNano) {
		return
	}
	a.fireBeacon(agentID, destIP, destPort, meanSec, cv, intervals, tsNano)
}

// meanCV returns the mean inter-arrival interval (nanos) and the coefficient of
// variation (stddev/mean) over the timestamps. Assumes len(ts) >= 2.
func meanCV(ts []int64) (mean, cv float64) {
	n := len(ts) - 1
	diffs := make([]float64, n)
	var sum float64
	for i := 1; i < len(ts); i++ {
		d := float64(ts[i] - ts[i-1])
		diffs[i-1] = d
		sum += d
	}
	mean = sum / float64(n)
	if mean == 0 {
		return 0, math.Inf(1)
	}
	var ss float64
	for _, d := range diffs {
		ss += (d - mean) * (d - mean)
	}
	std := math.Sqrt(ss / float64(n))
	return mean, std / mean
}

// onCooldown reports whether a (pattern,agent,scope) alert fired within cooldown.
// Updates the last-fired stamp when it returns false (i.e. we're about to fire).
func (a *Aggregator) onCooldown(pattern, agentID, scope string, tsNano int64) bool {
	key := pattern + "|" + agentID + "|" + scope
	cd := int64(a.cfg.CooldownSeconds) * 1_000_000_000
	if last, ok := a.cooldown[key]; ok && tsNano-last < cd {
		return true
	}
	a.cooldown[key] = tsNano
	return false
}

func (a *Aggregator) fireBeacon(agentID, destIP string, destPort uint16, meanSec, cv float64, intervals int, tsNano int64) {
	dest := fmt.Sprintf("%s:%d", destIP, destPort)
	p := rules.ExfilAnomalyPayload{
		Pattern:         "beacon",
		AgentIdentifier: agentID,
		Dest:            dest,
		IntervalSeconds: round1(meanSec),
		JitterCV:        round3(cv),
		SampleCount:     intervals,
		Process:         a.lastProc[agentID],
		PID:             a.lastPID[agentID],
		Rule:            "exfil-c2-watch",
	}
	a.emitEvent(agentID, p, tsNano)
	if a.logger != nil {
		a.logger.Printf("exfil_watch: BEACON · agent %s → %s every ~%.0fs (jitter %.0f%%)",
			agentID, dest, meanSec, cv*100)
	}
}

func (a *Aggregator) emitEvent(agentID string, p rules.ExfilAnomalyPayload, tsNano int64) {
	if a.emit == nil {
		return
	}
	payload, _ := json.Marshal(p)
	id := fmt.Sprintf("exfil_%s_%d", p.Pattern, tsNano)
	if err := a.emit(id, tsNano, agentID, "R12", "warn", string(payload)); err != nil && a.logger != nil {
		a.logger.Printf("exfil_watch: emit: %v", err)
	}
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }
func round3(f float64) float64 { return math.Round(f*1000) / 1000 }
