package gpuwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/oknek/oknek/internal/rules"
)

// EmitFunc records a detection event — same signature as cmd/oknekd's emit
// (store.InsertEvent + dashboard feed).
type EmitFunc func(id string, ts int64, agentID, ruleID, verdict, payloadJSON string) error

type namedProbe struct {
	name   string
	probes []HealthProbe // a check is healthy iff every probe is healthy
}

type serviceState struct {
	down      bool
	downSince time.Time
	alerted   bool // a live alert was already emitted for this down-window
}

// Watcher polls workload health on a pod and emits cost-anomaly events. The
// clock (now) and probes are injected so the state machine is deterministic in
// tests.
type Watcher struct {
	pod        string
	provider   string
	hourlyUSD  float64
	grace      time.Duration
	poll       time.Duration
	webhookURL string
	checks     []namedProbe
	engine     *rules.Engine
	emit       EmitFunc
	now        func() time.Time
	logger     *log.Logger
	states     map[string]*serviceState
}

// run polls every w.poll until ctx is cancelled.
func (w *Watcher) run(ctx context.Context) {
	t := time.NewTicker(w.poll)
	defer t.Stop()
	w.tick(ctx) // probe immediately, don't wait a full interval
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

// tick runs one poll cycle across all checks.
func (w *Watcher) tick(ctx context.Context) {
	for _, np := range w.checks {
		ok, errored := w.evalCheck(ctx, np)
		if errored {
			w.logger.Printf("gpuwatch: probe error on %q — skipping tick", np.name)
			// fail-safe: a broken probe never flips state. NOTE: a persistent probe
			// error suppresses alerts until the probe recovers — the log line above is
			// the only out-of-band signal for that condition.
			continue
		}
		st := w.states[np.name]
		if st == nil {
			st = &serviceState{}
			w.states[np.name] = st
		}
		now := w.now()
		switch {
		case ok && st.down: // recovery
			down := int64(now.Sub(st.downSince).Seconds())
			if st.alerted {
				w.emitEvent(ctx, np.name, st.downSince, down, true)
			}
			st.down, st.alerted, st.downSince = false, false, time.Time{}
		case !ok && !st.down: // went down
			st.down, st.downSince, st.alerted = true, now, false
		case !ok && st.down && !st.alerted: // still down, maybe cross grace
			if elapsed := now.Sub(st.downSince); elapsed >= w.grace {
				w.emitEvent(ctx, np.name, st.downSince, int64(elapsed.Seconds()), false)
				st.alerted = true
			}
		}
	}
}

// evalCheck is healthy iff every probe is healthy; errored if any probe errors.
func (w *Watcher) evalCheck(ctx context.Context, np namedProbe) (ok bool, errored bool) {
	all := true
	for _, p := range np.probes {
		h, _, err := p.Healthy(ctx)
		if err != nil {
			return false, true
		}
		if !h {
			all = false
		}
	}
	return all, false
}

// emitEvent builds the cost-anomaly event, runs it through the engine, persists
// any match via emit, and fires the Dean notification.
func (w *Watcher) emitEvent(ctx context.Context, service string, downSince time.Time, downSecs int64, resolved bool) {
	p := rules.CostAnomalyPayload{
		Provider: w.provider, PodID: w.pod, Service: service,
		DownSince: downSince.Unix(), DownSeconds: downSecs,
		HourlyUSD: w.hourlyUSD, ExposureUSD: round2(float64(downSecs) / 3600.0 * w.hourlyUSD),
		Resolved: resolved,
	}
	ts := w.now().UnixNano()
	ev := rules.Event{Kind: rules.KindCostAnomaly, AgentID: w.pod, Timestamp: ts, Payload: p}
	for _, m := range w.engine.Evaluate(ctx, ev) {
		if m.Verdict == rules.VerdictAllow {
			continue
		}
		payloadJSON, _ := json.Marshal(m.Evidence)
		id := fmt.Sprintf("e_%d_0_%s_%s", ts, m.RuleID, service)
		_ = w.emit(id, ts, ev.AgentID, m.RuleID, m.Verdict.String(), string(payloadJSON))
		draft, _ := m.Evidence["clawback_draft"].(string)
		line := deanLine(p, draft)
		w.logger.Print(line)
		postWebhook(w.webhookURL, line)
	}
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }
