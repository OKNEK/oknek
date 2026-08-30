package gpuwatch

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"testing"
	"time"

	"github.com/oknek/oknek/internal/rules"
)

type fakeProbe struct {
	ok  bool
	err error
}

func (f *fakeProbe) Healthy(ctx context.Context) (bool, string, error) { return f.ok, "", f.err }

type captured struct{ id, ruleID, verdict, payload string }

func newTestWatcher(fp *fakeProbe, now func() time.Time, sink *[]captured) *Watcher {
	eng := rules.NewEngine()
	eng.Register(rules.NewR9(300))
	return &Watcher{
		pod: "test-pod", provider: "runpod", hourlyUSD: 0.79,
		grace: 300 * time.Second, poll: 30 * time.Second,
		checks: []namedProbe{{name: "svc", probes: []HealthProbe{fp}}},
		engine: eng, now: now, logger: log.New(io.Discard, "", 0),
		states: map[string]*serviceState{},
		emit: func(id string, ts int64, agentID, ruleID, verdict, payload string) error {
			*sink = append(*sink, captured{id, ruleID, verdict, payload})
			return nil
		},
	}
}

func TestWatcher_AlertThenResolve(t *testing.T) {
	clk := time.Unix(1_700_000_000, 0)
	fp := &fakeProbe{ok: true}
	var sink []captured
	w := newTestWatcher(fp, func() time.Time { return clk }, &sink)
	ctx := context.Background()

	w.tick(ctx) // up — no event
	fp.ok = false
	w.tick(ctx) // down starts
	clk = clk.Add(200 * time.Second)
	w.tick(ctx) // 200s < grace — no event
	clk = clk.Add(150 * time.Second)
	w.tick(ctx) // 350s >= grace — ALERT
	clk = clk.Add(60 * time.Second)
	w.tick(ctx) // still down, alerted — no dup
	fp.ok = true
	clk = clk.Add(40 * time.Second)
	w.tick(ctx) // recovery — RESOLVED

	if len(sink) != 2 {
		t.Fatalf("want 2 events (alert + resolved), got %d: %+v", len(sink), sink)
	}
	var alert, resolved map[string]interface{}
	_ = json.Unmarshal([]byte(sink[0].payload), &alert)
	_ = json.Unmarshal([]byte(sink[1].payload), &resolved)
	if sink[0].verdict != "warn" || alert["resolved"] != false {
		t.Fatalf("first event should be a live warn alert: %+v", alert)
	}
	if alert["clawback_draft"] != nil {
		t.Fatal("live alert must not carry clawback_draft")
	}
	if resolved["resolved"] != true || resolved["clawback_draft"] == nil {
		t.Fatalf("second event should be a resolved tally with a draft: %+v", resolved)
	}
}

func TestWatcher_TwoServicesSameTickDistinctIDs(t *testing.T) {
	clk := time.Unix(1_700_000_000, 0)
	var sink []captured
	eng := rules.NewEngine()
	eng.Register(rules.NewR9(300))
	pa, pb := &fakeProbe{ok: false}, &fakeProbe{ok: false}
	w := &Watcher{
		pod: "test-pod", provider: "runpod", hourlyUSD: 0.79,
		grace: 300 * time.Second, poll: 30 * time.Second,
		checks: []namedProbe{
			{name: "svc-a", probes: []HealthProbe{pa}},
			{name: "svc-b", probes: []HealthProbe{pb}},
		},
		engine: eng, now: func() time.Time { return clk }, logger: log.New(io.Discard, "", 0),
		states: map[string]*serviceState{},
		emit: func(id string, ts int64, agentID, ruleID, verdict, payload string) error {
			sink = append(sink, captured{id, ruleID, verdict, payload})
			return nil
		},
	}
	ctx := context.Background()
	w.tick(ctx) // both go down
	clk = clk.Add(350 * time.Second)
	w.tick(ctx) // both cross grace on the SAME tick -> 2 alerts
	if len(sink) != 2 {
		t.Fatalf("want 2 alerts (one per service), got %d", len(sink))
	}
	if sink[0].id == sink[1].id {
		t.Fatalf("same-tick events must have distinct ids, both = %q", sink[0].id)
	}
}

func TestWatcher_SubGraceBlipSilent(t *testing.T) {
	clk := time.Unix(1_700_000_000, 0)
	fp := &fakeProbe{ok: true}
	var sink []captured
	w := newTestWatcher(fp, func() time.Time { return clk }, &sink)
	ctx := context.Background()

	w.tick(ctx)
	fp.ok = false
	w.tick(ctx)
	clk = clk.Add(60 * time.Second) // down 60s < grace
	fp.ok = true
	w.tick(ctx) // recovers before grace
	if len(sink) != 0 {
		t.Fatalf("sub-grace blip should emit nothing, got %d", len(sink))
	}
}
