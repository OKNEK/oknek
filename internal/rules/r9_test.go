package rules

import (
	"context"
	"strings"
	"testing"
)

func costEvent(p CostAnomalyPayload) Event {
	return Event{Kind: KindCostAnomaly, AgentID: p.PodID, Timestamp: 1, Payload: p}
}

func TestR9_BelowThresholdDoesNotFire(t *testing.T) {
	r := NewR9(300)
	_, ok := r.Match(context.Background(), costEvent(CostAnomalyPayload{DownSeconds: 120}))
	if ok {
		t.Fatal("R9 should not fire under MinDownSeconds")
	}
}

func TestR9_FiresAtExactThreshold(t *testing.T) {
	r := NewR9(300)
	if _, ok := r.Match(context.Background(), costEvent(CostAnomalyPayload{DownSeconds: 300})); !ok {
		t.Fatal("R9 should fire at exactly MinDownSeconds")
	}
}

func TestR9_LiveAlertFiresWarnWithoutDraft(t *testing.T) {
	r := NewR9(300)
	m, ok := r.Match(context.Background(), costEvent(CostAnomalyPayload{
		Provider: "runpod", PodID: "w411-radar2", Service: "radar-plant",
		DownSince: 1_700_000_000, DownSeconds: 330, HourlyUSD: 0.79, ExposureUSD: 0.07,
		Resolved: false,
	}))
	if !ok {
		t.Fatal("R9 should fire at/above MinDownSeconds")
	}
	if m.Verdict != VerdictWarn {
		t.Fatalf("verdict = %v, want warn", m.Verdict)
	}
	if _, has := m.Evidence["clawback_draft"]; has {
		t.Fatal("live alert must not carry clawback_draft")
	}
	if m.Evidence["resolved"] != false {
		t.Fatalf("resolved = %v, want false", m.Evidence["resolved"])
	}
}

func TestR9_ResolvedCarriesClawbackDraft(t *testing.T) {
	r := NewR9(300)
	m, ok := r.Match(context.Background(), costEvent(CostAnomalyPayload{
		Provider: "runpod", PodID: "w411-radar2", Service: "radar-plant",
		DownSince: 1_700_000_000, DownSeconds: 15360, HourlyUSD: 0.79, ExposureUSD: 3.37,
		Resolved: true,
	}))
	if !ok {
		t.Fatal("R9 should fire on resolved tally")
	}
	draft, has := m.Evidence["clawback_draft"].(string)
	if !has || !strings.Contains(draft, "w411-radar2") || !strings.Contains(draft, "4h16m") {
		t.Fatalf("clawback_draft missing pod or duration: %q", draft)
	}
}

func TestHumanDuration(t *testing.T) {
	cases := map[int64]string{0: "0s", 45: "45s", 300: "5m", 15360: "4h16m"}
	for secs, want := range cases {
		if got := HumanDuration(secs); got != want {
			t.Errorf("HumanDuration(%d) = %q, want %q", secs, got, want)
		}
	}
}
