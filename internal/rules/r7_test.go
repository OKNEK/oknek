package rules

import (
	"context"
	"testing"
)

// fakeScorer is a deterministic in-memory BaselineScorer for tests.
type fakeScorer struct {
	scores map[string]float64
	novel  map[string][]string
	errs   map[string]error
}

func (f *fakeScorer) Score(agentID string, features []string) (float64, []string, error) {
	key := agentID + "|" + joinFeatures(features)
	return f.scores[key], f.novel[key], f.errs[key]
}
func (f *fakeScorer) Observe(agentID, feature string) error { return nil }

func joinFeatures(fs []string) string {
	s := ""
	for i, f := range fs {
		if i > 0 {
			s += ","
		}
		s += f
	}
	return s
}

func TestR7_Match(t *testing.T) {
	scorer := &fakeScorer{
		scores: map[string]float64{
			"agent-a|exec:git,exec:ls":              0,   // familiar
			"agent-a|exec:nc":                       1,   // single novel — below threshold
			"agent-a|exec:nc,exec:base64":           2,   // two novel — at threshold
			"agent-a|exec:nc,exec:base64,exec:eval": 3,   // way above
			"agent-a|exec:curl":                     0.5, // rare but not novel
		},
		novel: map[string][]string{
			"agent-a|exec:nc":                       {"exec:nc"},
			"agent-a|exec:nc,exec:base64":           {"exec:nc", "exec:base64"},
			"agent-a|exec:nc,exec:base64,exec:eval": {"exec:nc", "exec:base64", "exec:eval"},
		},
	}
	r := NewR7(scorer) // Threshold 2.0, Warn

	cases := []struct {
		name      string
		features  []string
		wantMatch bool
	}{
		{"familiar features → no fire", []string{"exec:git", "exec:ls"}, false},
		{"one novel feature (score 1.0) below threshold", []string{"exec:nc"}, false},
		{"two novel features (score 2.0) at threshold", []string{"exec:nc", "exec:base64"}, true},
		{"three novel features (score 3.0)", []string{"exec:nc", "exec:base64", "exec:eval"}, true},
		{"rare feature only (0.5) below", []string{"exec:curl"}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := Event{
				Kind:    KindBaselineDrift,
				AgentID: "agent-a",
				Payload: BaselineDriftPayload{Features: c.features},
			}
			m, ok := r.Match(context.Background(), ev)
			if ok != c.wantMatch {
				t.Errorf("R7.Match ok = %v, want %v", ok, c.wantMatch)
				return
			}
			if ok && m.Verdict != VerdictWarn {
				t.Errorf("expected Warn, got %v", m.Verdict)
			}
			if ok {
				if _, hasNovel := m.Evidence["novel_features"]; !hasNovel {
					t.Errorf("evidence missing novel_features")
				}
			}
		})
	}
}

func TestR7_NoScorer_NoFire(t *testing.T) {
	r := &R7{Scorer: nil, Threshold: 0, Action: VerdictWarn}
	ev := Event{Kind: KindBaselineDrift, AgentID: "x", Payload: BaselineDriftPayload{Features: []string{"any"}}}
	if _, ok := r.Match(context.Background(), ev); ok {
		t.Errorf("R7 with nil scorer should never fire")
	}
}

func TestR7_WrongPayloadKind(t *testing.T) {
	r := NewR7(&fakeScorer{})
	ev := Event{Kind: KindBaselineDrift, Payload: "not a BaselineDriftPayload"}
	if _, ok := r.Match(context.Background(), ev); ok {
		t.Errorf("R7 matched on wrong payload type")
	}
}

func TestEngine_AllSevenRulesRegistered(t *testing.T) {
	e := NewEngine()
	scorer := &fakeScorer{
		scores: map[string]float64{"agent-x|exec:nc,exec:base64,exec:eval": 3.0},
		novel:  map[string][]string{"agent-x|exec:nc,exec:base64,exec:eval": {"exec:nc", "exec:base64", "exec:eval"}},
	}
	for _, r := range []Rule{NewR1(), NewR2(), NewR3(), NewR4(), NewR5(), NewR6(), NewR7(scorer)} {
		e.Register(r)
	}
	if e.Count() != 7 {
		t.Fatalf("Count() = %d, want 7 — the full v1 catalog", e.Count())
	}
	driftEv := Event{
		Kind:    KindBaselineDrift,
		AgentID: "agent-x",
		Payload: BaselineDriftPayload{Features: []string{"exec:nc", "exec:base64", "exec:eval"}},
	}
	matches := e.Evaluate(context.Background(), driftEv)
	if len(matches) != 1 || matches[0].RuleID != "R7" {
		t.Errorf("expected one R7 match on drift event, got %+v", matches)
	}
}
