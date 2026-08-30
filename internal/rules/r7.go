package rules

import "context"

// BaselineScorer is the dependency R7 needs to compute drift. The store package
// provides the canonical implementation; tests can fake it.
type BaselineScorer interface {
	// Score returns the drift score and the list of never-seen features.
	Score(agentID string, features []string) (score float64, novel []string, err error)
	// Observe records that an agent triggered a feature (one occurrence).
	Observe(agentID, feature string) error
}

// BaselineDriftPayload is the payload for KindBaselineDrift events. The hook
// layer (or the engine itself, in synthetic-check flows) is responsible for
// extracting the list of relevant features from a higher-level event before
// emitting a drift event.
type BaselineDriftPayload struct {
	Features []string // categorical features to score against the baseline
}

// R7 — behavioral drift score.
//
// The catch-all rule. Fires when an agent does something its 14-day rolling
// baseline has never (or rarely) seen. Default action Warn (not Block) because
// novelty != malice — the value is in surfacing the change for review.
//
// Validation:
//   - OWASP ASI09 — Human-Agent Trust Exploitation
//   - LayerX "Tainted Memories" (Oct 2025) — Atlas browser persistent memory
//     poisoning that none of R1–R6 catch directly
//
// Scoring: BaselineScorer.Score returns +1.0 per never-seen feature, +0.5 per
// rare feature (count < 3). R7 fires when total ≥ Threshold (default 2.0).
type R7 struct {
	Scorer    BaselineScorer
	Threshold float64
	Action    Verdict
}

// NewR7 returns Rule 7 wired to scorer with threshold 2.0 (two novel-or-rare
// features in a single drift event) and Action Warn.
func NewR7(scorer BaselineScorer) *R7 {
	return &R7{Scorer: scorer, Threshold: 2.0, Action: VerdictWarn}
}

func (r *R7) ID() string   { return "R7" }
func (r *R7) Name() string { return "behavioral drift score" }
func (r *R7) Kind() Kind   { return KindBaselineDrift }

func (r *R7) Match(ctx context.Context, e Event) (Match, bool) {
	if r.Scorer == nil {
		return Match{}, false
	}
	p, ok := e.Payload.(BaselineDriftPayload)
	if !ok {
		return Match{}, false
	}
	score, novel, err := r.Scorer.Score(e.AgentID, p.Features)
	if err != nil || score < r.Threshold {
		return Match{}, false
	}
	return Match{
		RuleID:  r.ID(),
		Name:    r.Name(),
		Verdict: r.Action,
		Evidence: map[string]interface{}{
			"score":            score,
			"threshold":        r.Threshold,
			"novel_features":   novel,
			"evaluated":        p.Features,
			"agent_identifier": e.AgentID,
			"pid":              e.PID,
		},
	}, true
}
