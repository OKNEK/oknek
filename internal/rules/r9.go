package rules

import (
	"context"
	"fmt"
	"time"
)

// R9 — billed-while-broken (GPU cost reconciler).
//
// Fires Warn when the gpuwatch governor reports a watched workload that has
// been down (while its pod kept billing) for at least MinDownSeconds. Alert
// only — never Block. MinDownSeconds is wired from the watcher's grace period
// at registration so the two gates cannot drift.
type R9 struct {
	MinDownSeconds int64
	Action         Verdict
}

// NewR9 returns Rule 9 gated at minDownSeconds (the watcher's grace period),
// action Warn.
func NewR9(minDownSeconds int64) *R9 {
	return &R9{MinDownSeconds: minDownSeconds, Action: VerdictWarn}
}

func (r *R9) ID() string   { return "R9" }
func (r *R9) Name() string { return "billed-while-broken (GPU cost reconciler)" }
func (r *R9) Kind() Kind   { return KindCostAnomaly }

func (r *R9) Match(ctx context.Context, e Event) (Match, bool) {
	p, ok := e.Payload.(CostAnomalyPayload)
	if !ok || p.DownSeconds < r.MinDownSeconds {
		return Match{}, false
	}
	ev := map[string]interface{}{
		"agent_identifier": e.AgentID,
		"pid":              e.PID,
		"provider":         p.Provider,
		"pod_id":           p.PodID,
		"service":          p.Service,
		"down_since":       p.DownSince,
		"down_seconds":     p.DownSeconds,
		"hourly_usd":       p.HourlyUSD,
		"exposure_usd":     p.ExposureUSD,
		"resolved":         p.Resolved,
	}
	if p.Resolved {
		ev["clawback_draft"] = clawbackDraft(p)
	}
	return Match{RuleID: r.ID(), Name: r.Name(), Verdict: r.Action, Evidence: ev}, true
}

// clawbackDraft renders the support-ticket text for a resolved incident.
func clawbackDraft(p CostAnomalyPayload) string {
	start := time.Unix(p.DownSince, 0).UTC()
	end := time.Unix(p.DownSince+p.DownSeconds, 0).UTC()
	return fmt.Sprintf(
		"Pod %s remained running and billed from %s to %s UTC (%s) while the workload %q was non-functional. Requesting credit for the billed-while-broken window (est. $%.2f @ $%.2f/hr).",
		p.PodID, start.Format("2006-01-02 15:04"), end.Format("15:04"),
		HumanDuration(p.DownSeconds), p.Service, p.ExposureUSD, p.HourlyUSD,
	)
}

// HumanDuration renders seconds as "4h16m" / "5m" / "45s". Exported so the
// gpuwatch notifier can reuse it for the Dean alert line.
func HumanDuration(secs int64) string {
	if secs < 0 {
		secs = 0
	}
	h := secs / 3600
	m := (secs % 3600) / 60
	s := secs % 60
	switch {
	case h > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm", m)
	default:
		return fmt.Sprintf("%ds", s)
	}
}
