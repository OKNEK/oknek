package store

import (
	"database/sql"
	"errors"
	"time"
)

// Default behavioral-baseline window used by R7. 14 days.
const baselineWindow = 14 * 24 * time.Hour

// ObserveBaseline records that an agent triggered a feature.
// Features are arbitrary categorical strings derived by the rule engine
// (e.g. "exec:git", "open:.env", "socket:443:anthropic.com"). Repeated
// observations within the rolling window increment the count.
func (s *Store) ObserveBaseline(agentID, feature string) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(
		`INSERT INTO baseline (agent_id, feature, count, observed_at)
		 VALUES (?, ?, 1, ?)
		 ON CONFLICT(agent_id, feature) DO UPDATE SET
		     count = count + 1,
		     observed_at = excluded.observed_at`,
		agentID, feature, now,
	)
	return err
}

// BaselineScore returns the R7 drift score for (agentID, features).
//
// Scoring (simple, intentionally aggressive on novelty):
//   +1.0 for any feature the agent has never seen in the window
//   +0.5 for any feature with count < 3 in the window  ("rare")
//   +0.0 for any feature with count >= 3 in the window ("familiar")
//
// novel returns the list of never-seen features in the input.
// Features outside the baselineWindow are treated as never-seen.
func (s *Store) BaselineScore(agentID string, features []string) (score float64, novel []string, err error) {
	cutoff := time.Now().Add(-baselineWindow).Unix()
	for _, f := range features {
		var count int
		err = s.db.QueryRow(
			`SELECT count FROM baseline
			 WHERE agent_id = ? AND feature = ? AND observed_at > ?`,
			agentID, f, cutoff,
		).Scan(&count)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return 0, nil, err
		}
		err = nil // ErrNoRows handled below as count == 0
		switch {
		case count == 0:
			score += 1.0
			novel = append(novel, f)
		case count < 3:
			score += 0.5
		}
	}
	return score, novel, nil
}

// BaselineSize returns the total number of (agent, feature) rows currently
// tracked across all agents. Used by /status to indicate baseline health.
func (s *Store) BaselineSize() int {
	var n int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM baseline").Scan(&n)
	return n
}
