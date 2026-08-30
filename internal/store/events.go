package store

// EventRecord is one persisted detection event.
type EventRecord struct {
	ID      string `json:"id"`
	TS      int64  `json:"ts"`
	AgentID string `json:"agent_id"`
	RuleID  string `json:"rule_id"`
	Verdict string `json:"verdict"`
	Payload string `json:"payload_json"`
}

// InsertEvent writes one detection event. id must be unique; a repeat id
// replaces the prior row (idempotent for retried writes).
func (s *Store) InsertEvent(id string, ts int64, agentID, ruleID, verdict, payloadJSON string) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO events (id, ts, agent_id, rule_id, verdict, payload_json)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, ts, agentID, ruleID, verdict, payloadJSON,
	)
	return err
}

// CountByVerdict returns how many events carry the given verdict.
func (s *Store) CountByVerdict(verdict string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE verdict = ?`, verdict).Scan(&n)
	return n, err
}

// CountByRule returns how many events were produced by the given rule.
func (s *Store) CountByRule(ruleID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE rule_id = ?`, ruleID).Scan(&n)
	return n, err
}

// EventsByRule returns up to limit events for the given rule, newest first.
func (s *Store) EventsByRule(ruleID string, limit int) ([]EventRecord, error) {
	rows, err := s.db.Query(
		`SELECT id, ts, agent_id, rule_id, verdict, payload_json
		 FROM events WHERE rule_id = ? ORDER BY ts DESC LIMIT ?`, ruleID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EventRecord
	for rows.Next() {
		var e EventRecord
		if err := rows.Scan(&e.ID, &e.TS, &e.AgentID, &e.RuleID, &e.Verdict, &e.Payload); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DistinctAgentCount returns the number of distinct non-empty agent_ids seen.
func (s *Store) DistinctAgentCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(DISTINCT agent_id) FROM events WHERE agent_id <> ''`).Scan(&n)
	return n, err
}

// RecentEvents returns up to limit events, newest first.
func (s *Store) RecentEvents(limit int) ([]EventRecord, error) {
	rows, err := s.db.Query(
		`SELECT id, ts, agent_id, rule_id, verdict, payload_json
		 FROM events ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EventRecord
	for rows.Next() {
		var e EventRecord
		if err := rows.Scan(&e.ID, &e.TS, &e.AgentID, &e.RuleID, &e.Verdict, &e.Payload); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
