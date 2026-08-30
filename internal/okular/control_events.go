package okular

import (
	"encoding/json"
	"fmt"
)

// Control events are security-critical, deliberate state changes of the enforcer itself
// (disarm/uninstall and policy changes) — distinct from the high-rate stream of agent
// actions. They are recorded RECORD-FIRST and FAIL-CLOSED: the event must be durably
// escrowed off-box (when a WORM shipper is configured) BEFORE the action proceeds, so a
// disarm or a policy weakening can never be silent. EmitDisarm/EmitPolicy return an error
// the caller MUST treat as "do not proceed".
const (
	EvDisarmAttempt    = "DISARM-ATTEMPT"    // a disarm was requested (token id recorded)
	EvDisarmAuthorized = "DISARM-AUTHORIZED" // the request verified; enforcement is about to drop
	EvDisarmDenied     = "DISARM-DENIED"     // the request failed verification (forged/absent token)
	EvDisarmed         = "DISARMED"          // enforcement actually dropped
	EvPolicySet        = "POLICY-SET"        // a policy was applied (name/version/mode)
	EvPolicyEnforce    = "POLICY-ENFORCE"    // a policy flipped observe->enforce (the loud one)
)

// controlAgent is the reserved ledger "agent" label for enforcer control events, so they
// never collide with a watched agent's name and can be queried as a group.
const controlAgent = "__oknek__"

// DisarmEvent is the payload of a disarm control event.
type DisarmEvent struct {
	TokenID string `json:"token_id"`
	Reason  string `json:"reason,omitempty"`
}

// PolicyEvent is the payload of a policy control event.
type PolicyEvent struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	Mode    string `json:"mode"`
}

// emitControlEvent appends a control event to the ledger and then escrows it off-box
// record-first. Contract: if a shipper is configured and the event cannot be confirmed in
// the off-box WORM store, it returns an error and the caller MUST abort the action. The
// event is still recorded locally (so the attempt is never lost), but "recorded locally,
// not escrowed" is treated as failure — inability to make the record immutable must never
// read as success. Callers serialize control events (they are deliberate, not high-rate).
func (l *Ledger) emitControlEvent(ts int64, kind, detail string) (*Anchor, error) {
	if err := l.Append(ts, controlAgent, kind, "", detail); err != nil {
		return nil, fmt.Errorf("record %s locally: %w", kind, err)
	}
	a, err := l.EmitAnchor(ts)
	if err != nil {
		// appended locally but the off-box escrow PUT failed → fail-closed.
		return a, fmt.Errorf("escrow %s off-box failed (fail-closed, do not proceed): %w", kind, err)
	}
	if l.shipper != nil && a == nil {
		// shipper configured but nothing was checkpointed/shipped for this event.
		return nil, fmt.Errorf("escrow %s off-box not confirmed (fail-closed): no anchor emitted", kind)
	}
	return a, nil
}

// EmitDisarm records a disarm control event (record-first, fail-closed). kind is one of
// the EvDisarm* constants; tokenID ties an authorization to its DISARMED.
func (l *Ledger) EmitDisarm(ts int64, kind, tokenID, reason string) (*Anchor, error) {
	detail, _ := json.Marshal(DisarmEvent{TokenID: tokenID, Reason: reason})
	return l.emitControlEvent(ts, kind, string(detail))
}

// EmitPolicy records a policy control event (record-first, fail-closed). kind is one of
// the EvPolicy* constants.
func (l *Ledger) EmitPolicy(ts int64, kind, name string, version int, mode string) (*Anchor, error) {
	detail, _ := json.Marshal(PolicyEvent{Name: name, Version: version, Mode: mode})
	return l.emitControlEvent(ts, kind, string(detail))
}

// VerifyControlEvents replays the control-event stream and enforces the invariants:
//   - every DISARMED must be preceded by a matching DISARM-AUTHORIZED (same token id) that
//     has not already been consumed — a DISARMED without one is a SILENT off-switch (tamper).
//   - POLICY-ENFORCE events are surfaced so a reviewer sees who opened an agent up, and when.
//
// It runs over the local ledger; the anchor/remote checks (VerifyAnchors/VerifyRemote) are
// what prove that local stream wasn't rewritten, so the two together are sound.
func (l *Ledger) VerifyControlEvents() (ok bool, issues []string, enforced []PolicyEvent, err error) {
	rows, err := l.db.Query(
		"SELECT seq, rule, payload FROM okular_ledger WHERE agent = ? ORDER BY seq ASC", controlAgent)
	if err != nil {
		return false, nil, nil, err
	}
	defer rows.Close()
	authorized := map[string]bool{} // token ids authorized but not yet consumed by a DISARMED
	for rows.Next() {
		var seq int64
		var kind, payload string
		if err := rows.Scan(&seq, &kind, &payload); err != nil {
			return false, nil, nil, err
		}
		switch kind {
		case EvDisarmAuthorized:
			var d DisarmEvent
			_ = json.Unmarshal([]byte(payload), &d)
			authorized[d.TokenID] = true
		case EvDisarmed:
			var d DisarmEvent
			_ = json.Unmarshal([]byte(payload), &d)
			if authorized[d.TokenID] {
				delete(authorized, d.TokenID) // consume the authorization
			} else {
				issues = append(issues, fmt.Sprintf(
					"DISARMED (seq %d, token %q) with no preceding DISARM-AUTHORIZED — silent off-switch",
					seq, d.TokenID))
			}
		case EvPolicyEnforce:
			var p PolicyEvent
			if json.Unmarshal([]byte(payload), &p) == nil {
				enforced = append(enforced, p)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return false, nil, nil, err
	}
	return len(issues) == 0, issues, enforced, nil
}
