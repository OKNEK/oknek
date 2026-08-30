package rules

import (
	"context"
)

// R4 — MCP URL drift.
//
// Fires when an agent attempts to use an MCP server endpoint that is not in
// the approved allowlist. The hook layer is expected to populate
// KnownEndpoints with canonical keys for each MCP server the user has
// explicitly approved (typically captured at install time and on each user
// confirmation).
//
// Validation:
//   - CVE-2025-54136 "MCPoison" — once a Cursor MCP server is approved, its
//     command can be swapped silently → persistent RCE
//   - CVE-2025-6514 — mcp-remote npm package versions 0.0.5–0.1.15 allow
//     arbitrary OS command execution on connect to a malicious server
//
// Default action: Block. Each endpoint identity is canonicalized as
// "<transport>:<command|url>" so that swapping the underlying command for
// a previously-approved server name reads as drift.
type R4 struct {
	KnownEndpoints map[string]bool
	Action         Verdict
}

// NewR4 returns Rule 4 with an empty allowlist (deny-by-default) and Block action.
func NewR4() *R4 {
	return &R4{KnownEndpoints: make(map[string]bool), Action: VerdictBlock}
}

func (r *R4) ID() string   { return "R4" }
func (r *R4) Name() string { return "MCP URL drift" }
func (r *R4) Kind() Kind   { return KindMCPEndpoint }

// Allow adds a canonical endpoint to the known list. Useful for setting up
// baselines from the daemon's persistent baseline store.
func (r *R4) Allow(transport, target string) {
	r.KnownEndpoints[canonicalMCPKey(transport, target)] = true
}

func (r *R4) Match(ctx context.Context, e Event) (Match, bool) {
	p, ok := e.Payload.(MCPEndpointPayload)
	if !ok {
		return Match{}, false
	}
	target := p.Command
	if p.URL != "" {
		target = p.URL
	}
	key := canonicalMCPKey(p.Transport, target)
	if r.KnownEndpoints[key] {
		return Match{}, false
	}
	return Match{
		RuleID:  r.ID(),
		Name:    r.Name(),
		Verdict: r.Action,
		Evidence: map[string]interface{}{
			"server_name":      p.ServerName,
			"transport":        p.Transport,
			"target":           target,
			"canonical_key":    key,
			"known_count":      len(r.KnownEndpoints),
			"agent_identifier": e.AgentID,
			"pid":              e.PID,
		},
	}, true
}

func canonicalMCPKey(transport, target string) string {
	return transport + ":" + target
}
