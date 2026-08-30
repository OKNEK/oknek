package rules

import (
	"context"
	"strings"
)

// R2 — settings.json permission flip.
//
// Fires when an AI agent's permission or policy configuration file is
// created or modified. Default action is Block — we want the user to
// explicitly verify the change before the agent picks up the new policy.
//
// Validation:
//   - CVE-2025-53773 (GitHub Copilot RCE via prompt-injected settings.json
//     write that flips YOLO/auto-approve)
//   - CVE-2025-54136 "MCPoison" (Cursor — once an MCP server is approved,
//     its command can be swapped silently for a persistent RCE)
//
// Matches by suffix on a curated list of agent-config paths.
type R2 struct {
	// Suffixes is the list of path suffixes to watch.
	// A path matches if it ends with any entry in this slice.
	Suffixes []string
	// Action when a match fires.
	Action Verdict
}

// DefaultR2Suffixes is the v1 list of agent-config files that, when modified
// or created, will fire R2. Users can extend via config.
var DefaultR2Suffixes = []string{
	"/.claude/settings.json",
	"/.claude/settings.local.json",
	"/.cursor/mcp.json",
	"/.cursor/settings.json",
	"/.cursor/rules",
	"/.clinerules",
	"/.continue/config.json",
	"/.continue/config.ts",
	"/.aider.conf.yml",
	"/.config/github-copilot/config.json",
	"/.vscode/settings.json", // VS Code workspace settings — watched only when
	                          // an AI extension is the writer (filter at hook layer)
}

// NewR2 returns Rule 2 with default watched suffixes and Block action.
func NewR2() *R2 {
	return &R2{Suffixes: append([]string(nil), DefaultR2Suffixes...), Action: VerdictBlock}
}

func (r *R2) ID() string   { return "R2" }
func (r *R2) Name() string { return "settings.json permission flip" }
func (r *R2) Kind() Kind   { return KindFileChanged }

func (r *R2) Match(ctx context.Context, e Event) (Match, bool) {
	p, ok := e.Payload.(FileChangePayload)
	if !ok {
		return Match{}, false
	}
	// Delete is informational, not actionable; only create/modify fire R2.
	if p.Op == FileOpDelete {
		return Match{}, false
	}
	matched := matchSuffix(p.Path, r.Suffixes)
	if matched == "" {
		return Match{}, false
	}
	return Match{
		RuleID:  r.ID(),
		Name:    r.Name(),
		Verdict: r.Action,
		Evidence: map[string]interface{}{
			"path":             p.Path,
			"op":               string(p.Op),
			"matched_suffix":   matched,
			"old_hash":         p.OldHash,
			"new_hash":         p.NewHash,
			"agent_identifier": e.AgentID,
			"pid":              e.PID,
			"ppid":             e.PPID,
		},
	}, true
}

// matchSuffix returns the first matching suffix, or "" if none match.
func matchSuffix(path string, suffixes []string) string {
	for _, s := range suffixes {
		if strings.HasSuffix(path, s) {
			return s
		}
	}
	return ""
}
