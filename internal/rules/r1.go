package rules

import (
	"context"
	"strings"
)

// R1 — subcommand-chain bypass.
//
// Detects bash commands whose chain depth meets or exceeds Threshold.
// Validation: Adversa Research "CC-643" disclosure (April 2026) — Claude Code
// deny rules silently disable for any bash command exceeding 50 subcommands.
//   https://adversa.ai/blog/claude-code-security-bypass-deny-rules-disabled/
//
// Default threshold of 8 is well below the bypass cap so the detection fires
// long before any plausible legitimate chain reaches a worrying length.
type R1 struct {
	Threshold int
	Action    Verdict
}

// NewR1 returns a Rule 1 instance with default threshold (8) and Block action.
func NewR1() *R1 {
	return &R1{Threshold: 8, Action: VerdictBlock}
}

func (r *R1) ID() string   { return "R1" }
func (r *R1) Name() string { return "subcommand-chain bypass" }
func (r *R1) Kind() Kind   { return KindExecObserved }

func (r *R1) Match(ctx context.Context, e Event) (Match, bool) {
	payload, ok := e.Payload.(ExecPayload)
	if !ok {
		return Match{}, false
	}
	depth := ChainDepth(payload.Command)
	if depth < r.Threshold {
		return Match{}, false
	}
	return Match{
		RuleID:  r.ID(),
		Name:    r.Name(),
		Verdict: r.Action,
		Evidence: map[string]interface{}{
			"bash_command":     payload.Command,
			"chain_depth":      depth,
			"threshold":        r.Threshold,
			"agent_identifier": e.AgentID,
			"pid":              e.PID,
			"ppid":             e.PPID,
		},
	}, true
}

// ChainDepth counts the number of subcommand invocations in cmd.
//
// Walks the command character by character, honoring single- and double-quote
// state and backslash escapes. Counts each occurrence of `;`, `&&`, `||`, `|`,
// `&`, and newline as a separator that introduces a new subcommand. Returns 0
// for whitespace-only input, otherwise at least 1.
//
// Intentionally over-counts in shell edge cases (separators inside command
// substitutions, heredocs) — we'd rather false-positive than miss a chained
// bypass.
func ChainDepth(cmd string) int {
	if strings.TrimSpace(cmd) == "" {
		return 0
	}
	n := 1
	inSingle, inDouble := false, false
	escape := false

	for i := 0; i < len(cmd); i++ {
		c := cmd[i]

		if escape {
			escape = false
			continue
		}
		if c == '\\' && !inSingle {
			escape = true
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if inSingle || inDouble {
			continue
		}

		switch c {
		case ';', '\n', '|', '&':
			n++
			// Collapse double operators: `&&`, `||`, `;;` count as one separator.
			if i+1 < len(cmd) && cmd[i+1] == c {
				i++
			}
		}
	}
	return n
}
