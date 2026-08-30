package rules

import (
	"bytes"
	"context"
	"fmt"
)

// R6 — instruction-file indirect prompt injection.
//
// Pre-scans agent-instruction files (CLAUDE.md, AGENT.md, .clinerules,
// .cursor/rules, .continue/config.*, .aider.conf.yml, README files when
// ingested as context) for patterns associated with indirect prompt
// injection. Vendor-agnostic by design — the patterns work across every
// AI coding agent that ingests repo content as context.
//
// Validation:
//   - arXiv 2509.22040 "Your AI, My Shell" — measured 41–84% attack success
//     rate against Cursor and GitHub Copilot via repo-borne injection
//   - Invariant Labs MCP tool poisoning research (April 2025)
//
// Default action: Warn (not Block). Indirect-injection patterns have higher
// false-positive rates than the other rules, so we surface the finding
// rather than freeze the agent — except when multiple high-confidence
// patterns fire on the same file, which we treat as a Block.
type R6 struct {
	Patterns    []InjectionPattern
	MaxScanSize int // skip scans on files larger than this (bytes)
	Action      Verdict
	// BlockOnMultiple raises the action to Block when ≥ N distinct patterns fire.
	BlockOnMultiple int
}

// InjectionPattern is a single named detector. Match returns (true, evidence)
// when the content trips this pattern.
type InjectionPattern struct {
	Name        string
	Description string
	Severity    string // "low" | "medium" | "high"
	Match       func(content []byte) (bool, string)
}

// NewR6 returns Rule 6 with the default pattern bank.
func NewR6() *R6 {
	return &R6{
		Patterns:        defaultR6Patterns(),
		MaxScanSize:     1 << 20, // 1 MiB
		Action:          VerdictWarn,
		BlockOnMultiple: 2,
	}
}

func (r *R6) ID() string   { return "R6" }
func (r *R6) Name() string { return "instruction-file indirect prompt injection" }
func (r *R6) Kind() Kind   { return KindFileScanned }

func (r *R6) Match(ctx context.Context, e Event) (Match, bool) {
	p, ok := e.Payload.(FileScanPayload)
	if !ok {
		return Match{}, false
	}
	if len(p.Content) > r.MaxScanSize {
		return Match{}, false
	}

	var findings []map[string]string
	for _, pat := range r.Patterns {
		if matched, evidence := pat.Match(p.Content); matched {
			findings = append(findings, map[string]string{
				"pattern":     pat.Name,
				"description": pat.Description,
				"severity":    pat.Severity,
				"evidence":    evidence,
			})
		}
	}
	if len(findings) == 0 {
		return Match{}, false
	}

	verdict := r.Action
	if r.BlockOnMultiple > 0 && len(findings) >= r.BlockOnMultiple {
		verdict = VerdictBlock
	}
	return Match{
		RuleID:  r.ID(),
		Name:    r.Name(),
		Verdict: verdict,
		Evidence: map[string]interface{}{
			"path":             p.Path,
			"content_size":     len(p.Content),
			"finding_count":    len(findings),
			"findings":         findings,
			"agent_identifier": e.AgentID,
			"pid":              e.PID,
		},
	}, true
}

// ─── default pattern bank ───────────────────────────────────

func defaultR6Patterns() []InjectionPattern {
	return []InjectionPattern{
		{
			Name:        "ignore-previous-instructions",
			Description: "classic prompt-injection escape phrase",
			Severity:    "high",
			Match: func(c []byte) (bool, string) {
				lc := bytes.ToLower(c)
				for _, p := range []string{
					"ignore previous instructions",
					"ignore all previous instructions",
					"ignore the above",
					"disregard previous",
					"forget your previous",
					"forget all prior",
					"override your instructions",
				} {
					if bytes.Contains(lc, []byte(p)) {
						return true, "matched phrase: " + p
					}
				}
				return false, ""
			},
		},
		{
			Name:        "role-injection",
			Description: "fake SYSTEM/ASSISTANT/USER role markers",
			Severity:    "high",
			Match: func(c []byte) (bool, string) {
				markers := []string{
					"SYSTEM:", "ASSISTANT:", "[SYSTEM]", "[ASSISTANT]",
					"<|im_start|>", "<|system|>", "<|user|>",
					"### Instruction:", "### System:",
				}
				for _, line := range bytes.Split(c, []byte("\n")) {
					trimmed := bytes.TrimSpace(line)
					if len(trimmed) < 3 {
						continue
					}
					for _, m := range markers {
						if bytes.HasPrefix(trimmed, []byte(m)) {
							return true, "role marker at line start: " + m
						}
					}
				}
				return false, ""
			},
		},
		{
			Name:        "white-on-white-text",
			Description: "CSS-style hidden text (visible to LLM, not to humans)",
			Severity:    "high",
			Match: func(c []byte) (bool, string) {
				lc := bytes.ToLower(c)
				for _, p := range []string{
					"color:white", "color:#fff", "color: #fff",
					"color: white", "display:none", "display: none",
					"font-size:0", "font-size: 0",
					"visibility:hidden", "visibility: hidden",
					"opacity:0", "opacity: 0",
				} {
					if bytes.Contains(lc, []byte(p)) {
						return true, "css hide rule: " + p
					}
				}
				return false, ""
			},
		},
		{
			Name:        "long-base64-blob",
			Description: "suspiciously long base64 run (>= 200 chars)",
			Severity:    "medium",
			Match: func(c []byte) (bool, string) {
				run := 0
				maxRun := 0
				for _, b := range c {
					if isBase64Char(b) {
						run++
						if run > maxRun {
							maxRun = run
						}
					} else {
						run = 0
					}
				}
				if maxRun >= 200 {
					return true, fmt.Sprintf("continuous base64 run of %d chars", maxRun)
				}
				return false, ""
			},
		},
		{
			Name:        "zero-width-unicode",
			Description: "excessive zero-width characters (invisible instructions)",
			Severity:    "medium",
			Match: func(c []byte) (bool, string) {
				// Zero-width and non-rendering Unicode codepoints commonly used
				// to hide imperatives in plain-looking text:
				//   U+200B zero-width space, U+200C zero-width non-joiner,
				//   U+200D zero-width joiner, U+2060 word joiner, U+FEFF BOM.
				count := 0
				s := string(c)
				for _, r := range s {
					switch r {
					case 0x200b, 0x200c, 0x200d, 0x2060, 0xfeff:
						count++
					}
				}
				if count > 20 {
					return true, fmt.Sprintf("%d zero-width chars", count)
				}
				return false, ""
			},
		},
		{
			Name:        "html-comment-imperative",
			Description: "HTML comment containing imperative instructions",
			Severity:    "medium",
			Match: func(c []byte) (bool, string) {
				lc := bytes.ToLower(c)
				i := 0
				for {
					start := bytes.Index(lc[i:], []byte("<!--"))
					if start == -1 {
						break
					}
					start += i
					end := bytes.Index(lc[start:], []byte("-->"))
					if end == -1 {
						break
					}
					inner := lc[start+4 : start+end]
					for _, p := range []string{
						"ignore", "system:", "you must", "you should",
						"please run", "execute the following", "do not tell",
					} {
						if bytes.Contains(inner, []byte(p)) {
							return true, "imperative in HTML comment: " + p
						}
					}
					i = start + end + 3
				}
				return false, ""
			},
		},
	}
}

func isBase64Char(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '+' || b == '/' || b == '=':
		return true
	}
	return false
}
