package rules

import (
	"context"
	"strings"
)

// R5 — egress to non-allowlisted domain.
//
// Fires when an agent process opens an outbound socket whose destination
// hostname is not in the suffix allowlist. Suffix matching means
// "anthropic.com" allows "api.anthropic.com", "console.anthropic.com",
// "status.anthropic.com", etc., but not "anthropic.com.evil.example".
//
// Validation:
//   - CVE-2025-55284 — Claude Code DNS exfil via pre-approved ping/dig
//   - CVE-2025-59145 "CamoLeak" — Copilot Chat private-source exfiltration
//     (CVSS 9.6) via hidden PR comment + GitHub Camo CSP bypass
//
// Default action: Block. Default allowlist covers the destinations a
// well-behaved agent actually needs (Anthropic, OpenAI, GitHub, package
// registries) — anything else gets a hard stop until the user confirms.
type R5 struct {
	AllowedSuffixes []string
	Action          Verdict
}

// DefaultR5AllowedSuffixes is the v1 starter allowlist. Users extend it via
// /etc/oknek/oknek.yaml (rules.r5.allowed_suffixes).
var DefaultR5AllowedSuffixes = []string{
	// Anthropic
	"anthropic.com",
	// OpenAI
	"openai.com",
	"oaiusercontent.com",
	// GitHub
	"github.com",
	"githubusercontent.com",
	"api.github.com",
	// Google (Gemini)
	"googleapis.com",
	"generativelanguage.googleapis.com",
	// Package registries
	"registry.npmjs.org",
	"npmjs.com",
	"pypi.org",
	"files.pythonhosted.org",
	"crates.io",
	"index.crates.io",
	"static.crates.io",
	// CDN / module hosts
	"cdn.jsdelivr.net",
	"unpkg.com",
	"deno.land",
	"esm.sh",
	// Cloudflare (oknek's own infra; safe by definition for paid customers)
	"oknek.com",
	"pages.dev",
}

// NewR5 returns Rule 5 with the default allowlist and Block action.
func NewR5() *R5 {
	return &R5{
		AllowedSuffixes: append([]string(nil), DefaultR5AllowedSuffixes...),
		Action:          VerdictBlock,
	}
}

func (r *R5) ID() string   { return "R5" }
func (r *R5) Name() string { return "egress to non-allowlisted domain" }
func (r *R5) Kind() Kind   { return KindSocketConnect }

func (r *R5) Match(ctx context.Context, e Event) (Match, bool) {
	p, ok := e.Payload.(SocketConnectPayload)
	if !ok {
		return Match{}, false
	}
	host := strings.ToLower(p.DestHost)
	if host == "" {
		// Without a hostname we can't classify. Fail open for now; the hook
		// layer can later resolve the IP to a hostname and re-fire.
		return Match{}, false
	}
	for _, s := range r.AllowedSuffixes {
		if strings.HasSuffix(host, s) {
			// Match either exactly or as a true subdomain (avoid prefix overlap):
			//   "anthropic.com"     → ok
			//   "api.anthropic.com" → ok
			//   "fakeanthropic.com" → not ok
			if host == s || strings.HasSuffix(host, "."+s) {
				return Match{}, false
			}
		}
	}
	return Match{
		RuleID:  r.ID(),
		Name:    r.Name(),
		Verdict: r.Action,
		Evidence: map[string]interface{}{
			"dest_host":        p.DestHost,
			"dest_ip":          p.DestIP,
			"dest_port":        p.DestPort,
			"process":          p.Process,
			"allowlist_size":   len(r.AllowedSuffixes),
			"agent_identifier": e.AgentID,
			"pid":              e.PID,
		},
	}, true
}
