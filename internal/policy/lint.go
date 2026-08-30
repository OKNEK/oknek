package policy

import "fmt"

// LintResult separates hard Errors (must block `apply`) from advisory Warnings.
type LintResult struct {
	Errors   []string
	Warnings []string
}

// OK reports whether the policy is safe to apply (no errors).
func (r LintResult) OK() bool { return len(r.Errors) == 0 }

func (r *LintResult) err(format string, a ...interface{}) {
	r.Errors = append(r.Errors, fmt.Sprintf(format, a...))
}
func (r *LintResult) warn(format string, a ...interface{}) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, a...))
}

// validModes / validDefaults are the accepted enum values.
var validModes = map[string]bool{"": true, "observe": true, "enforce": true}

// Lint validates a parsed AgentPolicy. The non-negotiable rule is the BRICK-THE-BOX guard:
// an enforce + default-deny policy with no selector would apply host-wide and could brick the
// machine — that is a hard error. Everything else (weak selector, non-deny default, egress
// without a resolver, unenforced domain rules) is a warning.
func Lint(p *AgentPolicy) LintResult {
	var r LintResult
	if p == nil {
		r.err("nil policy")
		return r
	}
	if p.Kind != "AgentPolicy" {
		r.err("kind must be \"AgentPolicy\", got %q", p.Kind)
	}
	if p.Metadata.Name == "" {
		r.err("metadata.name is required")
	}
	if !validModes[p.Mode] {
		r.err("mode must be \"observe\" or \"enforce\", got %q", p.Mode)
	}
	enforcing := p.Mode == "enforce"
	denyDefault := p.Default == "deny" || p.Default == ""

	// THE brick-the-box guard: a host-wide enforce + deny-all has no selector to scope it.
	if enforcing && denyDefault && p.Selector.empty() {
		r.err("enforce + default-deny with NO selector would apply host-wide (brick-the-box risk) — add a selector")
	}
	// A selector that exists but is only the spoofable envLabel under enforce.
	if enforcing && !p.Selector.empty() && !p.Selector.strong() {
		r.warn("selector is envLabel-only (spoofable) — bind an enforce policy on agentId/cgroup/containerImage/exePath")
	}
	// Default must be the deny spine; `allow` is monitoring-only.
	if p.Default != "" && p.Default != "deny" && p.Default != "allow" {
		r.err("default must be \"deny\" (or \"allow\" for explicit monitoring-only), got %q", p.Default)
	}
	if p.Default == "allow" {
		r.warn("default:allow is monitoring-only — the supported security spine is default:deny")
	}
	// Egress locked (default-deny + an egress allowlist) but no resolver -> DNS breaks.
	if denyDefault && len(p.Allow.Network.Egress) > 0 && !hasResolver(p.Allow.Network.Egress) {
		r.warn("egress is locked but no resolver entry — DNS resolution will break; add `resolver: <ip>`")
	}
	// Domain rules are v2 (DNS-aware) and not yet enforced — warn so no one ships on them.
	if n := countDomains(p.Allow.Network.Egress) + countDomains(p.Allow.Network.Deny); n > 0 {
		r.warn("%d domain-name egress rule(s) present — NOT YET ENFORCED (v1 is IP/CIDR + resolver); use cidr/port for now", n)
	}
	return r
}

func hasResolver(rules []EgressRule) bool {
	for _, e := range rules {
		if e.Resolver != "" {
			return true
		}
	}
	return false
}

func countDomains(rules []EgressRule) int {
	n := 0
	for _, e := range rules {
		if e.Domain != "" {
			n++
		}
	}
	return n
}
