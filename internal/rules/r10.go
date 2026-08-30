package rules

import (
	"context"
	"strings"
)

// R10 — route-around (LLM cost-gateway bypass).
//
// Fires when a watched process makes an outbound connection to a known LLM-API
// provider host directly, instead of routing through the configured cost
// gateway. This is the "route-around" overspend the OSS detector surfaces.
//
// Warn-only: the detector makes the bypass visible; it never blocks. Hard
// enforcement (SIGKILL / tamper-resistant block) is the paid control plane.
type R10 struct {
	GatewayHost    string
	GatewayPort    int
	Providers      []string
	ExcludeProc    []string
	EstCostPerCall map[string]float64
	Action         Verdict
}

// NewR10 builds the route-around rule from already-normalized settings.
func NewR10(gatewayHost string, gatewayPort int, providers, excludeProc []string, estCost map[string]float64) *R10 {
	return &R10{
		GatewayHost:    gatewayHost,
		GatewayPort:    gatewayPort,
		Providers:      append([]string(nil), providers...),
		ExcludeProc:    append([]string(nil), excludeProc...),
		EstCostPerCall: estCost,
		Action:         VerdictWarn,
	}
}

func (r *R10) ID() string   { return "R10" }
func (r *R10) Name() string { return "route-around (LLM cost-gateway bypass)" }
func (r *R10) Kind() Kind   { return KindSocketConnect }

func (r *R10) Match(ctx context.Context, e Event) (Match, bool) {
	p, ok := e.Payload.(SocketConnectPayload)
	if !ok {
		return Match{}, false
	}
	host := strings.ToLower(strings.TrimSpace(p.DestHost))
	if host == "" {
		return Match{}, false // unresolved (IP-only / cache miss) — fail open
	}
	for _, ex := range r.ExcludeProc {
		if ex != "" && strings.EqualFold(p.Process, ex) {
			return Match{}, false
		}
	}
	if r.isGateway(host, p.DestPort) {
		return Match{}, false // the good path — went through the gateway
	}
	provider := r.matchProvider(host)
	if provider == "" {
		return Match{}, false
	}
	return Match{
		RuleID:  r.ID(),
		Name:    r.Name(),
		Verdict: r.Action,
		Evidence: map[string]interface{}{
			"provider":     provider,
			"dest_host":    p.DestHost,
			"dest_port":    p.DestPort,
			"process":      p.Process,
			"pid":          e.PID,
			"ppid":         e.PPID,
			"via_gateway":  false,
			"est_cost_usd": r.estCost(provider),
		},
	}, true
}

func (r *R10) isGateway(host string, port int) bool {
	if port != r.GatewayPort {
		return false
	}
	gh := strings.ToLower(r.GatewayHost)
	if host == gh {
		return true
	}
	local := func(h string) bool { return h == "127.0.0.1" || h == "localhost" || h == "::1" }
	return local(gh) && local(host)
}

// matchProvider returns the matched provider suffix, or "" if host is not a provider.
func (r *R10) matchProvider(host string) string {
	for _, s := range r.Providers {
		s = strings.ToLower(s)
		if host == s || strings.HasSuffix(host, "."+s) {
			return s
		}
	}
	return ""
}

func (r *R10) estCost(provider string) float64 {
	if v, ok := r.EstCostPerCall[provider]; ok {
		return v
	}
	return r.EstCostPerCall["default"]
}
