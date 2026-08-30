package rules

import (
	"context"
	"testing"
)

func newTestR10() *R10 {
	return NewR10("127.0.0.1", 4000,
		[]string{"api.openai.com", "api.anthropic.com"},
		[]string{"litellm"},
		map[string]float64{"default": 0.02, "api.openai.com": 0.03})
}

func r10Event(host, process string, port, pid int) Event {
	return Event{
		Kind: KindSocketConnect, PID: pid,
		Payload: SocketConnectPayload{DestHost: host, DestPort: port, Process: process},
	}
}

func TestR10_DirectProviderCall_Fires(t *testing.T) {
	m, ok := newTestR10().Match(context.Background(), r10Event("api.openai.com", "worker", 443, 4821))
	if !ok {
		t.Fatal("expected R10 to fire on a direct provider call")
	}
	if m.Verdict != VerdictWarn {
		t.Errorf("verdict = %v, want Warn", m.Verdict)
	}
	if m.Evidence["provider"] != "api.openai.com" {
		t.Errorf("provider = %v", m.Evidence["provider"])
	}
	if m.Evidence["est_cost_usd"] != 0.03 {
		t.Errorf("est_cost_usd = %v, want 0.03 (provider override)", m.Evidence["est_cost_usd"])
	}
	if m.Evidence["pid"] != 4821 {
		t.Errorf("pid = %v, want 4821", m.Evidence["pid"])
	}
}

func TestR10_ViaGateway_DoesNotFire(t *testing.T) {
	if _, ok := newTestR10().Match(context.Background(), r10Event("127.0.0.1", "worker", 4000, 1)); ok {
		t.Error("calls to the gateway endpoint must not fire R10")
	}
	if _, ok := newTestR10().Match(context.Background(), r10Event("localhost", "worker", 4000, 1)); ok {
		t.Error("localhost:gateway-port must be treated as via-gateway")
	}
}

func TestR10_NonProvider_DoesNotFire(t *testing.T) {
	if _, ok := newTestR10().Match(context.Background(), r10Event("example.com", "worker", 443, 1)); ok {
		t.Error("non-provider host must not fire R10")
	}
}

func TestR10_ExcludedProcess_DoesNotFire(t *testing.T) {
	if _, ok := newTestR10().Match(context.Background(), r10Event("api.openai.com", "litellm", 443, 1)); ok {
		t.Error("excluded process (the gateway itself) must not fire R10")
	}
}

func TestR10_UnresolvedHost_DoesNotFire(t *testing.T) {
	if _, ok := newTestR10().Match(context.Background(), r10Event("", "worker", 443, 1)); ok {
		t.Error("empty (unresolved) host must not fire — fail open")
	}
}

func TestR10_DefaultEstCost(t *testing.T) {
	m, ok := newTestR10().Match(context.Background(), r10Event("api.anthropic.com", "worker", 443, 1))
	if !ok {
		t.Fatal("expected fire")
	}
	if m.Evidence["est_cost_usd"] != 0.02 {
		t.Errorf("est_cost_usd = %v, want 0.02 (default)", m.Evidence["est_cost_usd"])
	}
}

func TestR10_SubdomainMatch(t *testing.T) {
	if _, ok := newTestR10().Match(context.Background(), r10Event("eu.api.openai.com", "w", 443, 1)); !ok {
		t.Error("subdomain of provider should fire")
	}
	if _, ok := newTestR10().Match(context.Background(), r10Event("api.openai.com.evil.example", "w", 443, 1)); ok {
		t.Error("lookalike suffix must NOT fire")
	}
}
