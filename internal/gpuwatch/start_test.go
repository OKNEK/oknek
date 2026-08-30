package gpuwatch

import (
	"testing"

	"github.com/oknek/oknek/internal/config"
)

func TestBuildProbes_PortAndProcess(t *testing.T) {
	checks := []config.HealthCheck{
		{Name: "radar", Port: 8080},
		{Name: "enc", Process: "ffmpeg"},
		{Name: "both", Port: 9000, Process: "node"},
	}
	got := buildProbes(checks)
	if len(got) != 3 {
		t.Fatalf("want 3 checks, got %d", len(got))
	}
	if len(got[0].probes) != 1 || len(got[2].probes) != 2 {
		t.Fatalf("probe composition wrong: %+v", got)
	}
}

func TestNormalize_Defaults(t *testing.T) {
	cfg := config.GPUSpendConfig{} // all zero
	cfg = normalize(cfg, "host-x")
	if cfg.PollSeconds != 30 || cfg.GraceSeconds != 300 || cfg.PodID != "host-x" || cfg.Provider != "runpod" {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
}
