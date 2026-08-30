package gpuwatch

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/oknek/oknek/internal/config"
	"github.com/oknek/oknek/internal/rules"
)

// normalize fills operational defaults so a hand-written or partial config runs.
func normalize(c config.GPUSpendConfig, hostname string) config.GPUSpendConfig {
	if c.PollSeconds <= 0 {
		c.PollSeconds = 30
	}
	if c.GraceSeconds <= 0 {
		c.GraceSeconds = 300
	}
	if c.Provider == "" {
		c.Provider = "runpod"
	}
	if c.PodID == "" {
		c.PodID = hostname
	}
	return c
}

// buildProbes maps each HealthCheck to its probe set (Port and/or Process).
func buildProbes(checks []config.HealthCheck) []namedProbe {
	out := make([]namedProbe, 0, len(checks))
	for _, c := range checks {
		var probes []HealthProbe
		if c.Port > 0 {
			probes = append(probes, PortProbe{Port: c.Port})
		}
		if c.Process != "" {
			probes = append(probes, ProcessProbe{Pattern: c.Process})
		}
		out = append(out, namedProbe{name: c.Name, probes: probes})
	}
	return out
}

// Start builds a Watcher from config and runs its poll loop until ctx is
// cancelled. emit is the daemon's record-to-store-and-feed function.
func Start(ctx context.Context, raw config.GPUSpendConfig, engine *rules.Engine, emit EmitFunc, logger *log.Logger) {
	host, _ := os.Hostname()
	cfg := normalize(raw, host)
	w := &Watcher{
		pod: cfg.PodID, provider: cfg.Provider, hourlyUSD: cfg.HourlyUSD,
		grace:      time.Duration(cfg.GraceSeconds) * time.Second,
		poll:       time.Duration(cfg.PollSeconds) * time.Second,
		webhookURL: cfg.WebhookURL,
		checks:     buildProbes(cfg.Checks),
		engine:     engine, emit: emit, now: time.Now, logger: logger,
		states: map[string]*serviceState{},
	}
	go w.run(ctx)
}
