package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExfilWatch_Defaults(t *testing.T) {
	c := NormalizeExfilWatch(ExfilWatchConfig{Enabled: true})
	if c.BeaconMinCount != 4 || c.BeaconJitterTolerance != 0.15 || c.BeaconMinIntervalSeconds != 1 {
		t.Errorf("beacon defaults wrong: %+v", c)
	}
	if c.VelocityWindowSeconds != 30 || c.VelocityMaxConnects != 40 || c.CooldownSeconds != 300 {
		t.Errorf("velocity/cooldown defaults wrong: %+v", c)
	}
}

func TestLoad_ExfilWatchParse(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "oknek.yaml")
	yaml := "exfil_watch:\n  enabled: true\n  beacon_min_count: 6\n  velocity_max_connects: 99\n"
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ExfilWatch.Enabled || cfg.ExfilWatch.BeaconMinCount != 6 || cfg.ExfilWatch.VelocityMaxConnects != 99 {
		t.Errorf("exfil_watch parsed wrong: %+v", cfg.ExfilWatch)
	}
}

func TestLoad_DisarmParse(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "oknek.yaml")
	yaml := "disarm:\n  enabled: true\n  pub_key: deadbeef\n  marker_path: /var/lib/oknek/disarm.marker\n  max_token_age_seconds: 600\n"
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Disarm.Enabled || cfg.Disarm.PubKey != "deadbeef" ||
		cfg.Disarm.MarkerPath != "/var/lib/oknek/disarm.marker" || cfg.Disarm.MaxTokenAgeSeconds != 600 {
		t.Fatalf("disarm config did not parse: %+v", cfg.Disarm)
	}
}

func TestDefault_DevBase(t *testing.T) {
	cfg := Default()
	if cfg.Socket == "" || cfg.DBPath == "" {
		t.Fatalf("default config has empty paths: %+v", cfg)
	}
	if cfg.BaselineDays != 14 {
		t.Errorf("baseline_days default = %d, want 14", cfg.BaselineDays)
	}
}

func TestLoad_MissingFile_ReturnsDefault(t *testing.T) {
	cfg, err := Load("/no/such/file/oknek.yaml")
	if err != nil {
		t.Fatalf("Load missing file returned error: %v", err)
	}
	if cfg.Socket == "" {
		t.Errorf("Load missing file returned empty config")
	}
}

func TestLoad_OverlaysDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "oknek.yaml")
	content := []byte("baseline_days: 30\nsocket: /tmp/custom.sock\n")
	if err := os.WriteFile(cfgPath, content, 0o644); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BaselineDays != 30 {
		t.Errorf("baseline_days = %d, want 30", cfg.BaselineDays)
	}
	if cfg.Socket != "/tmp/custom.sock" {
		t.Errorf("socket = %q, want /tmp/custom.sock", cfg.Socket)
	}
	// fields not set in YAML should keep defaults
	if cfg.DBPath == "" {
		t.Errorf("db_path was overridden to empty; should keep default")
	}
}

func TestEnsureDirs(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		Socket:   filepath.Join(dir, "run", "oknek.sock"),
		DBPath:   filepath.Join(dir, "lib", "oknek.db"),
		LogPath:  filepath.Join(dir, "log", "oknek.log"),
		RulesDir: filepath.Join(dir, "rules", "active"),
	}
	if err := cfg.EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	for _, d := range []string{
		filepath.Join(dir, "run"),
		filepath.Join(dir, "lib"),
		filepath.Join(dir, "log"),
		filepath.Join(dir, "rules", "active"),
	} {
		if _, err := os.Stat(d); err != nil {
			t.Errorf("expected dir %s to exist: %v", d, err)
		}
	}
}

func TestNormalizeRouteAround_AppliesDefaults(t *testing.T) {
	got := NormalizeRouteAround(RouteAroundConfig{Enabled: true})
	if len(got.Providers) == 0 {
		t.Fatal("providers default not applied")
	}
	if got.EstCostPerCall["default"] != 0.02 {
		t.Errorf("default est cost = %v, want 0.02", got.EstCostPerCall["default"])
	}
	if got.SoftCap.WindowSeconds != 3600 {
		t.Errorf("window = %d, want 3600", got.SoftCap.WindowSeconds)
	}
}

func TestNormalizeRouteAround_KeepsProvided(t *testing.T) {
	in := RouteAroundConfig{
		Providers:      []string{"api.openai.com"},
		EstCostPerCall: map[string]float64{"default": 0.05},
		SoftCap:        SoftCapConfig{WindowSeconds: 60},
	}
	got := NormalizeRouteAround(in)
	if len(got.Providers) != 1 {
		t.Errorf("providers overwritten: %v", got.Providers)
	}
	if got.EstCostPerCall["default"] != 0.05 {
		t.Errorf("est cost overwritten: %v", got.EstCostPerCall["default"])
	}
	if got.SoftCap.WindowSeconds != 60 {
		t.Errorf("window overwritten: %d", got.SoftCap.WindowSeconds)
	}
}

func TestLoad_RouteAroundBlock(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/oknek.yaml"
	yaml := `
route_around:
  enabled: true
  gateway: { host: "127.0.0.1", port: 4000 }
  providers: ["api.openai.com", "api.anthropic.com"]
  exclude_processes: ["litellm"]
  est_cost_per_call: { default: 0.02, "api.openai.com": 0.03 }
  soft_cap: { window_seconds: 1800, budget_usd: 5.0 }
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ra := cfg.RouteAround
	if !ra.Enabled {
		t.Error("enabled should be true")
	}
	if ra.Gateway.Host != "127.0.0.1" || ra.Gateway.Port != 4000 {
		t.Errorf("gateway = %+v, want 127.0.0.1:4000", ra.Gateway)
	}
	if len(ra.Providers) != 2 {
		t.Errorf("providers = %v", ra.Providers)
	}
	if len(ra.ExcludeProc) != 1 || ra.ExcludeProc[0] != "litellm" {
		t.Errorf("exclude_processes = %v", ra.ExcludeProc)
	}
	if ra.EstCostPerCall["api.openai.com"] != 0.03 {
		t.Errorf("est_cost_per_call[api.openai.com] = %v, want 0.03", ra.EstCostPerCall["api.openai.com"])
	}
	if ra.SoftCap.WindowSeconds != 1800 || ra.SoftCap.BudgetUSD != 5.0 {
		t.Errorf("soft_cap = %+v", ra.SoftCap)
	}
}

func TestLoad_GPUSpend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oknek.yaml")
	yaml := `
gpu_spend:
  enabled: true
  provider: runpod
  pod_id: w411-radar2
  hourly_usd: 0.79
  poll_seconds: 30
  grace_seconds: 300
  webhook_url: "https://example/hook"
  checks:
    - name: radar-plant
      port: 8080
    - name: encoder
      process: "go-live|ffmpeg"
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.GPUSpend.Enabled || cfg.GPUSpend.HourlyUSD != 0.79 {
		t.Fatalf("gpu_spend not loaded: %+v", cfg.GPUSpend)
	}
	if len(cfg.GPUSpend.Checks) != 2 || cfg.GPUSpend.Checks[0].Port != 8080 ||
		cfg.GPUSpend.Checks[1].Process != "go-live|ffmpeg" {
		t.Fatalf("checks not loaded: %+v", cfg.GPUSpend.Checks)
	}
}

func TestEgressJail_AllowDNSDefault(t *testing.T) {
	if !(EgressJailConfig{Enabled: true}).AllowDNS() {
		t.Error("DNS should be allowed by default")
	}
	if (EgressJailConfig{BlockDNS: true}).AllowDNS() {
		t.Error("block_dns:true must disable DNS")
	}
}

func TestLoad_EgressJailBlock(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/oknek.yaml"
	yaml := "egress_jail:\n  enabled: true\n  gateway: { host: \"127.0.0.1\", port: 4000 }\n  enforce: true\n"
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ej := cfg.EgressJail
	if !ej.Enabled || ej.Gateway.Host != "127.0.0.1" || ej.Gateway.Port != 4000 || !ej.Enforce {
		t.Errorf("egress_jail parsed wrong: %+v", ej)
	}
	if !ej.AllowDNS() {
		t.Error("AllowDNS() should be true when block_dns unset")
	}
}

func TestLoad_FeedBlock(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "oknek.yaml")
	yaml := "feed:\n  enabled: true\n  url: https://oknek.com/api/events/ingest\n  key: okik_abc123\n"
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Feed.Enabled || cfg.Feed.URL != "https://oknek.com/api/events/ingest" || cfg.Feed.Key != "okik_abc123" {
		t.Fatalf("feed block parsed wrong: %+v", cfg.Feed)
	}
}
