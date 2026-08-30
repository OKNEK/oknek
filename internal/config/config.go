// Package config loads and validates the oknekd runtime configuration.
//
// Defaults adapt to the host: on Linux running as root we use the production
// paths under /run, /var/lib, /var/log and /etc/oknek. Everywhere else
// (Darwin dev, non-root Linux) we use user-scoped paths under ~/.oknek so the
// daemon can be developed and run without sudo.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"

	"github.com/oknek/oknek/internal/okular"
)

// Config is the daemon's runtime configuration.
type Config struct {
	Socket         string            `yaml:"socket"`          // Unix socket path
	DBPath         string            `yaml:"db_path"`         // SQLite event store path
	LogPath        string            `yaml:"log_path"`        // Log file path
	RulesDir       string            `yaml:"rules_dir"`       // Active rule pack directory
	BaselineDays   int               `yaml:"baseline_days"`   // Behavioral baseline window (R7)
	GPUSpend       GPUSpendConfig    `yaml:"gpu_spend"`       // billed-while-broken governor (R9), opt-in
	RouteAround    RouteAroundConfig `yaml:"route_around"`    // R10 route-around detector, opt-in
	EgressJail     EgressJailConfig  `yaml:"egress_jail"`     // R11 kernel egress jail, opt-in
	ExfilWatch     ExfilWatchConfig  `yaml:"exfil_watch"`     // R12 exfil/C2 watch, opt-in
	ProtectedFiles []string          `yaml:"protected_files"` // R3 inode-protected files (hardlink/rename-proof)
	Okredo         OkredoConfig      `yaml:"okredo"`          // per-agent identity + authorization (IAM), opt-in
	Okular         OkularConfig      `yaml:"okular"`          // tamper-proof audit ledger (the Audit pillar), opt-in
	SelfGuard      SelfGuardConfig   `yaml:"self_guard"`      // R20 anti-unpin: guard oknek's own bpffs pins, opt-in
	Disarm         DisarmConfig      `yaml:"disarm"`          // Tier-A gated uninstall: off-box-signed disarm authorization, opt-in
	Feed           FeedConfig        `yaml:"feed"`            // dashboard event feed (concierge per-customer), opt-in
	Pins           PinsConfig        `yaml:"pins"`            // R22 supply-chain pins: skills/hooks/settings/MCP manifests, opt-in
	Canary         CanaryConfig      `yaml:"canary"`          // R23 canary credentials (decoys), opt-in
	RuleOfTwo      RuleOfTwoConfig   `yaml:"rule_of_two"`     // R21 untrusted/private sets (mode is per Okredo profile)
	Identity       IdentityConfig    `yaml:"identity"`        // Okredo Attest: kernel-attested agent identity push, opt-in
	MCP            MCPConfig         `yaml:"mcp"`             // R24 MCP server jail: per-server kernel identity + egress allowlist, opt-in
}

// DisarmConfig configures Tier-A gated graceful disarm/uninstall. PubKey is the hex
// ed25519 public key of the OFF-BOX authorizer; the matching private key is held off the
// box (control plane / admin secret), so on-box root cannot forge an uninstall. A disarm
// requires a token signed by that key; the authorized disarm is recorded to Okular
// (record-first, fail-closed) and staged as a signed disarm-on-boot marker the loader
// re-verifies. Zero value disabled — uninstall then remains reboot + manual removal.
type DisarmConfig struct {
	Enabled            bool   `yaml:"enabled"`
	PubKey             string `yaml:"pub_key"`               // hex ed25519 pubkey of the off-box authorizer
	MarkerPath         string `yaml:"marker_path"`           // disarm-on-boot marker location
	MaxTokenAgeSeconds int    `yaml:"max_token_age_seconds"` // reject tokens older than this (replay window); 0 = rely on ExpiresAt
}

// FeedConfig configures the dashboard event feed. When enabled, every non-allow
// rule match is POSTed to the oknek dashboard ingest endpoint with the
// per-customer bearer Key, in addition to the local store. Zero value disabled.
//
// The same Key also authenticates the OUTBOUND config-pull channel (Dean's
// approve→apply loop): the daemon polls PendingURL for human-approved config changes
// and acks to AckURL. Both default to the ingest URL's origin + /api/config/pending
// and /api/config/ack when left empty. Config-pull additionally requires Okular
// (an approved change is sealed before it's applied).
type FeedConfig struct {
	Enabled    bool   `yaml:"enabled"`
	URL        string `yaml:"url"`         // e.g. https://oknek.com/api/events/ingest
	Key        string `yaml:"key"`         // per-customer ingest key (okik_...)
	PendingURL string `yaml:"pending_url"` // optional; default <origin>/api/config/pending
	AckURL     string `yaml:"ack_url"`     // optional; default <origin>/api/config/ack
}

// ConfigPullURLs returns the effective pending + ack URLs, deriving them from the
// ingest URL's origin when not set explicitly. Returns empty strings if no origin
// can be determined (feed disabled / malformed URL) — the caller treats that as
// "config-pull disabled".
func (f FeedConfig) ConfigPullURLs() (pending, ack string) {
	pending, ack = f.PendingURL, f.AckURL
	if pending != "" && ack != "" {
		return pending, ack
	}
	origin := originOf(f.URL)
	if origin == "" {
		return pending, ack
	}
	if pending == "" {
		pending = origin + "/api/config/pending"
	}
	if ack == "" {
		ack = origin + "/api/config/ack"
	}
	return pending, ack
}

// originOf returns scheme://host for a URL, or "" if it can't be parsed.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// SelfGuardConfig configures R20 anti-unpin (the self-pin-guard). When enabled, the
// kernel denies any attempt to rm/rename oknek's own bpffs pins — so a root insider
// can't detach enforcement by deleting the pin. It also emits a hash-chained
// heartbeat into Okular so a disable we CAN'T prevent in-kernel (reboot, exploit)
// still leaves an un-backfillable gap: silence becomes the alarm. Zero value
// disabled (fail-open, zero behavior change). Enforce=false arms it in observe.
type SelfGuardConfig struct {
	Enabled          bool `yaml:"enabled"`
	Enforce          bool `yaml:"enforce"`           // false = observe (log the DISABLE attempt, allow it)
	HeartbeatSeconds int  `yaml:"heartbeat_seconds"` // attestation beat interval (default 30)
	GapMultiple      int  `yaml:"gap_multiple"`      // a gap > heartbeat*this = silenced (default 3)
}

// NormalizeSelfGuard fills operational defaults so a partial config runs.
func NormalizeSelfGuard(c SelfGuardConfig) SelfGuardConfig {
	if c.HeartbeatSeconds <= 0 {
		c.HeartbeatSeconds = 30
	}
	if c.GapMultiple <= 0 {
		c.GapMultiple = 3
	}
	return c
}

// OkularConfig configures the tamper-proof flight recorder (the Audit pillar). When
// enabled, every kernel enforcement event is also sealed into a hash-chained ledger.
// Zero value disabled. Path defaults to okular.db beside the event store.
type OkularConfig struct {
	Enabled bool              `yaml:"enabled"`
	Path    string            `yaml:"path"`
	WORM    okular.WORMConfig `yaml:"worm"` // off-box anchor escrow (S3 Object-Lock); zero value disabled
}

// OkredoConfig is the per-agent authorization layer (the IAM pillar). Each named
// profile is an agent identity/role with a kernel-enforced egress allowlist applied
// on top of the base egress jail. Agents bind to a profile at `oknek run --profile`.
// Zero value disabled.
type OkredoConfig struct {
	Enabled  bool                     `yaml:"enabled"`
	Profiles map[string]OkredoProfile `yaml:"profiles"`
}

// OkredoProfile is one agent identity/role. AllowEgress entries are "ip:port"
// (exact host:port the agent of this profile is cleared to reach, additive to the
// base jail's gateway/DNS/loopback).
type OkredoProfile struct {
	AllowEgress []string `yaml:"allow_egress"`
	RuleOfTwo   string   `yaml:"rule_of_two"` // R21: off (default) | observe | enforce
}

// RuleOfTwoConfig (R21) names what counts as UNTRUSTED input and PRIVATE data for
// Meta's Agents Rule of Two. External comms (X) is any identity-granted non-gateway
// connect. Dirs match direct children only (one level). Resolved to inodes at start.
type RuleOfTwoConfig struct {
	// NetworkTrusted=false (default): an identity-granted external connect counts as
	// BOTH untrusted input and external comms — after private data, no external comms
	// at all (the strict exfil-cut). true: a connect is external comms only (pure
	// Meta semantics; you trust what comes back from allowlisted destinations).
	NetworkTrusted bool     `yaml:"network_trusted"`
	UntrustedDirs  []string `yaml:"untrusted_dirs"`
	UntrustedFiles []string `yaml:"untrusted_files"`
	PrivateDirs    []string `yaml:"private_dirs"`
	PrivateFiles   []string `yaml:"private_files"`
}

// Default returns the platform-appropriate default config.
func Default() *Config {
	if isProdHost() {
		cfg := &Config{
			Socket:       "/run/oknek/oknek.sock",
			DBPath:       "/var/lib/oknek/oknek.db",
			LogPath:      "/var/log/oknek/oknek.log",
			RulesDir:     "/var/lib/oknek/rules/active",
			BaselineDays: 14,
		}
		applyDefaults(cfg)
		return cfg
	}
	base := devBase()
	cfg := &Config{
		Socket:       filepath.Join(base, "oknek.sock"),
		DBPath:       filepath.Join(base, "oknek.db"),
		LogPath:      filepath.Join(base, "oknek.log"),
		RulesDir:     filepath.Join(base, "rules", "active"),
		BaselineDays: 14,
	}
	applyDefaults(cfg)
	return cfg
}

// PinsConfig is R22: hash-pin agent supply-chain artifacts (skills, hooks,
// settings, MCP manifests). A watched agent may not write a pinned file in place;
// a file the sweep finds TAMPERED is quarantined (no open/exec by a watched agent)
// until a human re-pins it with `oknek pin --accept`.
type PinsConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Enforce      bool     `yaml:"enforce"`       // false = observe: log tamper, never deny
	Paths        []string `yaml:"paths"`         // globs; "~/" = daemon HOME, relative = per-agent cwd, trailing "/**" = whole subtree
	SweepSeconds int      `yaml:"sweep_seconds"` // integrity re-hash interval (default 30)
}

// DefaultPinPaths is what `pins.paths` means when enabled and left empty.
var DefaultPinPaths = []string{
	"~/.claude/settings.json", "~/.claude.json", ".claude/settings.json",
	".claude/skills/**", ".claude/hooks/**", ".mcp.json", ".cursor/mcp.json", ".cursor/rules/**",
}

// CanaryConfig is R23: plant decoy credentials; any watched-agent open is a
// high-confidence alarm (mode alert) or a kernel block (mode block). Decoys are
// planted ONLY where no real file exists.
type CanaryConfig struct {
	Enabled bool     `yaml:"enabled"`
	Mode    string   `yaml:"mode"`  // alert | block (default alert)
	Plant   []string `yaml:"plant"` // decoy paths
}

// IdentityConfig is Okredo Attest: short-lived EdDSA identity tokens (JWT-SVID-shaped)
// minted by the daemon for each running watched agent and pushed to an IdP/SIEM.
// Needs okular.enabled (the signing key is the audit key).
type IdentityConfig struct {
	Enabled         bool              `yaml:"enabled"`
	WebhookURL      string            `yaml:"webhook_url"`      // POST {"attestation","event","agent"}; empty = no push (issue-only)
	Headers         map[string]string `yaml:"headers"`          // extra request headers (e.g. Authorization)
	Audience        string            `yaml:"audience"`         // default aud claim
	IntervalSeconds int               `yaml:"interval_seconds"` // refresh push interval (default 120)
	TTLSeconds      int               `yaml:"ttl_seconds"`      // token lifetime (default 300)
}

// MCPConfig is R24: every stdio MCP server an agent spawns gets its own Okredo
// identity (`mcp:<name>`) with the grants declared here (same "ip:port" / "cidr:port"
// syntax as Okredo). enforce=false (observe) binds nothing and records what each
// server actually reaches, so the allowlist can be written from evidence.
type MCPConfig struct {
	Enabled bool                `yaml:"enabled"`
	Enforce bool                `yaml:"enforce"`
	Grants  map[string][]string `yaml:"grants"`
}

// Load reads YAML config from path, overlaying onto Default().
// An empty path resolves to the platform-default location.
// If the resolved path does not exist, Default() is returned without error.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		path = DefaultPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	applyDefaults(cfg)
	return cfg, nil
}

// applyDefaults fills zero-valued fields of opt-in blocks that have a sane default.
func applyDefaults(cfg *Config) {
	if cfg.Pins.SweepSeconds <= 0 {
		cfg.Pins.SweepSeconds = 30
	}
	if cfg.Pins.Enabled && len(cfg.Pins.Paths) == 0 {
		cfg.Pins.Paths = append([]string(nil), DefaultPinPaths...)
	}
	if cfg.Canary.Mode == "" {
		cfg.Canary.Mode = "alert"
	}
	if cfg.Identity.IntervalSeconds <= 0 {
		cfg.Identity.IntervalSeconds = 120
	}
	if cfg.Identity.TTLSeconds <= 0 {
		cfg.Identity.TTLSeconds = 300
	}
}

// DefaultPath returns the default location to look for oknek.yaml.
func DefaultPath() string {
	if isProdHost() {
		return "/etc/oknek/oknek.yaml"
	}
	return filepath.Join(devBase(), "oknek.yaml")
}

// EnsureDirs creates the runtime directories the daemon needs to write to.
// Safe to call multiple times.
func (c *Config) EnsureDirs() error {
	for _, dir := range []string{
		filepath.Dir(c.Socket),
		filepath.Dir(c.DBPath),
		filepath.Dir(c.LogPath),
		c.RulesDir,
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	return nil
}

// GPUSpendConfig configures the R9 billed-while-broken governor. Zero value is
// disabled, so the daemon's behavior is unchanged until this block is set.
type GPUSpendConfig struct {
	Enabled      bool          `yaml:"enabled"`
	Provider     string        `yaml:"provider"`      // "runpod"
	PodID        string        `yaml:"pod_id"`        // defaults to hostname at start
	HourlyUSD    float64       `yaml:"hourly_usd"`    // configured pod rate
	PollSeconds  int           `yaml:"poll_seconds"`  // ticker interval (default 30 at start)
	GraceSeconds int           `yaml:"grace_seconds"` // ignore blips shorter than this (default 300)
	WebhookURL   string        `yaml:"webhook_url"`   // optional Discord/Slack push
	Checks       []HealthCheck `yaml:"checks"`
}

// HealthCheck is one watched workload. A check is healthy only if every set
// probe passes: Port (TCP listener) and/or Process (pgrep -f pattern).
type HealthCheck struct {
	Name    string `yaml:"name"`
	Process string `yaml:"process"`
	Port    int    `yaml:"port"`
}

func isProdHost() bool {
	return runtime.GOOS == "linux" && os.Geteuid() == 0
}

func devBase() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".oknek")
	}
	return filepath.Join(os.TempDir(), "oknek")
}

// RouteAroundConfig configures the R10 route-around detector. Zero value is
// disabled, so the daemon's behavior is unchanged until this block is set.
type RouteAroundConfig struct {
	Enabled        bool               `yaml:"enabled"`
	Gateway        Endpoint           `yaml:"gateway"`           // host+port the cost gateway listens on
	Providers      []string           `yaml:"providers"`         // LLM-API host suffixes; default list if empty
	ExcludeProc    []string           `yaml:"exclude_processes"` // process names to ignore (e.g. the gateway)
	EstCostPerCall map[string]float64 `yaml:"est_cost_per_call"` // provider suffix -> $/call; "default" fallback
	SoftCap        SoftCapConfig      `yaml:"soft_cap"`
}

// Endpoint is a host+port pair.
type Endpoint struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// SoftCapConfig is the route-around soft-cap (warn-only) budget over a rolling window.
type SoftCapConfig struct {
	WindowSeconds int     `yaml:"window_seconds"`
	BudgetUSD     float64 `yaml:"budget_usd"`
}

// DefaultRouteAroundProviders is the starter LLM-API host suffix list.
var DefaultRouteAroundProviders = []string{
	"api.openai.com",
	"api.anthropic.com",
	"generativelanguage.googleapis.com",
	"api.cohere.ai",
	"api.mistral.ai",
}

// EgressJailConfig configures the R11 kernel egress jail (BPF-LSM socket_connect).
// Zero value is disabled. DNS egress is allowed by default; set block_dns to deny it.
type EgressJailConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Gateway  Endpoint `yaml:"gateway"`   // Host is an IP (e.g. 127.0.0.1)
	BlockDNS bool     `yaml:"block_dns"` // opt-in to blocking DNS; default = DNS allowed
	Enforce  bool     `yaml:"enforce"`   // false = observe-only (log, no block)
}

// AllowDNS reports whether :53 egress is permitted (default true).
func (c EgressJailConfig) AllowDNS() bool { return !c.BlockDNS }

// ExfilWatchConfig configures R12 exfil/C2 watch (beaconing + velocity over the
// R11 off-gateway connect stream). Zero value is disabled. Alert-only; reads
// R11's connect events, so it requires egress_jail enabled to have a source.
type ExfilWatchConfig struct {
	Enabled                  bool    `yaml:"enabled"`
	BeaconMinCount           int     `yaml:"beacon_min_count"`            // intervals before calling it a beacon
	BeaconJitterTolerance    float64 `yaml:"beacon_jitter_tolerance"`     // max stddev/mean (CV) for "regular"
	BeaconMinIntervalSeconds float64 `yaml:"beacon_min_interval_seconds"` // below this mean interval = velocity, not beacon
	VelocityWindowSeconds    int     `yaml:"velocity_window_seconds"`
	VelocityMaxConnects      int     `yaml:"velocity_max_connects"`
	CooldownSeconds          int     `yaml:"cooldown_seconds"`
}

// NormalizeExfilWatch fills operational defaults so a partial config runs.
func NormalizeExfilWatch(c ExfilWatchConfig) ExfilWatchConfig {
	if c.BeaconMinCount <= 0 {
		c.BeaconMinCount = 4
	}
	if c.BeaconJitterTolerance <= 0 {
		c.BeaconJitterTolerance = 0.15
	}
	if c.BeaconMinIntervalSeconds <= 0 {
		c.BeaconMinIntervalSeconds = 1
	}
	if c.VelocityWindowSeconds <= 0 {
		c.VelocityWindowSeconds = 30
	}
	if c.VelocityMaxConnects <= 0 {
		c.VelocityMaxConnects = 40
	}
	if c.CooldownSeconds <= 0 {
		c.CooldownSeconds = 300
	}
	return c
}

// NormalizeRouteAround fills operational defaults so a partial config runs.
func NormalizeRouteAround(c RouteAroundConfig) RouteAroundConfig {
	if len(c.Providers) == 0 {
		c.Providers = append([]string(nil), DefaultRouteAroundProviders...)
	}
	if c.EstCostPerCall == nil {
		c.EstCostPerCall = map[string]float64{}
	}
	if _, ok := c.EstCostPerCall["default"]; !ok {
		c.EstCostPerCall["default"] = 0.02
	}
	if c.SoftCap.WindowSeconds <= 0 {
		c.SoftCap.WindowSeconds = 3600
	}
	return c
}
