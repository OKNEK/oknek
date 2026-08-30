// Package rules implements oknek's detection rule engine.
//
// Rules are evaluated against typed Events emitted by the hook layer (eBPF
// or LD_PRELOAD shim). Each rule declares the Kind of event it cares about,
// and the Engine dispatches events by Kind so the hot path only evaluates
// the relevant rules.
//
// v1 ships seven rules (R1–R7). They are registered in code today; YAML
// loading from rules/v1/*.yaml is a week-2 deliverable per /docs/rules/.
// R9 (opt-in GPU billed-while-broken cost governor) registers only when
// gpu_spend is enabled in config, so the default pack remains R1–R7.
package rules

import "context"

// Verdict is the outcome of a rule match. Higher values = more severe.
type Verdict int

const (
	VerdictAllow Verdict = iota
	VerdictWarn
	VerdictBlock
)

// String returns the lowercase wire format ("allow" / "warn" / "block").
func (v Verdict) String() string {
	switch v {
	case VerdictAllow:
		return "allow"
	case VerdictWarn:
		return "warn"
	case VerdictBlock:
		return "block"
	default:
		return "unknown"
	}
}

// Kind categorizes events by the kernel hook that produced them.
// Each rule declares exactly one Kind it consumes.
type Kind string

const (
	KindExecObserved  Kind = "exec_observed"
	KindFileOpened    Kind = "file_opened"
	KindSocketConnect Kind = "socket_connect"
	KindFileChanged   Kind = "file_changed"
	KindBaselineDrift Kind = "baseline_drift"
	KindFileScanned   Kind = "file_scanned"
	KindMCPEndpoint   Kind = "mcp_endpoint"
	KindCostAnomaly   Kind = "cost_anomaly"
	KindExfilAnomaly  Kind = "exfil_anomaly"
	KindTaint         Kind = "taint"      // R21 Rule of Two: session taint acquired / third property denied
	KindPinTamper     Kind = "pin_tamper" // R22 supply-chain artifact tampered/quarantined
	KindCanary        Kind = "canary"     // R23 decoy credential touched
)

// Event is the generic envelope passed to rules. The concrete payload is
// type-asserted by each rule from Payload.
type Event struct {
	Kind      Kind
	AgentID   string
	PID       int
	PPID      int
	Timestamp int64
	Payload   interface{}
}

// ExecPayload is the payload for KindExecObserved events — a single observed
// exec(2)-family syscall from a watched agent process.
type ExecPayload struct {
	Command string   // the bash command line (for `bash -c "<cmd>"`-style execs)
	Argv    []string // raw argv as observed at the syscall layer
	Cwd     string   // working directory at exec time, when available
}

// FileOp categorizes a file modification.
type FileOp string

const (
	FileOpCreate FileOp = "create"
	FileOpModify FileOp = "modify"
	FileOpDelete FileOp = "delete"
)

// FileChangePayload is the payload for KindFileChanged — a write/create/delete
// observed via inotify or eBPF tracepoints. Consumed by R2.
type FileChangePayload struct {
	Path    string // absolute path to the file
	Op      FileOp // create, modify, or delete
	OldHash string // sha256 hex before the change, if known
	NewHash string // sha256 hex after the change, if known
}

// FileOpenPayload is the payload for KindFileOpened — an observed open(2)
// syscall. Consumed by R3.
type FileOpenPayload struct {
	Path    string // absolute path to the file
	Mode    string // "read" | "write" | "readwrite" (best-effort from open flags)
	Process string // process name that performed the open, e.g. "claude"
}

// MCPEndpointPayload is the payload for KindMCPEndpoint — an attempt by an
// agent to use an MCP server. Consumed by R4.
type MCPEndpointPayload struct {
	ServerName string // user-given name from the MCP config, e.g. "github"
	Transport  string // "stdio" | "http" | "sse"
	Command    string // stdio transport: command + args (e.g. "npx mcp-remote https://...")
	URL        string // http/sse transport: full server URL
}

// SocketConnectPayload is the payload for KindSocketConnect — an outbound
// connect(2). Consumed by R5.
type SocketConnectPayload struct {
	DestHost string // hostname when known, else stringified IP
	DestIP   string // resolved IPv4/IPv6
	DestPort int    // remote port
	Process  string // process name that initiated the connect
}

// FileScanPayload is the payload for KindFileScanned — an agent-instruction
// file (CLAUDE.md, AGENT.md, .clinerules, ...) ingested for static analysis
// before the agent sees it. Consumed by R6.
type FileScanPayload struct {
	Path    string // absolute path to the file
	Content []byte // raw file contents (capped at ~1 MiB by the hook layer)
}

// CostAnomalyPayload is the payload for KindCostAnomaly — a billed-while-broken
// window detected by the gpuwatch governor: a watched workload was down while
// the rented pod stayed up and kept metering. Consumed by R9.
type CostAnomalyPayload struct {
	Provider    string  // "runpod"
	PodID       string  // pod identity (defaults to hostname)
	Service     string  // the watched workload that went down
	DownSince   int64   // unix seconds the service first went unhealthy
	DownSeconds int64   // billed-while-broken seconds at emit time
	HourlyUSD   float64 // configured pod rate
	ExposureUSD float64 // DownSeconds/3600 * HourlyUSD — clawback estimate
	Resolved    bool    // false = live alert (grace crossed); true = recovery tally
}

// ExfilAnomalyPayload is the payload for KindExfilAnomaly (R12) — a beaconing or
// high-velocity off-gateway egress pattern from a watched agent, detected by the
// exfilwatch aggregator over R11's connect stream. Alert-only.
type ExfilAnomalyPayload struct {
	Pattern         string  `json:"pattern"` // "beacon" | "velocity"
	AgentIdentifier string  `json:"agent_identifier"`
	Dest            string  `json:"dest,omitempty"` // beacon only (ip:port)
	IntervalSeconds float64 `json:"interval_seconds,omitempty"`
	JitterCV        float64 `json:"jitter_cv,omitempty"`
	SampleCount     int     `json:"sample_count,omitempty"`
	ConnectsWindow  int     `json:"connects_in_window,omitempty"`
	WindowSeconds   int     `json:"window_seconds,omitempty"`
	Process         string  `json:"process,omitempty"`
	PID             int     `json:"pid,omitempty"`
	Rule            string  `json:"rule"` // "exfil-c2-watch"
}

// Match is the return value of a rule that fired.
type Match struct {
	RuleID   string                 `json:"rule_id"`
	Name     string                 `json:"name"`
	Verdict  Verdict                `json:"verdict"`
	Evidence map[string]interface{} `json:"evidence"`
}

// Rule is the interface every detection rule implements.
type Rule interface {
	ID() string
	Name() string
	Kind() Kind
	// Match returns (Match, true) if the rule fires for this event,
	// or (zero, false) if it does not.
	Match(ctx context.Context, e Event) (Match, bool)
}

// RuleInfo is a compact metadata record for listing loaded rules.
type RuleInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind Kind   `json:"kind"`
}

// Engine holds registered rules indexed by Kind and evaluates events through them.
type Engine struct {
	byKind map[Kind][]Rule
	all    []Rule
}

// NewEngine returns an empty Engine. Register rules with Engine.Register.
func NewEngine() *Engine {
	return &Engine{byKind: make(map[Kind][]Rule)}
}

// Register adds a rule to the engine. Safe to call before Serve.
func (e *Engine) Register(r Rule) {
	e.byKind[r.Kind()] = append(e.byKind[r.Kind()], r)
	e.all = append(e.all, r)
}

// Evaluate runs every rule registered for ev.Kind against ev, returning
// every match in registration order.
func (e *Engine) Evaluate(ctx context.Context, ev Event) []Match {
	rules := e.byKind[ev.Kind]
	if len(rules) == 0 {
		return nil
	}
	var matches []Match
	for _, r := range rules {
		if m, ok := r.Match(ctx, ev); ok {
			matches = append(matches, m)
		}
	}
	return matches
}

// Count returns the total number of registered rules.
func (e *Engine) Count() int { return len(e.all) }

// List returns metadata for every registered rule, in registration order.
func (e *Engine) List() []RuleInfo {
	out := make([]RuleInfo, 0, len(e.all))
	for _, r := range e.all {
		out = append(out, RuleInfo{ID: r.ID(), Name: r.Name(), Kind: r.Kind()})
	}
	return out
}
