// Command oknek is the oknek CLI. It talks to a running oknekd daemon over
// a Unix socket and exposes operational subcommands (status, logs, allow,
// block, baseline, update, license, rules, version).
//
// See https://oknek.com/docs/cli/ for the full subcommand reference.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oknek/oknek/internal/config"
	"github.com/oknek/oknek/internal/disarm"
	"github.com/oknek/oknek/internal/ipc"
	"github.com/oknek/oknek/internal/okular"
)

// Build-time stamps injected via Makefile -ldflags.
var (
	version   = "0.9.0-arsenal"
	commit    = "unknown"
	buildDate = "unknown"
)

const helpText = `oknek %s · runtime defense CLI for AI agents

usage:
  oknek <subcommand> [args...]

subcommands:
  status                 print the daemon's current state
  check exec <bash-cmd>  run a bash command through the rule engine
  check filechange <path> [create|modify|delete]
                         simulate a file change event (R2)
  check fileopen <path>  simulate a file open event (R3)
  check mcp <transport> <command|url>
                         simulate an MCP endpoint use (R4)
                         transport: stdio | http | sse
  check socket <host> [port]
                         simulate an outbound socket connect (R5)
  check scan <file>      scan a file on disk for prompt-injection patterns (R6)
  check drift <agent> <feature1> [feature2 ...]
                         score features against the agent's baseline (R7)
  baseline observe <agent> <feature1> [feature2 ...]
                         add features to the baseline (training)
  baseline size          print total baseline row count
  rules list             list loaded detection rules
  routes                 show LLM-API calls that bypassed the cost gateway (R10)
  egress                 show off-gateway connects the kernel egress jail caught (R11)
  exfil                  show exfil/C2 beaconing + velocity alerts (R12)
  doctor                 preflight the true enforcement posture (honest coverage)
  pin                    hash-pin skills/hooks/settings/MCP manifests (R22 supply-chain guard)
  pin status             list pins + tamper/quarantine state
  pin --accept <p>...    re-pin after human review (lifts quarantine; sealed)
  canary plant [path...] plant decoy credentials (R23; never overwrites a real file)
  canary status | remove
  taint                  show each agent session's Rule-of-Two taint (R21: U·P·X, max two)
  taint clear <agent>    human checkpoint: reset a session's taint (sealed)
  identity issue --agent <a>   mint a kernel-attested identity token (Okredo Attest, EdDSA JWT)
  identity verify <jwt>  verify a token (signature + expiry) and print its claims
  identity pubkey        print the attestation public key (hex + JWKS)
  mcp                    MCP servers per agent: jailed identity, grants, what each reached, blocks (R24)
  attest                 verify anti-unpin heartbeat continuity (R20: silence = a disable)
  okredo                 show agent identity profiles + per-identity egress grants (IAM)
  okular                 verify the tamper-proof audit ledger (chain intact?)
  okular export [agent]  print a sealed, ed25519-signed export bundle (Audit)
  okular verify-export <f>  verify a sealed bundle offline (signature + chain)
  okular anchors         list signed head-hash checkpoints + verify vs the ledger
  okular anchor          seal a checkpoint now
  okular verify-remote   verify the immutable off-box WORM escrow vs on-box state (S3 Object-Lock)
  replay [agent]         replay an agent's sealed action timeline (Audit)
  ping                   round-trip a ping to the daemon
  version                print version (CLI and daemon)
  logs                   tail or query the event log     (not yet implemented)
  allow                  release a suspended agent       (not yet implemented)
  block                  force-suspend an agent          (not yet implemented)
  baseline               manage the 14-day baseline      (not yet implemented)
  update                 fetch the latest signed rule pack (not yet implemented)
  license                activate or inspect a paid-tier license (not yet implemented)

state: pre-release. v1 ships 2026-05-25.
docs:  https://oknek.com/docs/cli/
`

var stubSubcommands = []string{
	"logs", "allow", "block", "baseline", "update", "license",
}

func main() {
	var (
		showVersion = flag.Bool("version", false, "print version and exit")
		showHelp    = flag.Bool("help", false, "print help and exit")
		configPath  = flag.String("config", "", "config file path (default platform-appropriate)")
	)
	flag.Usage = func() { fmt.Fprintf(os.Stderr, helpText, version) }
	flag.Parse()

	if *showVersion {
		fmt.Printf("oknek %s · commit=%s · built=%s\n", version, commit, buildDate)
		return
	}
	if *showHelp {
		fmt.Printf(helpText, version)
		return
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Printf(helpText, version)
		return
	}

	cmd := args[0]
	rest := args[1:]
	switch cmd {
	case "version":
		runVersion(*configPath)
		return
	case "status":
		runStatus(*configPath)
		return
	case "ping":
		runPing(*configPath)
		return
	case "rules":
		runRules(*configPath, rest)
		return
	case "routes":
		runRoutes(*configPath)
		return
	case "egress":
		runEgress(*configPath)
		return
	case "exfil":
		runExfil(*configPath)
		return
	case "okredo":
		runOkredo(*configPath)
		return
	case "okular":
		runOkular(*configPath, rest)
		return
	case "replay":
		runReplay(*configPath, rest)
		return
	case "doctor":
		runDoctor(*configPath)
		return
	case "attest":
		runAttest(*configPath)
		return
	case "disarm":
		runDisarm(*configPath, rest)
		return
	case "check":
		runCheck(*configPath, rest)
		return
	case "baseline":
		runBaseline(*configPath, rest)
		return
	case "run":
		runRun(*configPath, rest)
		return
	case "mcp":
		runMCP(*configPath)
		return
	case "identity":
		runIdentity(*configPath, rest)
		return
	case "taint":
		runTaint(*configPath, rest)
		return
	case "pin":
		runPin(*configPath, rest)
		return
	case "canary":
		runCanary(*configPath, rest)
		return
	}

	if isStub(cmd) {
		fmt.Printf("oknek %s · subcommand=%s · not yet implemented\n", version, cmd)
		fmt.Println("see https://oknek.com/docs/cli/ for the planned semantics")
		return
	}

	fmt.Fprintf(os.Stderr, "oknek: unknown subcommand %q\n", cmd)
	fmt.Fprintf(os.Stderr, "run `oknek --help` for the subcommand list\n")
	os.Exit(2)
}

func isStub(cmd string) bool {
	for _, s := range stubSubcommands {
		if s == cmd {
			return true
		}
	}
	return false
}

func client(configPath string) (*ipc.Client, *config.Config) {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oknek: load config: %v\n", err)
		os.Exit(1)
	}
	return ipc.NewClient(cfg.Socket), cfg
}

func runVersion(configPath string) {
	fmt.Printf("oknek  (cli)    %s · commit=%s · built=%s\n", version, commit, buildDate)
	c, _ := client(configPath)
	var v map[string]string
	if err := c.Call("version", nil, &v); err != nil {
		fmt.Printf("oknekd (daemon) unreachable: %v\n", err)
		return
	}
	fmt.Printf("oknekd (daemon) %s · commit=%s · built=%s\n", v["version"], v["commit"], v["build_date"])
}

func runRoutes(configPath string) {
	c, _ := client(configPath)
	var s struct {
		Enabled       bool    `json:"enabled"`
		WindowSeconds int     `json:"window_seconds"`
		WindowUSD     float64 `json:"window_usd"`
		BudgetUSD     float64 `json:"budget_usd"`
		OverBudget    bool    `json:"over_budget"`
		Lifetime      int     `json:"lifetime"`
		Processes     []struct {
			Process  string  `json:"process"`
			Provider string  `json:"provider"`
			Count    int     `json:"count"`
			EstUSD   float64 `json:"est_usd"`
		} `json:"processes"`
	}
	if err := c.Call("routes", nil, &s); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: routes: %v\n", err)
		os.Exit(1)
	}
	if !s.Enabled {
		fmt.Println("route-around detector is disabled (set route_around.enabled in oknek.yaml)")
		return
	}
	state := "ok"
	if s.OverBudget {
		state = "OVER BUDGET"
	}
	fmt.Printf("route-arounds · last %ds · est ~$%.2f / $%.2f budget [%s] · %d lifetime\n",
		s.WindowSeconds, s.WindowUSD, s.BudgetUSD, state, s.Lifetime)
	if len(s.Processes) == 0 {
		fmt.Println("   none in window")
		return
	}
	for _, p := range s.Processes {
		fmt.Printf("   %-24s → %-30s %d call(s) · est ~$%.2f\n", p.Process, p.Provider, p.Count, p.EstUSD)
	}
}

func runDoctor(configPath string) {
	c, _ := client(configPath)
	var s struct {
		Verdict         string   `json:"verdict"`
		BPFLSMAvailable bool     `json:"bpf_lsm_available"`
		HookMode        string   `json:"hook_mode"`
		Pins            []string `json:"pins"`
		PinsExpected    int      `json:"pins_expected"`
		EgressEnabled   bool     `json:"egress_enabled"`
		EgressEnforce   bool     `json:"egress_enforce"`
		ProtectedFiles  int      `json:"protected_files"`
		PinnedArts      int      `json:"pinned_artifacts"`
		Quarantined     int      `json:"quarantined"`
		Canaries        int      `json:"canaries"`
		PinsEnforce     bool     `json:"pins_enforce"`
		R2Enforce       int      `json:"rule_of_two_enforce"`
		R2Observe       int      `json:"rule_of_two_observe"`
		R2Sets          int      `json:"rule_of_two_sets"`
		SelfGuardOn     bool     `json:"self_guard_enabled"`
		SelfGuardArmed  bool     `json:"self_guard_armed"`
		SelfGuardEnf    bool     `json:"self_guard_enforce"`
		Containerized   bool     `json:"containerized"`
		PIDNs           string   `json:"pid_ns"`
		Kernel          string   `json:"kernel"`
		Warnings        []string `json:"warnings"`
	}
	if err := c.Call("doctor", nil, &s); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: doctor (daemon unreachable?): %v\n", err)
		os.Exit(1)
	}
	ck := func(ok bool) string {
		if ok {
			return "✓" // ✓
		}
		return "✗" // ✗
	}
	fmt.Println("oknek doctor · enforcement preflight")
	fmt.Println("──────────────────────────────────────────")
	fmt.Printf("  %s  kernel BPF-LSM active       %s\n", ck(s.BPFLSMAvailable), s.Kernel)
	fmt.Printf("  %s  hooks attached              mode=%s\n", ck(s.HookMode == "ebpf"), s.HookMode)
	fmt.Printf("  %s  links pinned (kill-proof)   %d/%d  %v\n", ck(len(s.Pins) >= s.PinsExpected && s.PinsExpected > 0), len(s.Pins), s.PinsExpected, s.Pins)
	egr := "disabled"
	if s.EgressEnabled {
		egr = "observe"
		if s.EgressEnforce {
			egr = "ENFORCING"
		}
	}
	fmt.Printf("  %s  egress jail (R11)           %s\n", ck(s.EgressEnabled && s.EgressEnforce), egr)
	fmt.Printf("  %s  cred inode-protection (R3)  %d file(s)\n", ck(s.ProtectedFiles > 0), s.ProtectedFiles)
	fmt.Printf("  %s  supply-chain pins (R22)     %d pinned · %d quarantined · enforce=%v\n", ck(s.Quarantined == 0), s.PinnedArts, s.Quarantined, s.PinsEnforce)
	fmt.Printf("  %s  canary credentials (R23)    %d planted\n", ck(s.Canaries > 0), s.Canaries)
	fmt.Printf("  %s  rule of two (R21)           %d enforce · %d observe · %d set(s)\n", ck(s.R2Enforce > 0), s.R2Enforce, s.R2Observe, s.R2Sets)
	sg := "disabled"
	if s.SelfGuardOn {
		switch {
		case !s.SelfGuardArmed:
			sg = "enabled · NOT ARMED (fail-open)"
		case s.SelfGuardEnf:
			sg = "ENFORCING"
		default:
			sg = "observe"
		}
	}
	fmt.Printf("  %s  anti-unpin self-guard (R20) %s\n", ck(s.SelfGuardOn && s.SelfGuardArmed && s.SelfGuardEnf), sg)
	host := s.PIDNs
	if s.Containerized {
		host += "  (CONTAINERIZED)"
	}
	fmt.Printf("  %s  host PID namespace          %s\n", ck(!s.Containerized), host)
	fmt.Println("──────────────────────────────────────────")
	badge := s.Verdict
	switch s.Verdict {
	case "KERNEL-ENFORCED":
		badge = "\U0001F7E2 KERNEL-ENFORCED"
	case "OBSERVE":
		badge = "\U0001F7E1 OBSERVE (logging, not blocking)"
	case "DEGRADED":
		badge = "\U0001F534 DEGRADED — enforcement NOT live"
	}
	fmt.Printf("  verdict: %s\n", badge)
	for _, w := range s.Warnings {
		fmt.Printf("  ⚠ %s\n", w)
	}
}

// runDisarm drives Tier-A gated disarm: `keygen` (make the off-box keypair), `sign` (mint a
// signed token OFF-BOX), and `request` (send a token to the daemon to authorize + stage an
// uninstall). keygen/sign never touch the daemon — the private key stays off the box.
func runDisarm(configPath string, args []string) {
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "keygen":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("disarm keypair — KEEP THE PRIVATE KEY OFF-BOX (whoever holds it can authorize uninstall):")
		fmt.Printf("  pub_key  (put in the box's oknek.yaml under disarm.pub_key):\n    %s\n", hex.EncodeToString(pub))
		fmt.Printf("  priv_key (off-box only, for `oknek disarm sign`):\n    %s\n", hex.EncodeToString(priv))
	case "sign":
		fs := flag.NewFlagSet("disarm sign", flag.ExitOnError)
		key := fs.String("key", "", "hex ed25519 PRIVATE key (from keygen)")
		host := fs.String("host", "", "host id the token authorizes (the box's hostname)")
		ttl := fs.Duration("ttl", time.Hour, "token validity window")
		id := fs.String("id", "", "token id (default: time-based)")
		reason := fs.String("reason", "", "reason note")
		_ = fs.Parse(args)
		pk, err := hex.DecodeString(strings.TrimSpace(*key))
		if err != nil || len(pk) != ed25519.PrivateKeySize {
			fmt.Fprintf(os.Stderr, "sign: --key must be a %d-byte hex ed25519 private key\n", ed25519.PrivateKeySize)
			os.Exit(1)
		}
		if *host == "" {
			fmt.Fprintln(os.Stderr, "sign: --host required (the box's hostname)")
			os.Exit(1)
		}
		tid := *id
		if tid == "" {
			tid = fmt.Sprintf("tok-%d", time.Now().UnixNano())
		}
		now := time.Now().Unix()
		tok, err := disarm.SignToken(ed25519.PrivateKey(pk), disarm.Token{
			HostID: *host, TokenID: tid, IssuedAt: now, ExpiresAt: now + int64(ttl.Seconds()), Reason: *reason,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "sign: %v\n", err)
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(tok, "", "  ")
		fmt.Println(string(b))
	case "request", "":
		fs := flag.NewFlagSet("disarm request", flag.ExitOnError)
		tokenFile := fs.String("token", "", "path to a signed token JSON (from `disarm sign`)")
		_ = fs.Parse(args)
		if *tokenFile == "" {
			fmt.Fprintln(os.Stderr, "usage: oknek disarm request --token <file>   (also: keygen, sign)")
			os.Exit(2)
		}
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read token: %v\n", err)
			os.Exit(1)
		}
		var tok disarm.Token
		if err := json.Unmarshal(data, &tok); err != nil {
			fmt.Fprintf(os.Stderr, "parse token: %v\n", err)
			os.Exit(1)
		}
		c, _ := client(configPath)
		var res struct {
			OK      bool   `json:"ok"`
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if err := c.Call("disarm", map[string]interface{}{"token": tok}, &res); err != nil {
			fmt.Fprintf(os.Stderr, "oknek: disarm: %v\n", err)
			os.Exit(1)
		}
		if !res.OK {
			fmt.Fprintf(os.Stderr, "disarm DENIED: %s\n", res.Error)
			os.Exit(1)
		}
		fmt.Printf("disarm OK: %s\n", res.Message)
	default:
		fmt.Fprintf(os.Stderr, "oknek disarm: unknown subcommand %q (use: keygen | sign | request)\n", sub)
		os.Exit(2)
	}
}

func runAttest(configPath string) {
	c, _ := client(configPath)
	var s struct {
		Enabled       bool   `json:"enabled"`
		Active        bool   `json:"active"`
		Reason        string `json:"reason"`
		Heartbeats    int    `json:"heartbeats"`
		Continuous    bool   `json:"continuous"`
		Tolerance     int64  `json:"tolerance_seconds"`
		AllEnforcing  bool   `json:"all_enforcing"`
		DisabledBeats int    `json:"disabled_beats"`
		Live          bool   `json:"live"`
		SilentFor     int64  `json:"silent_for_seconds"`
		Gaps          []struct {
			AfterTS  int64 `json:"after_ts"`
			BeforeTS int64 `json:"before_ts"`
			Seconds  int64 `json:"seconds"`
		} `json:"gaps"`
	}
	if err := c.Call("attest", nil, &s); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: attest: %v\n", err)
		os.Exit(1)
	}
	if !s.Enabled {
		fmt.Println("anti-unpin attestation is disabled (set self_guard.enabled in oknek.yaml)")
		return
	}
	if !s.Active {
		fmt.Printf("anti-unpin attestation inactive: %s\n", s.Reason)
		return
	}
	fmt.Printf("anti-unpin attestation · %d heartbeat(s) · gap tolerance %ds\n", s.Heartbeats, s.Tolerance)
	if !s.Live {
		fmt.Printf("   ✗ SILENCE — no heartbeat for %ds (> tolerance) — enforcement may be DOWN (reboot/exploit/stopped)\n", s.SilentFor)
	}
	if !s.AllEnforcing {
		fmt.Printf("   ✗ %d heartbeat(s) reported enforcement OFF — a flip the gap detector can't see\n", s.DisabledBeats)
	}
	if s.Continuous && s.AllEnforcing && s.Live {
		fmt.Println("   ✓ CONTINUOUS + ENFORCING + LIVE — no gap, no enforce-off beat, fresh")
		return
	}
	if s.Continuous && s.Live {
		return
	}
	fmt.Printf("   ✗ %d SILENCE GAP(S) — enforcement went dark (a disable that can't be hidden):\n", len(s.Gaps))
	for _, g := range s.Gaps {
		from := time.Unix(g.AfterTS, 0).Format("01-02 15:04:05")
		to := time.Unix(g.BeforeTS, 0).Format("01-02 15:04:05")
		fmt.Printf("   %s → %s   silent %ds\n", from, to, g.Seconds)
	}
}

func runEgress(configPath string) {
	c, _ := client(configPath)
	var s struct {
		Enabled  bool   `json:"enabled"`
		Enforce  bool   `json:"enforce"`
		Gateway  string `json:"gateway"`
		Lifetime int    `json:"lifetime"`
		Attempts []struct {
			TS      int64  `json:"ts"`
			Agent   string `json:"agent"`
			Process string `json:"process"`
			Dest    string `json:"dest"`
			PID     int    `json:"pid"`
		} `json:"attempts"`
	}
	if err := c.Call("egress", nil, &s); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: egress: %v\n", err)
		os.Exit(1)
	}
	if !s.Enabled {
		fmt.Println("egress jail is disabled (set egress_jail.enabled in oknek.yaml)")
		return
	}
	mode := "observe · logs, does not block"
	verb := "would block"
	if s.Enforce {
		mode = "ENFORCING · blocks at the kernel"
		verb = "BLOCKED"
	}
	fmt.Printf("egress jail · gateway %s · %s · %d off-gateway attempt(s) lifetime\n",
		s.Gateway, mode, s.Lifetime)
	if len(s.Attempts) == 0 {
		fmt.Println("   no off-gateway connections from watched agents yet")
		return
	}
	for _, a := range s.Attempts {
		t := time.Unix(0, a.TS).Format("01-02 15:04:05")
		fmt.Printf("   %s  %-18s %-14s → %-22s [%s]\n", t, a.Agent, a.Process, a.Dest, verb)
	}
}

func runOkular(configPath string, rest []string) {
	if len(rest) >= 1 && rest[0] == "export" {
		agent := ""
		if len(rest) >= 2 {
			agent = rest[1]
		}
		runOkularExport(configPath, agent)
		return
	}
	if len(rest) >= 1 && rest[0] == "verify-export" {
		if len(rest) < 2 {
			fmt.Fprintln(os.Stderr, "usage: oknek okular verify-export <bundle.json>")
			os.Exit(2)
		}
		runOkularVerifyExport(rest[1])
		return
	}
	if len(rest) >= 1 && rest[0] == "anchors" {
		runOkularAnchors(configPath)
		return
	}
	if len(rest) >= 1 && rest[0] == "anchor" {
		runOkularAnchorNow(configPath)
		return
	}
	if len(rest) >= 1 && rest[0] == "verify-remote" {
		runOkularVerifyRemote(configPath)
		return
	}
	c, _ := client(configPath)
	var s struct {
		Enabled   bool   `json:"enabled"`
		Active    bool   `json:"active"`
		Total     int64  `json:"total"`
		HeadSeq   int64  `json:"head_seq"`
		HeadHash  string `json:"head_hash"`
		Intact    bool   `json:"intact"`
		BrokenSeq int64  `json:"broken_seq"`
	}
	if err := c.Call("okular", nil, &s); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: okular: %v\n", err)
		os.Exit(1)
	}
	if !s.Enabled {
		fmt.Println("okular (tamper-proof audit ledger) is disabled (set okular.enabled in oknek.yaml)")
		return
	}
	hh := s.HeadHash
	if len(hh) > 16 {
		hh = hh[:16]
	}
	fmt.Println("okular · tamper-proof audit ledger")
	fmt.Printf("   entries:   %d\n", s.Total)
	fmt.Printf("   head:      seq %d · %s…\n", s.HeadSeq, hh)
	if s.Intact {
		fmt.Println("   integrity: ✓ chain intact — every action sealed, record provably unaltered")
	} else {
		fmt.Printf("   integrity: ✗ TAMPERED — hash chain breaks at seq %d\n", s.BrokenSeq)
	}
	fmt.Println("   replay an agent with: oknek replay <agent>")
}

func runOkularAnchors(configPath string) {
	c, _ := client(configPath)
	var s struct {
		Enabled  bool   `json:"enabled"`
		Verified bool   `json:"verified"`
		Count    int    `json:"count"`
		Reason   string `json:"reason"`
		Anchors  []struct {
			Seq      int64  `json:"anchor_seq"`
			TS       int64  `json:"ts"`
			HeadSeq  int64  `json:"head_seq"`
			HeadHash string `json:"head_hash"`
		} `json:"anchors"`
	}
	if err := c.Call("okular.anchors", nil, &s); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: okular anchors: %v\n", err)
		os.Exit(1)
	}
	if !s.Enabled {
		fmt.Println("okular ledger is disabled (set okular.enabled in oknek.yaml)")
		return
	}
	fmt.Printf("okular anchors · %d published checkpoint(s)\n", s.Count)
	for _, a := range s.Anchors {
		t := time.Unix(0, a.TS).Format("01-02 15:04:05")
		hh := a.HeadHash
		if len(hh) > 16 {
			hh = hh[:16]
		}
		fmt.Printf("   #%-3d %s  head seq %-5d  %s…\n", a.Seq, t, a.HeadSeq, hh)
	}
	if s.Verified {
		fmt.Println("   integrity: ✓ ledger agrees with every published checkpoint")
		fmt.Println("   (a later full rewrite of the ledger can't match these — even re-signed)")
	} else {
		fmt.Printf("   integrity: ✗ %s\n", s.Reason)
	}
}

func runOkularAnchorNow(configPath string) {
	c, _ := client(configPath)
	var s struct {
		Enabled bool `json:"enabled"`
		Anchor  *struct {
			Seq     int64  `json:"anchor_seq"`
			HeadSeq int64  `json:"head_seq"`
			Hash    string `json:"hash"`
		} `json:"anchor"`
	}
	if err := c.Call("okular.anchor.now", nil, &s); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: okular anchor: %v\n", err)
		os.Exit(1)
	}
	if !s.Enabled {
		fmt.Println("okular ledger is disabled (set okular.enabled in oknek.yaml)")
		return
	}
	if s.Anchor == nil {
		fmt.Println("okular: no new entries to anchor since the last checkpoint")
		return
	}
	hh := s.Anchor.Hash
	if len(hh) > 16 {
		hh = hh[:16]
	}
	fmt.Printf("okular: sealed anchor #%d at head seq %d (%s…)\n", s.Anchor.Seq, s.Anchor.HeadSeq, hh)
}

func runOkularVerifyRemote(configPath string) {
	c, _ := client(configPath)
	var s struct {
		Enabled    bool     `json:"enabled"`
		Anchors    int      `json:"anchors"`
		NewestSeq  int64    `json:"newest_seq"`
		NewestTime int64    `json:"newest_time"`
		OK         bool     `json:"ok"`
		Issues     []string `json:"issues"`
	}
	if err := c.Call("okular.verify-remote", nil, &s); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: okular verify-remote: %v\n", err)
		os.Exit(1)
	}
	if !s.Enabled {
		fmt.Println("off-box WORM escrow is disabled (set okular.worm.enabled in oknek.yaml)")
		return
	}
	fmt.Printf("okular verify-remote · %d escrowed anchor(s) · newest #%d", s.Anchors, s.NewestSeq)
	if s.NewestTime > 0 {
		fmt.Printf(" @ %s", time.Unix(s.NewestTime, 0).Format("01-02 15:04:05"))
	}
	fmt.Println()
	if s.OK {
		fmt.Println("   ✓ escrow intact — chain+signatures valid, no gaps, no back-dating, ledger agrees")
		return
	}
	fmt.Printf("   ✗ %d ISSUE(S) — the immutable off-box record disagrees with on-box state:\n", len(s.Issues))
	for _, is := range s.Issues {
		fmt.Printf("     • %s\n", is)
	}
	os.Exit(1)
}

func runOkularExport(configPath, agent string) {
	c, _ := client(configPath)
	var b okular.Bundle
	if err := c.Call("okular.export", map[string]interface{}{"agent": agent}, &b); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: okular export: %v\n", err)
		os.Exit(1)
	}
	if b.Format == "" {
		fmt.Fprintln(os.Stderr, "okular ledger is disabled (set okular.enabled in oknek.yaml)")
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(&b, "", "  ")
	fmt.Println(string(out))
}

func cond(b bool, a, c string) string {
	if b {
		return a
	}
	return c
}

func runOkularVerifyExport(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oknek: read %s: %v\n", path, err)
		os.Exit(1)
	}
	var b okular.Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: parse bundle: %v\n", err)
		os.Exit(1)
	}
	sigOK, chainOK, err := okular.VerifyBundle(&b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oknek: verify: %v\n", err)
		os.Exit(1)
	}
	fp := b.PubKey
	if len(fp) > 16 {
		fp = fp[:16]
	}
	mark := func(ok bool) string {
		if ok {
			return "✓"
		}
		return "✗"
	}
	fmt.Printf("okular sealed export · agent %q · %d action(s) · head seq %d\n", b.Agent, b.Count, b.HeadSeq)
	fmt.Printf("   signing key: %s…\n", fp)
	fmt.Printf("   %s signature: %s\n", mark(sigOK), cond(sigOK, "valid — not altered since sealed", "INVALID — tampered or wrong key"))
	fmt.Printf("   %s chain:     %s\n", mark(chainOK), cond(chainOK, "intact — every action's hash links", "BROKEN — an entry was edited"))
	if sigOK && chainOK {
		fmt.Println("   verdict: ✓ SEALED & VERIFIED")
	} else {
		fmt.Println("   verdict: ✗ FAILED — do not trust this record")
		os.Exit(3)
	}
}

func runReplay(configPath string, rest []string) {
	agent := ""
	if len(rest) > 0 {
		agent = rest[0]
	}
	c, _ := client(configPath)
	var s struct {
		Enabled bool `json:"enabled"`
		Entries []struct {
			Seq     int64  `json:"seq"`
			TS      int64  `json:"ts"`
			Agent   string `json:"agent"`
			Rule    string `json:"rule"`
			Verdict string `json:"verdict"`
			Payload string `json:"payload"`
		} `json:"entries"`
	}
	if err := c.Call("okular.replay", map[string]interface{}{"agent": agent, "limit": 50}, &s); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: replay: %v\n", err)
		os.Exit(1)
	}
	if !s.Enabled {
		fmt.Println("okular ledger is disabled (set okular.enabled in oknek.yaml)")
		return
	}
	who := agent
	if who == "" {
		who = "all agents"
	}
	fmt.Printf("okular replay · %s · %d action(s), newest first\n", who, len(s.Entries))
	for _, e := range s.Entries {
		t := time.Unix(0, e.TS).Format("15:04:05")
		pay := e.Payload
		if len(pay) > 60 {
			pay = pay[:60] + "…"
		}
		fmt.Printf("   #%-5d %s  %-16s %-4s %-6s %s\n", e.Seq, t, e.Agent, e.Rule, e.Verdict, pay)
	}
}

func runOkredo(configPath string) {
	c, _ := client(configPath)
	var s struct {
		Enabled  bool `json:"enabled"`
		Active   bool `json:"active"`
		Profiles []struct {
			Name     string   `json:"name"`
			PolicyID int      `json:"policy_id"`
			Grants   []string `json:"grants"`
		} `json:"profiles"`
	}
	if err := c.Call("okredo", nil, &s); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: okredo: %v\n", err)
		os.Exit(1)
	}
	if !s.Enabled {
		fmt.Println("okredo (agent IAM) is disabled (set okredo.enabled in oknek.yaml)")
		return
	}
	state := "configured · INACTIVE (needs egress_jail + kernel BPF-LSM)"
	if s.Active {
		state = "ACTIVE · identity-scoped authorization enforced at the kernel"
	}
	fmt.Printf("okredo (agent IAM) · %s\n", state)
	if len(s.Profiles) == 0 {
		fmt.Println("   no profiles defined")
		return
	}
	for _, p := range s.Profiles {
		fmt.Printf("   %-18s [policy %d]\n", p.Name, p.PolicyID)
		if len(p.Grants) == 0 {
			fmt.Println("      egress: base jail only (gateway · DNS · loopback)")
			continue
		}
		for _, g := range p.Grants {
			fmt.Printf("      egress: %s\n", g)
		}
	}
	fmt.Println("   bind an agent with: oknek run --profile <name> <command>")
}

func runExfil(configPath string) {
	c, _ := client(configPath)
	var s struct {
		Enabled  bool `json:"enabled"`
		Active   bool `json:"active"`
		Lifetime int  `json:"lifetime"`
		Catches  []struct {
			TS       int64   `json:"ts"`
			Agent    string  `json:"agent"`
			Pattern  string  `json:"pattern"`
			Dest     string  `json:"dest"`
			Interval float64 `json:"interval"`
			Jitter   float64 `json:"jitter"`
			Connects int     `json:"connects"`
			Process  string  `json:"process"`
		} `json:"catches"`
	}
	if err := c.Call("exfil", nil, &s); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: exfil: %v\n", err)
		os.Exit(1)
	}
	if !s.Enabled {
		fmt.Println("exfil watch is disabled (set exfil_watch.enabled in oknek.yaml)")
		return
	}
	state := "INACTIVE (needs egress_jail enabled)"
	if s.Active {
		state = "active · alert-only"
	}
	fmt.Printf("exfil/C2 watch · %s · %d alert(s) lifetime\n", state, s.Lifetime)
	if len(s.Catches) == 0 {
		fmt.Println("   no beaconing or velocity alerts yet")
		return
	}
	for _, e := range s.Catches {
		t := time.Unix(0, e.TS).Format("01-02 15:04:05")
		switch e.Pattern {
		case "beacon":
			fmt.Printf("   %s  BEACON   %-18s → %-22s every ~%.0fs (jitter %.0f%%) [%s]\n",
				t, e.Agent, e.Dest, e.Interval, e.Jitter*100, e.Process)
		case "velocity":
			fmt.Printf("   %s  VELOCITY %-18s %d off-gateway connects in window [%s]\n",
				t, e.Agent, e.Connects, e.Process)
		}
	}
}

func runPing(configPath string) {
	c, _ := client(configPath)
	var resp map[string]string
	if err := c.Call("ping", nil, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: ping: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(resp["pong"])
}

func runStatus(configPath string) {
	c, cfg := client(configPath)
	var s map[string]interface{}
	if err := c.Call("status", nil, &s); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: status: %v\n", err)
		fmt.Fprintf(os.Stderr, "  socket: %s\n", cfg.Socket)
		fmt.Fprintf(os.Stderr, "  hint:   is oknekd running? try `oknekd` in another terminal.\n")
		os.Exit(1)
	}
	printStatus(s)
}

func printStatus(s map[string]interface{}) {
	get := func(k string) string {
		if v, ok := s[k]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}

	fmt.Printf("oknek %s · kernel %s · %s-mode\n",
		get("version"), get("kernel"), get("hook_mode"))
	rows := [][2]string{
		{"socket", get("socket")},
		{"db", fmt.Sprintf("%s (%s bytes, %s events)", get("db_path"), get("db_size_bytes"), get("events"))},
		{"schema", get("schema_version")},
		{"install id", truncate(get("install_id"), 24)},
		{"rule pack", get("rule_pack")},
		{"agents", fmt.Sprintf("%s watched · %s blocked · %s alerted", get("agents"), get("blocked"), get("alerted"))},
		{"uptime", get("uptime_seconds") + "s"},
	}
	for _, r := range rows {
		fmt.Printf("   %-12s %s\n", r[0]+":", r[1])
	}

	// emit any unexpected fields after the known ones (debug aid)
	known := map[string]bool{
		"version": true, "kernel": true, "hook_mode": true, "socket": true,
		"db_path": true, "db_size_bytes": true, "events": true, "schema_version": true,
		"install_id": true, "rule_pack": true, "agents": true, "blocked": true,
		"alerted": true, "uptime_seconds": true,
		"commit": true, "build_date": true, "goos": true, "goarch": true,
	}
	extras := make([]string, 0)
	for k := range s {
		if !known[k] {
			extras = append(extras, k)
		}
	}
	sort.Strings(extras)
	for _, k := range extras {
		fmt.Printf("   %-12s %v\n", k+":", s[k])
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func runRules(configPath string, rest []string) {
	if len(rest) == 0 || rest[0] != "list" {
		fmt.Fprintln(os.Stderr, "usage: oknek rules list")
		os.Exit(2)
	}
	c, _ := client(configPath)
	var resp struct {
		Count int `json:"count"`
		Rules []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Kind string `json:"kind"`
		} `json:"rules"`
	}
	if err := c.Call("rules.list", nil, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: rules list: %v\n", err)
		os.Exit(1)
	}
	if resp.Count == 0 {
		fmt.Println("no rules loaded")
		return
	}
	for _, r := range resp.Rules {
		fmt.Printf("%-4s %-32s %s\n", r.ID, r.Name, r.Kind)
	}
}

func runCheck(configPath string, rest []string) {
	if len(rest) == 0 {
		checkUsage()
	}
	switch rest[0] {
	case "exec":
		if len(rest) < 2 {
			checkUsage()
		}
		cmd := strings.Join(rest[1:], " ")
		runCheckRPC(configPath, "check.exec",
			map[string]string{"command": cmd}, cmd)
	case "filechange":
		if len(rest) < 2 {
			checkUsage()
		}
		path := rest[1]
		op := "modify"
		if len(rest) >= 3 {
			op = rest[2]
		}
		runCheckRPC(configPath, "check.filechange",
			map[string]string{"path": path, "op": op}, path+" ("+op+")")
	case "fileopen":
		if len(rest) < 2 {
			checkUsage()
		}
		path := rest[1]
		runCheckRPC(configPath, "check.fileopen",
			map[string]string{"path": path, "mode": "read", "process": "claude"}, path)
	case "mcp":
		if len(rest) < 3 {
			checkUsage()
		}
		transport := rest[1]
		target := strings.Join(rest[2:], " ")
		params := map[string]string{"transport": transport}
		if transport == "stdio" {
			params["command"] = target
		} else {
			params["url"] = target
		}
		runCheckRPC(configPath, "check.mcp", params, transport+" "+target)
	case "socket":
		if len(rest) < 2 {
			checkUsage()
		}
		host := rest[1]
		port := "443"
		if len(rest) >= 3 {
			port = rest[2]
		}
		runCheckRPCAny(configPath, "check.socket",
			map[string]interface{}{"dest_host": host, "dest_port": atoiOr(port, 443)},
			host+":"+port)
	case "scan":
		if len(rest) < 2 {
			checkUsage()
		}
		path := rest[1]
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "oknek: read %s: %v\n", path, err)
			os.Exit(1)
		}
		runCheckRPCAny(configPath, "check.scan",
			map[string]interface{}{
				"path":    path,
				"content": base64Encode(data),
			},
			path)
	case "drift":
		if len(rest) < 3 {
			checkUsage()
		}
		agent := rest[1]
		feats := rest[2:]
		runCheckRPCAny(configPath, "check.drift",
			map[string]interface{}{"agent_id": agent, "features": feats},
			fmt.Sprintf("%s · %d features", agent, len(feats)))
	default:
		checkUsage()
	}
}

func runBaseline(configPath string, rest []string) {
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "usage:")
		fmt.Fprintln(os.Stderr, "  oknek baseline observe <agent> <feature1> [feature2 ...]")
		fmt.Fprintln(os.Stderr, "  oknek baseline size")
		os.Exit(2)
	}
	switch rest[0] {
	case "observe":
		if len(rest) < 3 {
			fmt.Fprintln(os.Stderr, "usage: oknek baseline observe <agent> <feature1> [...]")
			os.Exit(2)
		}
		agent := rest[1]
		feats := rest[2:]
		c, _ := client(configPath)
		var resp struct {
			Observed     int    `json:"observed"`
			AgentID      string `json:"agent_id"`
			BaselineSize int    `json:"baseline_size"`
		}
		if err := c.Call("baseline.observe",
			map[string]interface{}{"agent_id": agent, "features": feats},
			&resp); err != nil {
			fmt.Fprintf(os.Stderr, "oknek: baseline observe: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("observed %d features for agent=%s · baseline now %d rows\n",
			resp.Observed, resp.AgentID, resp.BaselineSize)
	case "size":
		c, _ := client(configPath)
		var resp struct {
			BaselineSize int `json:"baseline_size"`
		}
		if err := c.Call("baseline.size", nil, &resp); err != nil {
			fmt.Fprintf(os.Stderr, "oknek: baseline size: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("baseline rows: %d\n", resp.BaselineSize)
	default:
		fmt.Fprintf(os.Stderr, "oknek: unknown baseline subcommand %q\n", rest[0])
		os.Exit(2)
	}
}

// runRun registers this process as a watched agent with the daemon, then execs
// the given command. Because syscall.Exec keeps the SAME pid, the target runs
// under the kernel BPF-LSM hook — so even a statically-linked target (which the
// LD_PRELOAD shim can't touch) has its credential reads enforced.
func runRun(configPath string, rest []string) {
	// Flags before the command: --agent <name>, --profile <name>. A `--` ends
	// flag parsing so `oknek run --agent x -- cmd --its-own-flag` works.
	profile := os.Getenv("OKNEK_PROFILE")
	agentFlag := ""
	for len(rest) >= 2 && (rest[0] == "--agent" || rest[0] == "--profile") {
		if rest[0] == "--agent" {
			agentFlag = rest[1]
		} else {
			profile = rest[1]
		}
		rest = rest[2:]
	}
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "usage: oknek run [--agent <name>] [--profile <name>] <command> [args...]")
		fmt.Fprintln(os.Stderr, "  runs <command> as an oknek-watched agent so oknek can block dangerous")
		fmt.Fprintln(os.Stderr, "  actions in real time — kernel BPF-LSM where available, LD_PRELOAD shim otherwise.")
		os.Exit(2)
	}
	agent := agentFlag
	if agent == "" {
		agent = os.Getenv("OKNEK_AGENT")
	}
	if agent == "" {
		agent = "run-" + strconv.Itoa(os.Getpid())
	}
	c, cfg := client(configPath)
	params := map[string]interface{}{"pid": os.Getpid(), "agent_id": agent, "mode": "ebpf", "new_session": true}
	if profile != "" {
		params["profile"] = profile
	}
	if err := c.Call("hook.attach", params, nil); err != nil {
		fmt.Fprintf(os.Stderr, "oknek run: warning: daemon unreachable (%v); running unwatched\n", err)
	}
	bin, err := exec.LookPath(rest[0])
	if err != nil {
		bin = rest[0]
	}
	if err := syscall.Exec(bin, rest, oknekRunEnv(cfg, agent)); err != nil {
		fmt.Fprintf(os.Stderr, "oknek run: exec %s: %v\n", bin, err)
		os.Exit(1)
	}
}

// oknekRunEnv builds the child environment for `oknek run`: names the agent,
// points the shim at the daemon socket, and injects the LD_PRELOAD interposition
// shim so enforcement works even without a kernel BPF-LSM (on BPF-LSM kernels the
// hook.attach already arms the kernel path; the shim is harmless belt-and-braces).
// Shim path = $OKNEK_SHIM, else the standard install location if present.
func oknekRunEnv(cfg *config.Config, agent string) []string {
	shim := os.Getenv("OKNEK_SHIM")
	if shim == "" {
		for _, p := range []string{
			"/usr/local/lib/oknek/liboknek_preload.so",
			"/opt/oknek/lib/oknek/liboknek_preload.so",
		} {
			if fi, e := os.Stat(p); e == nil && !fi.IsDir() {
				shim = p
				break
			}
		}
	}
	ld := os.Getenv("LD_PRELOAD")
	if shim != "" {
		if ld != "" {
			ld = shim + ":" + ld
		} else {
			ld = shim
		}
	}
	sock := ""
	if cfg != nil {
		sock = cfg.Socket
	}
	// Rebuild environ, dropping pre-existing copies of the vars we set so the
	// child's getenv resolves to ours (getenv returns the first match).
	drop := map[string]bool{"OKNEK_AGENT": true, "OKNEK_SOCK": true, "LD_PRELOAD": true}
	var out []string
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i > 0 && drop[kv[:i]] {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "OKNEK_AGENT="+agent)
	if sock != "" {
		out = append(out, "OKNEK_SOCK="+sock)
	}
	if ld != "" {
		out = append(out, "LD_PRELOAD="+ld)
	}
	return out
}

func atoiOr(s string, def int) int {
	n := def
	if v, err := strconv.Atoi(s); err == nil {
		n = v
	}
	return n
}

func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func runCheckRPCAny(configPath, method string, params map[string]interface{}, display string) {
	c, _ := client(configPath)
	var resp struct {
		Input     string                   `json:"input"`
		Matched   bool                     `json:"matched"`
		Evaluated int                      `json:"evaluated"`
		Matches   []map[string]interface{} `json:"matches"`
	}
	if err := c.Call(method, params, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: %s: %v\n", method, err)
		os.Exit(1)
	}
	if !resp.Matched {
		fmt.Printf("ok · no rules fired (%d evaluated)\n", resp.Evaluated)
		fmt.Printf("    input: %s\n", display)
		return
	}
	fmt.Printf("⚠ %d rule(s) fired (out of %d evaluated)\n\n", len(resp.Matches), resp.Evaluated)
	for _, m := range resp.Matches {
		fmt.Printf("  %s %s (%s)\n", m["rule_id"], m["name"], m["verdict"])
		if ev, ok := m["evidence"].(map[string]interface{}); ok {
			for k, v := range ev {
				fmt.Printf("    %-18s %v\n", k+":", v)
			}
		}
		fmt.Println()
	}
}

func checkUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  oknek check exec <bash command>")
	fmt.Fprintln(os.Stderr, "  oknek check filechange <path> [create|modify|delete]")
	fmt.Fprintln(os.Stderr, "  oknek check fileopen <path>")
	os.Exit(2)
}

func runCheckRPC(configPath, method string, params map[string]string, display string) {
	c, _ := client(configPath)
	var resp struct {
		Input     string                   `json:"input"`
		Matched   bool                     `json:"matched"`
		Evaluated int                      `json:"evaluated"`
		Matches   []map[string]interface{} `json:"matches"`
	}
	if err := c.Call(method, params, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: %s: %v\n", method, err)
		os.Exit(1)
	}
	if !resp.Matched {
		fmt.Printf("ok · no rules fired (%d evaluated)\n", resp.Evaluated)
		fmt.Printf("    input: %s\n", display)
		return
	}
	fmt.Printf("⚠ %d rule(s) fired (out of %d evaluated)\n\n", len(resp.Matches), resp.Evaluated)
	for _, m := range resp.Matches {
		fmt.Printf("  %s %s (%s)\n", m["rule_id"], m["name"], m["verdict"])
		if ev, ok := m["evidence"].(map[string]interface{}); ok {
			for k, v := range ev {
				fmt.Printf("    %-18s %v\n", k+":", v)
			}
		}
		fmt.Println()
	}
}
