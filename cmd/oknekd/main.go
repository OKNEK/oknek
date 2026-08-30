// Command oknekd is the oknek runtime defense daemon.
//
// oknekd hooks AI agent processes at the kernel syscall layer (eBPF BPF-LSM on
// Linux, LD_PRELOAD shim as fallback), baselines their behavior, and blocks the
// action in-kernel when an agent goes rogue. Kernel-enforced rules cover the full
// agent-attack surface — steal (R3 cred file + R13 cross-process memory), exfil
// (R11 egress jail), persist (R14 backdoor writes), escalate (R15 sudo/su exec),
// inbound backdoor (R16 socket bind), self-defense (R17 bpf() lockdown, R18 kernel-
// module load, R19 mount) — plus the R1–R7 detection pack and R9/R10/R12
// governance/watch rules. 11 BPF programs (9 enforcing + fork/exit propagation).
//
// This binary is pre-release. v1 ships 2026-05-25. See https://oknek.com/docs/
// for the architecture overview and detection rule reference.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oknek/oknek/internal/attest"
	"github.com/oknek/oknek/internal/config"
	"github.com/oknek/oknek/internal/configpull"
	"github.com/oknek/oknek/internal/disarm"
	"github.com/oknek/oknek/internal/exfilwatch"
	"github.com/oknek/oknek/internal/feed"
	"github.com/oknek/oknek/internal/gpuwatch"
	"github.com/oknek/oknek/internal/hooks/ebpf"
	"github.com/oknek/oknek/internal/ipc"
	"github.com/oknek/oknek/internal/okular"
	"github.com/oknek/oknek/internal/routewatch"
	"github.com/oknek/oknek/internal/rules"
	"github.com/oknek/oknek/internal/store"

	"golang.org/x/sys/unix"
)

// Build-time stamps injected via Makefile -ldflags.
var (
	version   = "0.9.0-arsenal"
	commit    = "unknown"
	buildDate = "unknown"
)

const helpText = `oknekd %s · runtime defense daemon for AI agents

usage:
  oknekd                    run the daemon (foreground)
  oknekd --config <path>    use a specific config file
  oknekd --version          print version and exit
  oknekd --help             this help

state: pre-release. v1 ships 2026-05-25.
docs:  https://oknek.com/docs/architecture/
`

var startedAt = time.Now()

// hookState tracks which interception mode is live and which agents have
// attached, so `status` can report the truth instead of hard-coded zeros.
type hookState struct {
	mu     sync.Mutex
	mode   string
	agents map[string]bool
}

func newHookState() *hookState {
	return &hookState{mode: "stub", agents: map[string]bool{}}
}

func (h *hookState) attach(mode, agent string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// The kernel path is the authority: once BPF-LSM has attached ("ebpf"), a later
	// per-process shim registration ("ld_preload"/"dyld") must not downgrade the
	// reported mode — the shim runs UNDER the kernel hooks, it does not replace them.
	if mode != "" && !(h.mode == "ebpf" && mode != "ebpf") {
		h.mode = mode
	}
	if agent != "" {
		h.agents[agent] = true
	}
}

func (h *hookState) snapshot() (mode string, agents int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.mode, len(h.agents)
}

// HookAttachParams is the body of hook.attach (sent once by the shim at init).
type HookAttachParams struct {
	Mode    string `json:"mode"`     // "ld_preload" | "dyld"
	AgentID string `json:"agent_id"` // logical agent identity
	PID     int    `json:"pid,omitempty"`
	Binary  string `json:"binary,omitempty"`
	Profile string `json:"profile,omitempty"` // Okredo identity/role profile
	// NewSession is set ONLY by `oknek run`: a fresh session for this identity, so
	// its R21 taint is reset. The LD_PRELOAD shim attaches per process and must NOT
	// reset the session (a child `cat` is the same session).
	NewSession bool `json:"new_session,omitempty"`
}

func hookAttachHandler(hs *hookState, loader *ebpf.Loader, okredo map[string]uint16, idSvc *identityService, mcpSvc *mcpService) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		var p HookAttachParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, fmt.Errorf("decode params: %w", err)
			}
		}
		hs.attach(p.Mode, p.AgentID)
		// Identify the agent by the kernel-verified peer PID (SO_PEERCRED): it is the
		// GLOBAL pid even when the agent runs in a container and reports its
		// namespaced pid in the body, and it can't be spoofed. This is what makes
		// enforcement actually match across a PID namespace (the Class-6 container
		// gap). Fall back to the self-reported PID only when peer creds are
		// unavailable (e.g. non-Linux dev).
		pid := p.PID
		if peer, ok := ipc.PeerPIDFromContext(ctx); ok {
			if p.PID > 0 && peer != p.PID {
				log.Printf("hook.attach: agent %q registered at global pid %d (agent-reported nspid %d) — container-translated", p.AgentID, peer, p.PID)
			}
			pid = peer
		}
		if loader != nil && pid > 0 {
			if p.NewSession {
				_ = loader.ClearTaint(p.AgentID) // R21: new session starts clean
			}
			_ = loader.RegisterPID(uint32(pid), p.AgentID)
			// Okredo: bind this agent's kernel identity to its authorization profile.
			if p.Profile != "" {
				if id, ok := okredo[p.Profile]; ok {
					_ = loader.SetAgentPolicy(uint32(pid), id)
					log.Printf("okredo: agent %q bound to profile %q (policy %d) at pid %d", p.AgentID, p.Profile, id, pid)
				} else {
					log.Printf("okredo: agent %q requested unknown profile %q — base jail only", p.AgentID, p.Profile)
				}
			}
			if p.NewSession {
				mcpSvc.NewSession(uint32(pid), p.AgentID, p.Profile) // R24: read this session's MCP manifests
				idSvc.Push(p.AgentID, "register")                    // Okredo Attest: announce the new session
			}
		}
		mode, agents := hs.snapshot()
		return map[string]interface{}{"ok": true, "hook_mode": mode, "agents": agents}, nil
	}
}

// logMatches persists every non-allow match to the event store and, when a feed
// is configured, POSTs it to the dashboard (nil-safe, best-effort).
func logMatches(db *store.Store, poster *feed.Poster, ev rules.Event, matches []rules.Match) {
	for _, m := range matches {
		if m.Verdict == rules.VerdictAllow {
			continue
		}
		payload, _ := json.Marshal(m.Evidence)
		id := fmt.Sprintf("e_%d_%d_%s", ev.Timestamp, ev.PID, m.RuleID)
		_ = db.InsertEvent(id, ev.Timestamp, ev.AgentID, m.RuleID, m.Verdict.String(), string(payload))
		poster.Post(id, ev.Timestamp, ev.AgentID, m.RuleID, m.Verdict.String(), string(payload))
	}
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
		fmt.Printf("oknekd %s · commit=%s · built=%s\n", version, commit, buildDate)
		return
	}
	if *showHelp {
		fmt.Printf(helpText, version)
		return
	}

	if err := run(*configPath); err != nil {
		log.Fatalf("oknekd: %v", err)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := cfg.EnsureDirs(); err != nil {
		return fmt.Errorf("ensure dirs: %w", err)
	}

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer db.Close()

	engine := rules.NewEngine()
	engine.Register(rules.NewR1())
	engine.Register(rules.NewR2())
	engine.Register(rules.NewR3())
	engine.Register(rules.NewR4())
	engine.Register(rules.NewR5())
	engine.Register(rules.NewR6())
	engine.Register(rules.NewR7(&storeBaselineAdapter{db}))
	log.Printf("rules: %d loaded", engine.Count())

	srv, err := ipc.NewServer(cfg.Socket)
	if err != nil {
		return fmt.Errorf("ipc server: %w", err)
	}

	hs := newHookState()

	// ctx drives both the IPC server and the eBPF ringbuf drain.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// R12 exfil/C2 watch — opt-in via exfil_watch. The aggregator taps R11's
	// kernel connect stream (below) to detect beaconing + velocity. Alert-only.
	var exfilAgg *exfilwatch.Aggregator
	var exfilObserve ebpf.ConnectObserver
	if cfg.ExfilWatch.Enabled {
		ew := config.NormalizeExfilWatch(cfg.ExfilWatch)
		exfilAgg = exfilwatch.New(ew, db.InsertEvent, log.Default())
		exfilObserve = exfilAgg.Observe
	}

	// Dashboard feed (concierge per-customer). nil = disabled; Post is nil-safe.
	var poster *feed.Poster
	if cfg.Feed.Enabled {
		poster = feed.New(cfg.Feed.URL, cfg.Feed.Key)
		if poster != nil {
			log.Printf("feed: dashboard event feed ENABLED -> %s", cfg.Feed.URL)
		} else {
			log.Printf("feed: enabled but url/key missing — feed disabled")
		}
	}

	// Okular (Audit pillar) — seal every kernel enforcement event into a tamper-proof
	// hash-chained ledger, in addition to the operational event store.
	insert := db.InsertEvent
	if poster != nil {
		base := insert
		insert = func(id string, ts int64, agentID, ruleID, verdict, payload string) error {
			err := base(id, ts, agentID, ruleID, verdict, payload)
			poster.Post(id, ts, agentID, ruleID, verdict, payload)
			return err
		}
	}
	// R24: an R11 block from a bound MCP server pid is relabelled R24 (set once the
	// MCP service exists; nil until then). Applied OUTERMOST (below, right before
	// ebpf.Start) so the relabelled rule reaches the store, the feed AND Okular.
	var mcpRelabel func(ruleID, payload string) (string, string)
	var mcpObserve ebpf.ConnectObserver
	connectObserve := func(agentID, comm string, pid int, ip string, port uint16, ts int64) {
		if exfilObserve != nil {
			exfilObserve(agentID, comm, pid, ip, port, ts)
		}
		if mcpObserve != nil {
			mcpObserve(agentID, comm, pid, ip, port, ts)
		}
	}

	var okularLedger *okular.Ledger
	if cfg.Okular.Enabled {
		opath := cfg.Okular.Path
		if opath == "" {
			opath = filepath.Join(filepath.Dir(cfg.DBPath), "okular.db")
		}
		l, oerr := okular.Open(opath)
		if oerr != nil {
			log.Printf("okular: disabled — %v", oerr)
		} else {
			okularLedger = l
			defer okularLedger.Close()
			base := insert
			insert = func(id string, ts int64, agentID, ruleID, verdict, payload string) error {
				err := base(id, ts, agentID, ruleID, verdict, payload)
				_ = okularLedger.Append(ts, agentID, ruleID, verdict, payload)
				return err
			}
			seq, _ := okularLedger.Head()
			log.Printf("okular: tamper-proof audit ledger active at %s (resumed at seq %d)", opath, seq)
			// Off-box WORM escrow (S3 Object-Lock): makes anchors immutable off-box, so
			// on-box root can't rewrite audit history. Opt-in via okular.worm.
			if cfg.Okular.WORM.Enabled {
				h, _ := os.Hostname()
				okularLedger.SetShipper(okular.NewWORMShipper(cfg.Okular.WORM, h))
				log.Printf("okular: WORM escrow ENABLED -> %s/%s region=%s retain=%dd — anchors escrowed immutable off-box",
					cfg.Okular.WORM.Endpoint, cfg.Okular.WORM.Bucket, cfg.Okular.WORM.Region, cfg.Okular.WORM.RetentionDays)
			}
			// Anchoring: periodically publish a signed, chained head-hash checkpoint
			// to the append-only anchor file AND the daemon log (journald = an
			// external sink), so a later full rewrite of the ledger can't match the
			// already-published checkpoints.
			go func() {
				t := time.NewTicker(60 * time.Second)
				defer t.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-t.C:
						a, err := okularLedger.EmitAnchor(time.Now().UnixNano())
						if a != nil {
							log.Printf("okular: anchor #%d sealed head seq %d (%s…)", a.Seq, a.HeadSeq, a.Hash[:16])
						}
						if err != nil {
							// a non-nil anchor + error = local seal OK but OFF-BOX ESCROW FAILED:
							// loud, because a blocked escrow is itself a tamper signal (gap off-box).
							log.Printf("okular: ⚠️ WORM escrow FAILED for anchor: %v", err)
						}
					}
				}
			}()
		}
	}

	// Config-pull (Dean's approve→apply loop). The daemon polls the dashboard for
	// human-APPROVED config changes, validates each against the allowlist, seals it
	// into Okular (record-first, fail-closed), applies it to the effective-policy
	// overlay, and acks with the seal receipt. Outbound-only, reuses the feed key.
	// Requires Okular — an approved change is never applied unless it's first sealed.
	if cfg.Feed.Enabled && cfg.Feed.Key != "" {
		pendingURL, ackURL := cfg.Feed.ConfigPullURLs()
		switch {
		case okularLedger == nil:
			log.Printf("configpull: feed enabled but okular is off — config-pull needs the audit ledger; skipping")
		case pendingURL == "" || ackURL == "":
			log.Printf("configpull: feed enabled but no config endpoints could be derived from %q; skipping", cfg.Feed.URL)
		default:
			overlayPath := filepath.Join(filepath.Dir(cfg.DBPath), "policy.overlay.yaml")
			overlay, operr := configpull.OpenOverlay(overlayPath)
			if operr != nil {
				log.Printf("configpull: disabled — %v", operr)
			} else {
				sealer := okularPolicySealer{l: okularLedger}
				if puller := configpull.New(pendingURL, ackURL, cfg.Feed.Key, overlay, sealer, log.Default()); puller != nil {
					log.Printf("configpull: config-pull ENABLED -> %s (overlay %s)", pendingURL, overlayPath)
					go puller.Run(ctx, 60*time.Second)
				}
			}
		}
	}

	// Prefer kernel-grade enforcement (BPF-LSM). Falls back to LD_PRELOAD mode
	// when the box can't run it. The loader registers watched-agent PIDs and
	// streams block events into the same store the LD_PRELOAD path writes to.
	{
		base := insert
		insert = func(id string, ts int64, agentID, ruleID, verdict, payload string) error {
			if mcpRelabel != nil {
				ruleID, payload = mcpRelabel(ruleID, payload)
			}
			return base(id, ts, agentID, ruleID, verdict, payload)
		}
	}
	ebpfLoader, eerr := ebpf.Start(ctx, insert, hs.attach, connectObserve)
	if eerr != nil {
		log.Printf("eBPF LSM: inactive (%v) — running in LD_PRELOAD mode", eerr)
	} else {
		log.Printf("eBPF LSM: attached · kernel-grade R3 enforcement live")
		defer ebpfLoader.Close()
	}

	// R11 egress jail — opt-in via egress_jail config. Needs the BPF-LSM loader.
	// Watched agents are registered via the existing hook.attach → RegisterPID
	// path, so they're jailed the moment the policy is installed.
	if cfg.EgressJail.Enabled {
		if ebpfLoader != nil {
			ip := net.ParseIP(cfg.EgressJail.Gateway.Host)
			resolvers := systemResolvers()
			if ip == nil {
				log.Printf("egress_jail: gateway host %q is not an IP — jail inactive", cfg.EgressJail.Gateway.Host)
			} else if err := ebpfLoader.SetEgressPolicy(ip, cfg.EgressJail.Gateway.Port, cfg.EgressJail.AllowDNS(), cfg.EgressJail.Enforce, resolvers); err != nil {
				log.Printf("egress_jail: set policy failed: %v", err)
			} else {
				log.Printf("egress_jail: R11 active · gateway %s:%d · allow_dns=%v (resolvers=%d) · enforce=%v",
					ip, cfg.EgressJail.Gateway.Port, cfg.EgressJail.AllowDNS(), len(resolvers), cfg.EgressJail.Enforce)
			}
		} else {
			log.Printf("egress_jail: configured but INACTIVE — kernel BPF-LSM unavailable on this host (route-around block needs lsm=...,bpf)")
		}
	}

	// R3 inode protection — resolve protected_files to (dev, inode) so credential
	// reads are blocked even when opened via a hardlink, rename, or bind-mount
	// (different path, same inode). Additive: an empty list leaves R3's name
	// matching untouched. dev is re-encoded to the kernel's new_encode_dev() form
	// so it matches inode->i_sb->s_dev as the BPF hook reads it.
	if ebpfLoader != nil && len(cfg.ProtectedFiles) > 0 {
		n := 0
		for _, path := range cfg.ProtectedFiles {
			var st unix.Stat_t
			if err := unix.Stat(path, &st); err != nil {
				continue
			}
			major, minor := unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev))
			kdev := (major << 20) | minor // kernel MKDEV = inode->i_sb->s_dev as the BPF hook reads it
			if err := ebpfLoader.AddProtectedInode(kdev, uint64(st.Ino)); err == nil {
				n++
			}
		}
		log.Printf("cred_guard: %d protected inode(s) loaded — hardlink/rename-proof", n)
	}

	// Tier-A gated disarm: BEFORE arming, honor an authorized disarm-on-boot marker. The
	// marker embeds an off-box-signed token (root can write the file but cannot forge the
	// signature), so a VALID marker -> don't arm = clean authorized uninstall via reboot;
	// a forged/absent marker is ignored and we arm normally. BootCheck records DISARMED
	// record-first and only signals "don't arm" once that lands (else it stays armed).
	disarmedAtBoot := false
	if cfg.Disarm.Enabled && okularLedger != nil {
		if az, err := newDisarmAuthorizer(cfg, okularLedger); err != nil {
			log.Printf("disarm: config error, arming normally: %v", err)
		} else if arm, derr := az.BootCheck(time.Now().Unix()); !arm {
			disarmedAtBoot = true
			log.Printf("disarm: authorized disarm marker honored — NOT arming self_guard (clean uninstall)")
		} else if derr != nil {
			log.Printf("disarm: %v", derr)
		}
	}

	// R20 anti-unpin (self-pin-guard) — opt-in via self_guard config. Arms the
	// kernel guard that denies rm/rename of oknek's OWN bpffs pins (so a root
	// insider can't detach enforcement by deleting the pin) and starts the
	// attestation heartbeat + in-process pin watchdog. Unlike every other rule this
	// guards oknek's off-switch against anyone, root included.
	if cfg.SelfGuard.Enabled && !disarmedAtBoot {
		sg := config.NormalizeSelfGuard(cfg.SelfGuard)
		if ebpfLoader == nil {
			log.Printf("self_guard: configured but INACTIVE — kernel BPF-LSM unavailable (anti-unpin needs lsm=...,bpf)")
		} else if err := ebpfLoader.ArmSelfGuard(sg.Enforce); err != nil {
			log.Printf("self_guard: arm failed: %v", err)
		} else {
			init, enf := ebpfLoader.SelfGuardArmed()
			log.Printf("self_guard: R20 armed · pin dir %s · enforce=%v (initialised=%v) · %d pins protected",
				ebpf.PinDir(), enf, init, ebpfLoader.CountPins())
			// Part B+C: heartbeat into Okular (silence = the alarm — a disable we
			// can't prevent in-kernel still leaves an un-backfillable ledger gap) +
			// in-process pin watchdog (re-pin a link if its bpffs pin is removed
			// while we're alive). Heartbeat attestation needs the append-only ledger.
			if okularLedger != nil {
				go func() {
					t := time.NewTicker(time.Duration(sg.HeartbeatSeconds) * time.Second)
					defer t.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-t.C:
							if healed := ebpfLoader.HealPins(); healed > 0 {
								log.Printf("self_guard: watchdog re-pinned %d link(s)", healed)
							}
							_, e := ebpfLoader.SelfGuardArmed()
							payload := fmt.Sprintf(`{"pins":%d,"enforcing":%v}`, ebpfLoader.CountPins(), e)
							_ = okularLedger.Append(time.Now().UnixNano(), heartbeatAgent, heartbeatRule, "alive", payload)
						}
					}
				}()
				log.Printf("self_guard: attestation heartbeat every %ds (gap>%ds = enforcement silenced) → okular",
					sg.HeartbeatSeconds, sg.HeartbeatSeconds*sg.GapMultiple)
			} else {
				log.Printf("self_guard: heartbeat attestation disabled — needs okular.enabled (the append-only ledger)")
			}
		}
	}

	// Okredo (IAM) — assign each named profile a kernel policy id and load its
	// per-agent egress allowlist. Agents bind to a profile at hook.attach
	// (`oknek run --profile`), and the kernel applies that identity's grants.
	okredoProfiles := map[string]uint16{}
	if cfg.Okredo.Enabled && ebpfLoader != nil {
		names := make([]string, 0, len(cfg.Okredo.Profiles))
		for name := range cfg.Okredo.Profiles {
			names = append(names, name)
		}
		sort.Strings(names) // deterministic policy-id assignment
		var id uint16
		grants := 0
		for _, name := range names {
			id++
			okredoProfiles[name] = id
			for _, entry := range cfg.Okredo.Profiles[name].AllowEgress {
				host, portStr, err := net.SplitHostPort(entry)
				port, perr := strconv.Atoi(portStr)
				if err != nil || perr != nil {
					log.Printf("okredo: profile %q has bad allow_egress %q (want ip:port or cidr:port)", name, entry)
					continue
				}
				if strings.Contains(host, "/") { // CIDR range grant
					ip, ipnet, cerr := net.ParseCIDR(host)
					ones, bits := 0, 0
					if cerr == nil {
						ones, bits = ipnet.Mask.Size()
					}
					if cerr != nil || bits != 32 || ones == 0 || ones%8 != 0 {
						log.Printf("okredo: profile %q CIDR %q must be byte-aligned IPv4 (/8,/16,/24,/32)", name, entry)
						continue
					}
					if err := ebpfLoader.AddEgressCIDR(id, ip.Mask(ipnet.Mask), uint8(ones/8), uint16(port)); err == nil {
						grants++
					}
				} else { // exact ip:port grant
					ip := net.ParseIP(host)
					if ip == nil {
						log.Printf("okredo: profile %q has bad ip %q", name, entry)
						continue
					}
					if err := ebpfLoader.AddEgressAllow(id, ip, uint16(port)); err == nil {
						grants++
					}
				}
			}
		}
		log.Printf("okredo: %d profile(s), %d egress grant(s) loaded — identity-scoped authorization active", len(okredoProfiles), grants)
		// Reap agent_policy entries for dead pids (bounds the map; the exit hook
		// can't safely clean it due to Go's exec-from-worker-thread leader swap).
		go func() {
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					ebpfLoader.ReapDeadPolicies()
				}
			}
		}()
	}

	// R12 exfil/C2 watch — honest active/inactive log. Its only source is R11's
	// kernel connect stream, so it is truly active only when egress_jail is
	// enabled AND the BPF-LSM loader actually attached on this host.
	if cfg.ExfilWatch.Enabled {
		ew := config.NormalizeExfilWatch(cfg.ExfilWatch)
		switch {
		case !cfg.EgressJail.Enabled:
			log.Printf("exfil_watch: configured but INACTIVE — needs egress_jail enabled (R12 reads R11's connect stream)")
		case ebpfLoader == nil:
			log.Printf("exfil_watch: configured but INACTIVE — egress_jail enabled but kernel BPF-LSM unavailable, no connect stream")
		default:
			log.Printf("exfil_watch: R12 active · beacon≥%d/jitter<%.0f%% · velocity>%d/%ds (alert-only)",
				ew.BeaconMinCount, ew.BeaconJitterTolerance*100, ew.VelocityMaxConnects, ew.VelocityWindowSeconds)
		}
	}

	// R9 GPU billed-while-broken governor — opt-in via gpu_spend config.
	// MinDownSeconds is wired from the same grace the watcher normalizes (default
	// 300) so the rule gate and the watcher's emit threshold stay in lockstep.
	if cfg.GPUSpend.Enabled {
		grace := cfg.GPUSpend.GraceSeconds
		if grace <= 0 {
			grace = 300
		}
		engine.Register(rules.NewR9(int64(grace)))
		gpuwatch.Start(ctx, cfg.GPUSpend, engine, db.InsertEvent, log.Default())
		log.Printf("gpu_spend: R9 watcher started · %d checks · $%.2f/hr",
			len(cfg.GPUSpend.Checks), cfg.GPUSpend.HourlyUSD)
	}

	// R10 route-around detector — opt-in via route_around config. Warn-only.
	var routeAgg *routewatch.Aggregator
	if cfg.RouteAround.Enabled {
		ra := config.NormalizeRouteAround(cfg.RouteAround)
		engine.Register(rules.NewR10(ra.Gateway.Host, ra.Gateway.Port, ra.Providers, ra.ExcludeProc, ra.EstCostPerCall))
		routeAgg = routewatch.New(ra.SoftCap.WindowSeconds, ra.SoftCap.BudgetUSD, db.InsertEvent, time.Now, log.Default())
		log.Printf("route_around: R10 detector started · gateway %s:%d · %d providers · soft-cap $%.2f/%ds",
			ra.Gateway.Host, ra.Gateway.Port, len(ra.Providers), ra.SoftCap.BudgetUSD, ra.SoftCap.WindowSeconds)
	}

	// R22 supply-chain pins + R23 canaries — persisted state is armed into the kernel
	// maps at boot; the integrity sweep runs only when pins are enabled. Both are
	// opt-in and fail-open (no BPF => alert-only via the sweep, nothing denied).
	// R21 Rule of Two — classify untrusted/private sets + per-profile mode (opt-in per profile).
	r2 := armRuleOfTwo(cfg, ebpfLoader, okredoProfiles)

	pinSvc := newPinService(cfg, db, ebpfLoader, okularLedger, insert)
	if cfg.Pins.Enabled || cfg.Canary.Enabled {
		np, nq, nc := pinSvc.Arm()
		log.Printf("pins: armed · %d pinned · %d quarantined · %d canaries (mode %s) · enforce=%v kernel=%v",
			np, nq, nc, cfg.Canary.Mode, cfg.Pins.Enforce, ebpfLoader != nil)
	}
	if cfg.Pins.Enabled {
		go pinSvc.RunSweeper(ctx)
	}

	// Okredo Attest — kernel-attested agent identity (JWT-SVID-shaped, signed with the
	// Okular key). The posture inside every token is computed by the same code path as
	// `oknek doctor`, so a token can never claim more than doctor would print.
	doctorSnap := func() map[string]interface{} {
		v, _ := doctorHandler(cfg, hs, ebpfLoader, pinSvc, r2)(context.Background(), &ipc.Request{})
		m, _ := v.(map[string]interface{})
		return m
	}
	idSvc := newIdentityService(cfg, db, ebpfLoader, okularLedger, okredoProfiles, doctorSnap)
	mcpSvc := newMCPService(cfg, ebpfLoader, okredoProfiles)
	if cfg.MCP.Enabled {
		mcpRelabel = mcpSvc.Relabel
		mcpObserve = mcpSvc.Observe
		ebpfLoader.SetExecObserver(mcpSvc.OnExec)
	}
	if cfg.Identity.Enabled && okularLedger != nil {
		go idSvc.RunPusher(ctx)
	}

	srv.Handle("version", versionHandler)
	srv.Handle("status", statusHandler(cfg, db, engine, hs))
	srv.Handle("ping", pingHandler)
	srv.Handle("rules.list", rulesListHandler(engine))
	srv.Handle("check.exec", checkExecHandler(engine, db, poster))
	srv.Handle("check.filechange", checkFileChangeHandler(engine))
	srv.Handle("check.fileopen", checkFileOpenHandler(engine, db, poster, pinSvc, ebpfLoader != nil))
	srv.Handle("check.mcp", checkMCPHandler(engine))
	srv.Handle("check.socket", checkSocketHandler(engine, db, routeAgg, poster, ebpfLoader != nil, mcpObserve))
	srv.Handle("routes", routesHandler(routeAgg))
	srv.Handle("egress", egressHandler(cfg, db))
	srv.Handle("exfil", exfilHandler(cfg, db, ebpfLoader != nil))
	srv.Handle("doctor", doctorHandler(cfg, hs, ebpfLoader, pinSvc, r2))
	srv.Handle("pin.set", pinSetHandler(pinSvc))
	srv.Handle("taint.show", taintShowHandler(cfg, ebpfLoader, db))
	srv.Handle("taint.clear", taintClearHandler(ebpfLoader, okularLedger, idSvc))
	srv.Handle("identity.issue", identityIssueHandler(idSvc))
	srv.Handle("identity.pubkey", identityPubkeyHandler(idSvc))
	srv.Handle("mcp.status", mcpStatusHandler(mcpSvc))
	srv.Handle("pin.accept", pinAcceptHandler(pinSvc))
	srv.Handle("pin.status", pinStatusHandler(pinSvc))
	srv.Handle("canary.plant", canaryPlantHandler(pinSvc))
	srv.Handle("canary.status", pinStatusHandler(pinSvc))
	srv.Handle("canary.remove", canaryRemoveHandler(pinSvc))
	srv.Handle("okredo", okredoHandler(cfg, ebpfLoader != nil))
	srv.Handle("okular", okularStatusHandler(cfg, okularLedger))
	srv.Handle("okular.replay", okularReplayHandler(okularLedger))
	srv.Handle("okular.export", okularExportHandler(okularLedger))
	srv.Handle("okular.anchors", okularAnchorsHandler(okularLedger))
	srv.Handle("okular.anchor.now", okularAnchorNowHandler(okularLedger))
	srv.Handle("okular.verify-remote", okularVerifyRemoteHandler(cfg, okularLedger))
	srv.Handle("attest", attestHandler(cfg, okularLedger))
	srv.Handle("disarm", disarmHandler(cfg, okularLedger))
	srv.Handle("check.scan", checkScanHandler(engine))
	srv.Handle("check.drift", checkDriftHandler(engine, db))
	srv.Handle("hook.attach", hookAttachHandler(hs, ebpfLoader, okredoProfiles, idSvc, mcpSvc))
	srv.Handle("baseline.observe", baselineObserveHandler(db))
	srv.Handle("baseline.size", baselineSizeHandler(db))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("oknekd %s listening on %s · db %s", version, cfg.Socket, cfg.DBPath)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ctx) }()

	select {
	case sig := <-sigCh:
		log.Printf("received %s, shutting down", sig)
	case err := <-serveErr:
		if err != nil {
			log.Printf("serve: %v", err)
		}
	}

	cancel()
	if err := srv.Close(); err != nil {
		log.Printf("close server: %v", err)
	}
	log.Println("oknekd stopped")
	return nil
}

func pingHandler(ctx context.Context, req *ipc.Request) (interface{}, error) {
	return map[string]string{"pong": "ok"}, nil
}

func versionHandler(ctx context.Context, req *ipc.Request) (interface{}, error) {
	return map[string]string{
		"version":    version,
		"commit":     commit,
		"build_date": buildDate,
	}, nil
}

func statusHandler(cfg *config.Config, db *store.Store, eng *rules.Engine, hs *hookState) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		events, _ := db.EventCount()
		baselineSize := db.BaselineSize()
		mode, hookAgents := hs.snapshot()
		blocked, _ := db.CountByVerdict("block")
		warned, _ := db.CountByVerdict("warn")
		dbAgents, _ := db.DistinctAgentCount()
		agents := hookAgents
		if dbAgents > agents {
			agents = dbAgents
		}
		routeArounds, _ := db.CountByRule("R10")
		return map[string]interface{}{
			"baseline_size":  baselineSize,
			"version":        version,
			"commit":         commit,
			"build_date":     buildDate,
			"goos":           runtime.GOOS,
			"goarch":         runtime.GOARCH,
			"kernel":         kernelVersion(),
			"hook_mode":      mode,
			"socket":         cfg.Socket,
			"db_path":        cfg.DBPath,
			"db_size_bytes":  db.FileSize(),
			"events":         events,
			"install_id":     db.Meta("install_id"),
			"schema_version": db.Meta("schema_version"),
			"rule_pack":      fmt.Sprintf("v1 · %d rules loaded", eng.Count()),
			"rule_count":     eng.Count(),
			"agents":         agents,
			"blocked":        blocked,
			"alerted":        blocked + warned,
			"route_arounds":  routeArounds,
			"uptime_seconds": int(time.Since(startedAt).Seconds()),
		}, nil
	}
}

func rulesListHandler(eng *rules.Engine) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		return map[string]interface{}{
			"count": eng.Count(),
			"rules": eng.List(),
		}, nil
	}
}

func routesHandler(agg *routewatch.Aggregator) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		return agg.Status(), nil // nil-safe → {"enabled":false}
	}
}

// egressHandler surfaces the R11 kernel egress-jail catches: off-gateway connect
// attempts from watched agents (blocked, or — in observe mode — would-be blocked).
func egressHandler(cfg *config.Config, db *store.Store) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		ej := cfg.EgressJail
		lifetime, _ := db.CountByRule("R11")
		recs, _ := db.EventsByRule("R11", 20)
		attempts := make([]map[string]interface{}, 0, len(recs))
		for _, r := range recs {
			var p struct {
				Dest    string `json:"dest"`
				Process string `json:"process"`
				PID     int    `json:"pid"`
			}
			_ = json.Unmarshal([]byte(r.Payload), &p)
			attempts = append(attempts, map[string]interface{}{
				"ts":      r.TS,
				"agent":   r.AgentID,
				"process": p.Process,
				"dest":    p.Dest,
				"pid":     p.PID,
			})
		}
		gateway := ""
		if ej.Gateway.Host != "" {
			gateway = fmt.Sprintf("%s:%d", ej.Gateway.Host, ej.Gateway.Port)
		}
		return map[string]interface{}{
			"enabled":  ej.Enabled,
			"enforce":  ej.Enforce,
			"gateway":  gateway,
			"lifetime": lifetime,
			"attempts": attempts,
		}, nil
	}
}

// systemResolvers returns the host's DNS resolver IPs (from /etc/resolv.conf).
// With egress_jail enforcing, :53 is allowed only to these (empty = legacy allow-any).
func systemResolvers() []net.IP {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip := net.ParseIP(f[1]); ip != nil {
				out = append(out, ip)
			}
		}
	}
	return out
}

// exfilHandler surfaces R12 exfil/C2 catches (beaconing + velocity), alert-only.
// bpfActive reflects whether the kernel connect stream (R12's only source) is live.
func exfilHandler(cfg *config.Config, db *store.Store, bpfActive bool) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		lifetime, _ := db.CountByRule("R12")
		recs, _ := db.EventsByRule("R12", 20)
		catches := make([]map[string]interface{}, 0, len(recs))
		for _, r := range recs {
			var p rules.ExfilAnomalyPayload
			_ = json.Unmarshal([]byte(r.Payload), &p)
			catches = append(catches, map[string]interface{}{
				"ts":       r.TS,
				"agent":    r.AgentID,
				"pattern":  p.Pattern,
				"dest":     p.Dest,
				"interval": p.IntervalSeconds,
				"jitter":   p.JitterCV,
				"connects": p.ConnectsWindow,
				"process":  p.Process,
			})
		}
		return map[string]interface{}{
			"enabled":  cfg.ExfilWatch.Enabled,
			"active":   cfg.ExfilWatch.Enabled && cfg.EgressJail.Enabled && bpfActive,
			"lifetime": lifetime,
			"catches":  catches,
		}, nil
	}
}

// doctorHandler reports the daemon's TRUE enforcement posture so it can never
// silently claim kernel protection it isn't delivering (red-team Class 6 — honest
// coverage / preflight). A "DEGRADED" verdict means oknek is running userspace-only
// and CANNOT block a static binary; the operator must boot with lsm=...,bpf.
// okularStatusHandler reports the audit ledger head + an on-demand integrity verify.
func okularStatusHandler(cfg *config.Config, l *okular.Ledger) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		if l == nil {
			return map[string]interface{}{"enabled": cfg.Okular.Enabled, "active": false}, nil
		}
		seq, head := l.Head()
		ok, broken, total, err := l.Verify()
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"enabled": true, "active": true,
			"total": total, "head_seq": seq, "head_hash": head,
			"intact": ok, "broken_seq": broken,
		}, nil
	}
}

// ReplayParams is the body of okular.replay.
type ReplayParams struct {
	Agent string `json:"agent"`
	Limit int    `json:"limit"`
}

// okularReplayHandler returns an agent's action timeline from the ledger.
func okularReplayHandler(l *okular.Ledger) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		if l == nil {
			return map[string]interface{}{"enabled": false}, nil
		}
		var p ReplayParams
		if len(req.Params) > 0 {
			_ = json.Unmarshal(req.Params, &p)
		}
		entries, err := l.Timeline(p.Agent, p.Limit)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"enabled": true, "entries": entries}, nil
	}
}

// ExportParams is the body of okular.export.
type ExportParams struct {
	Agent string `json:"agent"`
	Limit int    `json:"limit"`
}

// okularExportHandler returns a sealed, ed25519-signed bundle of an agent's timeline.
func okularExportHandler(l *okular.Ledger) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		if l == nil {
			return map[string]interface{}{"enabled": false}, nil
		}
		var p ExportParams
		if len(req.Params) > 0 {
			_ = json.Unmarshal(req.Params, &p)
		}
		if p.Limit <= 0 {
			p.Limit = 100000
		}
		return l.ExportSigned(p.Agent, p.Limit, time.Now().UnixNano())
	}
}

// okularAnchorsHandler lists the published anchors and verifies the chain + that the
// live ledger still agrees with every checkpoint.
func okularAnchorsHandler(l *okular.Ledger) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		if l == nil {
			return map[string]interface{}{"enabled": false}, nil
		}
		anchors, err := l.Anchors()
		if err != nil {
			return nil, err
		}
		ok, count, reason, err := l.VerifyAnchors()
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"enabled": true, "anchors": anchors, "verified": ok, "count": count, "reason": reason,
		}, nil
	}
}

// okularAnchorNowHandler seals a checkpoint immediately (ops/demo; the daemon also
// anchors on a timer).
func okularAnchorNowHandler(l *okular.Ledger) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		if l == nil {
			return map[string]interface{}{"enabled": false}, nil
		}
		a, err := l.EmitAnchor(time.Now().UnixNano())
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"enabled": true, "anchor": a}, nil
	}
}

// okularVerifyRemoteHandler pulls the immutable off-box WORM escrow and verifies it as
// source-of-truth against the local ledger: chain+sigs, gaps, back-dating, ledger rewrite.
func okularVerifyRemoteHandler(cfg *config.Config, l *okular.Ledger) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		if l == nil || !cfg.Okular.WORM.Enabled {
			return map[string]interface{}{"enabled": false}, nil
		}
		res, err := l.VerifyRemote(5 * time.Minute)
		if err != nil {
			return nil, err
		}
		issues := res.Issues
		if issues == nil {
			issues = []string{}
		}
		return map[string]interface{}{
			"enabled": true, "anchors": res.Anchors, "newest_seq": res.NewestSeq,
			"newest_time": res.NewestTime.Unix(), "ok": res.OK, "issues": issues,
		}, nil
	}
}

// heartbeatAgent/Rule label the R20 attestation beats in the Okular ledger so the
// attest check can isolate them from real agent events.
const (
	heartbeatAgent = "oknek-self"
	heartbeatRule  = "HEARTBEAT"
)

// attestHandler reports liveness-attestation continuity: it pulls the R20 heartbeat
// stream from the Okular ledger and flags any silence longer than the tolerance. A
// gap means enforcement went dark across that window (a disable we couldn't prevent
// in-kernel — reboot, kernel exploit, boot-race) — and because the ledger is
// append-only + anchored, that gap can't be backfilled. Silence is the alarm.
// newDisarmAuthorizer builds the Tier-A disarm Authorizer from config: the off-box pubkey,
// the host binding (hostname), the marker path, and the record-first ledger sink.
func newDisarmAuthorizer(cfg *config.Config, l *okular.Ledger) (*disarm.Authorizer, error) {
	pub, err := hex.DecodeString(strings.TrimSpace(cfg.Disarm.PubKey))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("disarm.pub_key must be %d-byte hex ed25519 (err=%v)", ed25519.PublicKeySize, err)
	}
	host, _ := os.Hostname()
	mp := cfg.Disarm.MarkerPath
	if mp == "" {
		mp = filepath.Join(filepath.Dir(cfg.DBPath), "disarm.marker")
	}
	return disarm.NewAuthorizer(ed25519.PublicKey(pub), host, mp, disarm.LedgerRecorder(l), cfg.Disarm.MaxTokenAgeSeconds), nil
}

// disarmHandler is the RPC behind `oknek disarm request`: verify an off-box-signed token,
// record DISARM-AUTHORIZED record-first (fail-closed), and stage the disarm-on-boot marker.
// A reboot then completes the uninstall — the loader's BootCheck won't re-arm.
func disarmHandler(cfg *config.Config, l *okular.Ledger) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		if !cfg.Disarm.Enabled {
			return map[string]interface{}{"ok": false, "error": "disarm not enabled (set disarm.enabled + disarm.pub_key)"}, nil
		}
		if l == nil {
			return map[string]interface{}{"ok": false, "error": "disarm needs okular.enabled (record-first audit)"}, nil
		}
		var p struct {
			Token disarm.Token `json:"token"`
		}
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, fmt.Errorf("bad disarm params: %w", err)
			}
		}
		az, err := newDisarmAuthorizer(cfg, l)
		if err != nil {
			return map[string]interface{}{"ok": false, "error": err.Error()}, nil
		}
		if err := az.RequestDisarm(p.Token, time.Now().Unix()); err != nil {
			return map[string]interface{}{"ok": false, "error": err.Error()}, nil
		}
		return map[string]interface{}{"ok": true,
			"message": "disarm AUTHORIZED + recorded off-box; marker staged — REBOOT to complete uninstall (loader will not re-arm)"}, nil
	}
}

func attestHandler(cfg *config.Config, l *okular.Ledger) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		if !cfg.SelfGuard.Enabled {
			return map[string]interface{}{"enabled": false}, nil
		}
		if l == nil {
			return map[string]interface{}{
				"enabled": true, "active": false,
				"reason": "attestation needs okular.enabled (the append-only ledger)",
			}, nil
		}
		sg := config.NormalizeSelfGuard(cfg.SelfGuard)
		entries, err := l.Timeline(heartbeatAgent, 100000)
		if err != nil {
			return nil, err
		}
		secs := make([]int64, 0, len(entries))
		enf := make([]bool, 0, len(entries))
		for _, e := range entries {
			secs = append(secs, e.TS/1_000_000_000) // ledger ts is UnixNano -> seconds
			var p struct {
				Enforcing bool `json:"enforcing"`
			}
			_ = json.Unmarshal([]byte(e.Payload), &p)
			enf = append(enf, p.Enforcing)
		}
		tol := int64(sg.HeartbeatSeconds * sg.GapMultiple)
		r := attest.Check(secs, tol)
		er := attest.ScanEnforcing(enf) // a beat that arrives but reports enforce=off is its own alarm
		// TERMINAL silence: Check() only sees gaps BETWEEN recorded beats. A stream that
		// stopped (reboot dropped the bpf LSM, daemon answering from stale beats; or the
		// heartbeat goroutine never started) reads "continuous" to Check but is dead. Flag
		// it by comparing the newest beat to now. No beats while enabled = also silence.
		hasBeats, silentFor := attest.SinceNewest(secs, time.Now().Unix())
		live := hasBeats && silentFor <= tol
		return map[string]interface{}{
			"enabled": true, "active": true,
			"heartbeats": r.Beats, "continuous": r.Continuous,
			"tolerance_seconds": tol, "gaps": r.Gaps,
			"all_enforcing": er.AllEnforcing, "disabled_beats": er.DisabledBeats,
			"live": live, "silent_for_seconds": silentFor,
		}, nil
	}
}

// okredoHandler surfaces the Okredo (IAM) state: configured agent profiles and the
// per-identity egress grants the kernel enforces.
func okredoHandler(cfg *config.Config, bpfActive bool) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		names := make([]string, 0, len(cfg.Okredo.Profiles))
		for n := range cfg.Okredo.Profiles {
			names = append(names, n)
		}
		sort.Strings(names)
		profiles := make([]map[string]interface{}, 0, len(names))
		for i, n := range names {
			grants := cfg.Okredo.Profiles[n].AllowEgress
			if grants == nil {
				grants = []string{}
			}
			profiles = append(profiles, map[string]interface{}{
				"name": n, "policy_id": i + 1, "grants": grants,
			})
		}
		return map[string]interface{}{
			"enabled":  cfg.Okredo.Enabled,
			"active":   cfg.Okredo.Enabled && cfg.EgressJail.Enabled && bpfActive,
			"profiles": profiles,
		}, nil
	}
}

func doctorHandler(cfg *config.Config, hs *hookState, loader *ebpf.Loader, pinSvc *pinService, r2 r2Summary) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		pinned, quarantined, canaries := 0, 0, 0
		if pinSvc != nil {
			st := pinSvc.Status()
			pinned, _ = st["pinned"].(int)
			quarantined, _ = st["quarantined"].(int)
			if cs, ok := st["canaries"].([]store.Canary); ok {
				canaries = len(cs)
			}
		}
		mode, _ := hs.snapshot()
		if loader != nil {
			mode = "ebpf" // kernel path attached = the truth, whatever the last shim registration said
		}
		avail := ebpf.Available()
		pins := bpffsPins()
		contd := containerized()
		bpfAttached := loader != nil

		// R20 anti-unpin: the core enforcing set is 11 pins; self_guard adds 3
		// (inode_unlink/inode_rename/sb_umount) when enabled = 14 total expected.
		// 0.9: all 14 links are pinned (11 enforcing + 3 R20 anti-unpin hooks, which
		// attach always and enforce only once self_guard arms them).
		expected := 14
		sgInit, sgEnf := false, false
		if loader != nil {
			sgInit, sgEnf = loader.SelfGuardArmed()
		}

		warnings := []string{}
		verdict := "KERNEL-ENFORCED"
		switch {
		case !avail:
			verdict = "DEGRADED"
			warnings = append(warnings, "kernel BPF-LSM not in the active LSM list — enforcement is NOT live; boot with lsm=...,bpf. Until then oknek runs userspace-only and cannot block a static binary.")
		case !bpfAttached:
			verdict = "DEGRADED"
			warnings = append(warnings, "BPF-LSM is available but the programs are not attached — running userspace-only.")
		case cfg.EgressJail.Enabled && !cfg.EgressJail.Enforce:
			verdict = "OBSERVE"
			warnings = append(warnings, "egress jail is in observe mode — set egress_jail.enforce: true to block at the kernel.")
		}
		if avail && bpfAttached && len(pins) < expected {
			warnings = append(warnings, fmt.Sprintf("only %d/%d BPF links pinned to bpffs — enforcement may not survive a daemon kill.", len(pins), expected))
		}
		if cfg.SelfGuard.Enabled && bpfAttached && !sgInit {
			warnings = append(warnings, "self_guard is enabled but R20 is not armed (self_id not written) — anti-unpin is fail-OPEN; root can still rm the pins.")
		}
		if cfg.SelfGuard.Enabled && sgInit && !sgEnf {
			warnings = append(warnings, "self_guard (R20 anti-unpin) is in observe mode — set self_guard.enforce: true to deny pin removal.")
		}
		if quarantined > 0 {
			warnings = append(warnings, fmt.Sprintf("%d pinned artifact(s) TAMPERED and quarantined — review with `oknek pin status`, re-pin with `oknek pin --accept`.", quarantined))
		}
		if contd {
			warnings = append(warnings, "daemon is running inside a container — it sees only its own PID namespace; agents in other namespaces are NOT covered. Run on the host PID namespace.")
		}
		return map[string]interface{}{
			"verdict":             verdict,
			"bpf_lsm_available":   avail,
			"hook_mode":           mode,
			"pins":                pins,
			"pins_expected":       expected,
			"egress_enabled":      cfg.EgressJail.Enabled,
			"egress_enforce":      cfg.EgressJail.Enforce,
			"exfil_enabled":       cfg.ExfilWatch.Enabled,
			"protected_files":     len(cfg.ProtectedFiles),
			"pinned_artifacts":    pinned,
			"quarantined":         quarantined,
			"canaries":            canaries,
			"pins_enforce":        cfg.Pins.Enabled && cfg.Pins.Enforce,
			"rule_of_two_enforce": r2.Enforce,
			"rule_of_two_observe": r2.Observe,
			"rule_of_two_sets":    r2.Files + r2.Dirs,
			"self_guard_enabled":  cfg.SelfGuard.Enabled,
			"self_guard_armed":    sgInit,
			"self_guard_enforce":  sgEnf,
			"containerized":       contd,
			"pid_ns":              pidNS(),
			"kernel":              kernelVersion(),
			"warnings":            warnings,
		}, nil
	}
}

// bpffsPins lists which oknek BPF links are pinned to bpffs (enforcement that
// survives a daemon SIGKILL). Matches the names pinned in ebpf.Start.
func bpffsPins() []string {
	want := []string{"file_open", "socket_connect", "sendmsg", "ptrace", "exec", "bind", "bpf", "kmod", "mount", "inode_unlink", "inode_rename", "sb_umount", "fork", "exit"}
	out := []string{}
	dir := ebpf.PinDir()
	for _, n := range want {
		if _, err := os.Stat(dir + "/" + n); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// containerized reports whether oknekd is running inside a container (where its
// PID-namespace view would not cover agents on the host or in sibling namespaces).
func containerized() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		for _, m := range []string{"docker", "lxc", "kubepods", "containerd", "libpod"} {
			if strings.Contains(s, m) {
				return true
			}
		}
	}
	return false
}

// pidNS returns the daemon's PID-namespace identifier (e.g. "pid:[4026531836]").
func pidNS() string {
	if l, err := os.Readlink("/proc/self/ns/pid"); err == nil {
		return l
	}
	return "unknown"
}

// CheckExecParams is the request body for the check.exec RPC.
type CheckExecParams struct {
	Command string `json:"command"`
	AgentID string `json:"agent_id,omitempty"`
}

// CheckFileChangeParams is the body of check.filechange.
type CheckFileChangeParams struct {
	Path    string `json:"path"`
	Op      string `json:"op"` // "create" | "modify" | "delete"
	NewHash string `json:"new_hash,omitempty"`
	OldHash string `json:"old_hash,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
}

func checkFileChangeHandler(eng *rules.Engine) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		var p CheckFileChangeParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, fmt.Errorf("decode params: %w", err)
			}
		}
		op := rules.FileOp(p.Op)
		if op == "" {
			op = rules.FileOpModify
		}
		ev := rules.Event{
			Kind:      rules.KindFileChanged,
			AgentID:   p.AgentID,
			Timestamp: time.Now().UnixNano(),
			Payload: rules.FileChangePayload{
				Path:    p.Path,
				Op:      op,
				OldHash: p.OldHash,
				NewHash: p.NewHash,
			},
		}
		return checkResponse(p.Path, eng.Evaluate(ctx, ev), eng.Count()), nil
	}
}

// CheckFileOpenParams is the body of check.fileopen.
type CheckFileOpenParams struct {
	Path    string `json:"path"`
	Mode    string `json:"mode,omitempty"`    // "read" | "write" | "readwrite"
	Process string `json:"process,omitempty"` // process name that opened it
	AgentID string `json:"agent_id,omitempty"`
}

func checkFileOpenHandler(eng *rules.Engine, db *store.Store, poster *feed.Poster, pinSvc *pinService, kernelAttached bool) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		var p CheckFileOpenParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, fmt.Errorf("decode params: %w", err)
			}
		}
		if p.Mode == "" {
			p.Mode = "read"
		}
		if p.Process == "" {
			p.Process = "claude"
		}
		// R23: a planted decoy must never be answered by R3's credential-name block
		// (that would pre-empt the kernel canary hook). Alert mode allows; block denies.
		if pinSvc != nil {
			if _, ok := pinSvc.IsCanary(p.Path); ok {
				m := []rules.Match{}
				if pinSvc.CanaryTouched(p.AgentID, p.Process, p.Path, kernelAttached) {
					m = append(m, rules.Match{RuleID: "R23", Name: "canary", Verdict: rules.VerdictBlock,
						Evidence: map[string]interface{}{"path": p.Path, "severity": "critical", "mode": "block"}})
				}
				return checkResponse(p.Path, m, eng.Count()), nil
			}
		}
		ev := rules.Event{
			Kind:      rules.KindFileOpened,
			AgentID:   p.AgentID,
			Timestamp: time.Now().UnixNano(),
			Payload: rules.FileOpenPayload{
				Path:    p.Path,
				Mode:    p.Mode,
				Process: p.Process,
			},
		}
		matches := eng.Evaluate(ctx, ev)
		logMatches(db, poster, ev, matches)
		return checkResponse(p.Path, matches, eng.Count()), nil
	}
}

// checkResponse builds a consistent JSON shape for all check.* handlers.
func checkResponse(input string, matches []rules.Match, total int) map[string]interface{} {
	out := []map[string]interface{}{}
	for _, m := range matches {
		out = append(out, map[string]interface{}{
			"rule_id":  m.RuleID,
			"name":     m.Name,
			"verdict":  m.Verdict.String(),
			"evidence": m.Evidence,
		})
	}
	return map[string]interface{}{
		"input":     input,
		"matched":   len(matches) > 0,
		"matches":   out,
		"evaluated": total,
	}
}

// ─── R7: behavioral drift glue ──────────────────────────────

// storeBaselineAdapter wires *store.Store to the rules.BaselineScorer interface.
type storeBaselineAdapter struct {
	db *store.Store
}

func (a *storeBaselineAdapter) Score(agentID string, features []string) (float64, []string, error) {
	return a.db.BaselineScore(agentID, features)
}
func (a *storeBaselineAdapter) Observe(agentID, feature string) error {
	return a.db.ObserveBaseline(agentID, feature)
}

type CheckDriftParams struct {
	AgentID  string   `json:"agent_id"`
	Features []string `json:"features"`
}

func checkDriftHandler(eng *rules.Engine, db *store.Store) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		var p CheckDriftParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, fmt.Errorf("decode params: %w", err)
			}
		}
		ev := rules.Event{
			Kind:      rules.KindBaselineDrift,
			AgentID:   p.AgentID,
			Timestamp: time.Now().UnixNano(),
			Payload:   rules.BaselineDriftPayload{Features: p.Features},
		}
		display := fmt.Sprintf("%s · %v", p.AgentID, p.Features)
		return checkResponse(display, eng.Evaluate(ctx, ev), eng.Count()), nil
	}
}

type BaselineObserveParams struct {
	AgentID  string   `json:"agent_id"`
	Features []string `json:"features"`
}

func baselineObserveHandler(db *store.Store) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		var p BaselineObserveParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, fmt.Errorf("decode params: %w", err)
			}
		}
		for _, f := range p.Features {
			if err := db.ObserveBaseline(p.AgentID, f); err != nil {
				return nil, err
			}
		}
		return map[string]interface{}{
			"observed":      len(p.Features),
			"agent_id":      p.AgentID,
			"baseline_size": db.BaselineSize(),
		}, nil
	}
}

func baselineSizeHandler(db *store.Store) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		return map[string]interface{}{"baseline_size": db.BaselineSize()}, nil
	}
}

// ─── R4: MCP endpoint check ─────────────────────────────────

type CheckMCPParams struct {
	ServerName string `json:"server_name,omitempty"`
	Transport  string `json:"transport"` // "stdio" | "http" | "sse"
	Command    string `json:"command,omitempty"`
	URL        string `json:"url,omitempty"`
	AgentID    string `json:"agent_id,omitempty"`
}

func checkMCPHandler(eng *rules.Engine) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		var p CheckMCPParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, fmt.Errorf("decode params: %w", err)
			}
		}
		ev := rules.Event{
			Kind:      rules.KindMCPEndpoint,
			AgentID:   p.AgentID,
			Timestamp: time.Now().UnixNano(),
			Payload: rules.MCPEndpointPayload{
				ServerName: p.ServerName,
				Transport:  p.Transport,
				Command:    p.Command,
				URL:        p.URL,
			},
		}
		display := p.Transport + " · " + p.Command + p.URL
		return checkResponse(display, eng.Evaluate(ctx, ev), eng.Count()), nil
	}
}

// ─── R5: outbound socket check ──────────────────────────────

type CheckSocketParams struct {
	DestHost string `json:"dest_host"`
	DestPort int    `json:"dest_port,omitempty"`
	Process  string `json:"process,omitempty"`
	PID      int    `json:"pid,omitempty"`
	PPID     int    `json:"ppid,omitempty"`
	AgentID  string `json:"agent_id,omitempty"`
}

func checkSocketHandler(eng *rules.Engine, db *store.Store, agg *routewatch.Aggregator, poster *feed.Poster, kernelAttached bool, observe ebpf.ConnectObserver) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		var p CheckSocketParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, fmt.Errorf("decode params: %w", err)
			}
		}
		if p.Process == "" {
			p.Process = "claude"
		}
		if p.DestPort == 0 {
			p.DestPort = 443
		}
		ev := rules.Event{
			Kind:      rules.KindSocketConnect,
			AgentID:   p.AgentID,
			PID:       p.PID,
			PPID:      p.PPID,
			Timestamp: time.Now().UnixNano(),
			Payload: rules.SocketConnectPayload{
				DestHost: p.DestHost,
				DestPort: p.DestPort,
				Process:  p.Process,
			},
		}
		display := fmt.Sprintf("%s:%d", p.DestHost, p.DestPort)
		matches := eng.Evaluate(ctx, ev)
		// R24 observe: the shim sees every connect (allowed ones too, which the kernel
		// never reports) — feed it to the MCP observer so "what did this server reach"
		// has evidence even when nothing is blocked.
		// Prefer the kernel-verified peer pid (SO_PEERCRED) over the shim's self-report.
		if observe != nil {
			pid := p.PID
			if peer, ok := ipc.PeerPIDFromContext(ctx); ok && peer > 0 {
				pid = peer
			}
			if ip := net.ParseIP(p.DestHost); ip != nil && pid > 0 {
				observe(p.AgentID, p.Process, pid, ip.String(), uint16(p.DestPort), ev.Timestamp)
			}
		}
		// With BPF-LSM attached the KERNEL is the egress authority (R11 jail + Okredo
		// identity grants + R21). The userspace R5 allowlist cannot see identity
		// grants, so its block would pre-empt a connect the kernel is authorized to
		// allow. Downgrade to warn: the shim reports, the kernel decides.
		if kernelAttached {
			for i := range matches {
				if matches[i].Verdict == rules.VerdictBlock {
					matches[i].Verdict = rules.VerdictWarn
					if matches[i].Evidence == nil {
						matches[i].Evidence = map[string]interface{}{}
					}
					matches[i].Evidence["downgraded"] = "kernel BPF-LSM is the egress authority (R11/Okredo/R21)"
				}
			}
		}
		logMatches(db, poster, ev, matches)
		recordRouteArounds(agg, matches)
		return checkResponse(display, matches, eng.Count()), nil
	}
}

// recordRouteArounds feeds R10 matches into the route-around aggregator.
func recordRouteArounds(agg *routewatch.Aggregator, matches []rules.Match) {
	if agg == nil {
		return
	}
	for _, m := range matches {
		if m.RuleID != "R10" {
			continue
		}
		provider, _ := m.Evidence["provider"].(string)
		process, _ := m.Evidence["process"].(string)
		pid, _ := m.Evidence["pid"].(int)
		cost, _ := m.Evidence["est_cost_usd"].(float64)
		agg.Record(provider, process, pid, cost)
	}
}

// ─── R6: instruction-file scan check ────────────────────────

type CheckScanParams struct {
	Path    string `json:"path"`
	Content string `json:"content"` // base64-encoded payload to bypass JSON escaping headaches
	AgentID string `json:"agent_id,omitempty"`
}

func checkScanHandler(eng *rules.Engine) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		var p CheckScanParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, fmt.Errorf("decode params: %w", err)
			}
		}
		// Content arrives base64-encoded to avoid corrupting JSON for binary input.
		decoded, err := base64.StdEncoding.DecodeString(p.Content)
		if err != nil {
			// fall back to treating the field as raw bytes (CLI may have sent plain text)
			decoded = []byte(p.Content)
		}
		ev := rules.Event{
			Kind:      rules.KindFileScanned,
			AgentID:   p.AgentID,
			Timestamp: time.Now().UnixNano(),
			Payload: rules.FileScanPayload{
				Path:    p.Path,
				Content: decoded,
			},
		}
		return checkResponse(p.Path, eng.Evaluate(ctx, ev), eng.Count()), nil
	}
}

func checkExecHandler(eng *rules.Engine, db *store.Store, poster *feed.Poster) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		var p CheckExecParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, fmt.Errorf("decode params: %w", err)
			}
		}
		ev := rules.Event{
			Kind:      rules.KindExecObserved,
			AgentID:   p.AgentID,
			Timestamp: time.Now().UnixNano(),
			Payload:   rules.ExecPayload{Command: p.Command},
		}
		matches := eng.Evaluate(ctx, ev)
		logMatches(db, poster, ev, matches)
		return checkResponse(p.Command, matches, eng.Count()), nil
	}
}

func kernelVersion() string {
	if runtime.GOOS != "linux" {
		return fmt.Sprintf("%s/%s (no kernel)", runtime.GOOS, runtime.GOARCH)
	}
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	s := string(data)
	if n := len(s); n > 0 && s[n-1] == '\n' {
		s = s[:n-1]
	}
	return s
}

// okularPolicySealer adapts the Okular ledger to configpull.Sealer. Each applied
// config change is recorded record-first and fail-closed via EmitPolicy: a host
// observe→enforce flip is the loud POLICY-ENFORCE event, everything else POLICY-SET.
// A non-nil error means "not durably sealed" and the puller will NOT apply/ack.
type okularPolicySealer struct{ l *okular.Ledger }

func (s okularPolicySealer) Seal(name string, version int, enforce bool) (string, error) {
	kind := okular.EvPolicySet
	mode := "set"
	if enforce {
		kind = okular.EvPolicyEnforce
		mode = "enforce"
	}
	a, err := s.l.EmitPolicy(time.Now().UnixNano(), kind, name, version, mode)
	if err != nil {
		return "", err
	}
	if a != nil {
		return fmt.Sprintf("okular anchor#%d seq=%d %s", a.Seq, a.HeadSeq, safePrefix(a.Hash, 12)), nil
	}
	return fmt.Sprintf("okular %s v%d", mode, version), nil
}

func safePrefix(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[:n]
}
