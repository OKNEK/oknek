package main

// R24 MCP server jail — daemon half. When an agent session starts, read its MCP
// manifests; give every stdio server its own Okredo identity (`mcp:<name>`) with
// the operator-declared grants; when the kernel reports an exec, match the process
// against the manifest and bind it. An R11 block from a bound server is relabelled
// R24 with the server's name. In observe mode nothing is bound — the daemon records
// what each server actually reaches ("declared vs observed").

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oknek/oknek/internal/config"
	"github.com/oknek/oknek/internal/hooks/ebpf"
	"github.com/oknek/oknek/internal/ipc"
	"github.com/oknek/oknek/internal/mcp"
)

type mcpServer struct {
	mcp.Server
	Agent    string           `json:"agent"`
	PolicyID uint16           `json:"policy_id"` // 0 = not jailed (remote, or observe mode)
	Grants   []string         `json:"grants"`
	Pids     map[uint32]int64 `json:"pids"`     // live pids -> first seen (unix ns)
	Observed map[string]int64 `json:"observed"` // "ip:port" -> last seen (unix ns)
	Blocks   int              `json:"blocks"`
}

type mcpService struct {
	cfg        *config.Config
	loader     *ebpf.Loader
	profiles   map[string]uint16 // Okredo profile name -> id (static)
	nextPolicy uint16
	mu         sync.Mutex
	servers    map[string]*mcpServer // agent + "/" + name
	byPid      map[uint32]*mcpServer
	bound      map[string]bool // server key -> grants already loaded into the kernel
}

func newMCPService(cfg *config.Config, loader *ebpf.Loader, profiles map[string]uint16) *mcpService {
	m := &mcpService{cfg: cfg, loader: loader, profiles: profiles, nextPolicy: uint16(len(profiles)) + 1,
		servers: map[string]*mcpServer{}, byPid: map[uint32]*mcpServer{}, bound: map[string]bool{}}
	if cfg.MCP.Enabled {
		mode := "OBSERVE (record what each server reaches; nothing bound)"
		if cfg.MCP.Enforce {
			mode = "ENFORCE (stdio servers jailed to their grants)"
		}
		log.Printf("mcp: R24 MCP server jail ENABLED · %s · %d server grant list(s) · kernel=%v", mode, len(cfg.MCP.Grants), loader != nil)
	}
	return m
}

func (m *mcpService) enabled() bool { return m != nil && m.cfg.MCP.Enabled }

func procEnv(pid uint32, key string) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return ""
	}
	for _, kv := range strings.Split(string(b), "\x00") {
		if strings.HasPrefix(kv, key+"=") {
			return kv[len(key)+1:]
		}
	}
	return ""
}

// NewSession loads the manifests visible to a freshly registered agent process.
func (m *mcpService) NewSession(pid uint32, agent, profile string) {
	if !m.enabled() || pid == 0 {
		return
	}
	cwd, _ := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	home := procEnv(pid, "HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	servers := mcp.Load(cwd, home)
	if len(servers) == 0 {
		return
	}
	r2 := r2ModeOf(m.cfg.Okredo.Profiles[profile].RuleOfTwo)
	m.mu.Lock()
	defer m.mu.Unlock()
	jailed, remote := 0, 0
	for _, s := range servers {
		key := agent + "/" + s.Name
		ms, ok := m.servers[key]
		if !ok {
			ms = &mcpServer{Server: s, Agent: agent, Pids: map[uint32]int64{}, Observed: map[string]int64{}, Grants: []string{}}
			m.servers[key] = ms
		} else {
			ms.Server = s
		}
		if g, ok := m.cfg.MCP.Grants[s.Name]; ok {
			ms.Grants = g
		}
		if s.Transport != "stdio" {
			remote++
			continue
		}
		if m.cfg.MCP.Enforce && m.loader != nil {
			if ms.PolicyID == 0 {
				ms.PolicyID = m.nextPolicy
				m.nextPolicy++
			}
			if !m.bound[key] {
				n := loadGrants(m.loader, ms.PolicyID, ms.Grants, "mcp:"+s.Name)
				_ = m.loader.SetR2Mode(ms.PolicyID, r2)
				m.bound[key] = true
				log.Printf("mcp: %s/%s jailed as policy %d · %d grant(s) · rule_of_two=%d", agent, s.Name, ms.PolicyID, n, r2)
			}
			jailed++
		}
	}
	log.Printf("mcp: agent %q declares %d MCP server(s) — %d stdio jailed, %d remote (grant their hosts on the agent profile)", agent, len(servers), jailed, remote)
}

// loadGrants parses "ip:port" / "cidr:port" entries into the kernel allowlist for a policy.
func loadGrants(loader *ebpf.Loader, policyID uint16, entries []string, label string) int {
	n := 0
	for _, entry := range entries {
		host, portStr, err := net.SplitHostPort(entry)
		port, perr := strconv.Atoi(portStr)
		if err != nil || perr != nil {
			log.Printf("%s: bad grant %q (want ip:port or cidr:port)", label, entry)
			continue
		}
		if strings.Contains(host, "/") {
			ip, ipnet, cerr := net.ParseCIDR(host)
			ones, bits := 0, 0
			if cerr == nil {
				ones, bits = ipnet.Mask.Size()
			}
			if cerr != nil || bits != 32 || ones == 0 || ones%8 != 0 {
				log.Printf("%s: CIDR %q must be byte-aligned IPv4 (/8,/16,/24,/32)", label, entry)
				continue
			}
			if loader.AddEgressCIDR(policyID, ip.Mask(ipnet.Mask), uint8(ones/8), uint16(port)) == nil {
				n++
			}
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil {
			log.Printf("%s: bad ip %q", label, entry)
			continue
		}
		if loader.AddEgressAllow(policyID, ip, uint16(port)) == nil {
			n++
		}
	}
	return n
}

// OnExec is the kernel exec-observed callback: match the new process against the
// agent's manifest and bind it to its server identity. A child of an already-bound
// server pid belongs to the same server.
func (m *mcpService) OnExec(pid, ppid uint32, agent, name string) {
	if !m.enabled() {
		return
	}
	m.mu.Lock()
	if parent, ok := m.byPid[ppid]; ok {
		m.byPid[pid] = parent
		parent.Pids[pid] = time.Now().UnixNano()
		m.mu.Unlock()
		return
	}
	var candidates []*mcpServer
	for _, s := range m.servers {
		if s.Agent == agent && s.Transport == "stdio" {
			candidates = append(candidates, s)
		}
	}
	m.mu.Unlock()
	if len(candidates) == 0 {
		return
	}
	var argv []string
	for i := 0; i < 3; i++ {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err == nil && len(b) > 0 {
			argv = mcp.ParseCmdline(b)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(argv) == 0 {
		return
	}
	for _, s := range candidates {
		if !mcp.Match(argv, s.Server) {
			continue
		}
		m.mu.Lock()
		s.Pids[pid] = time.Now().UnixNano()
		m.byPid[pid] = s
		m.mu.Unlock()
		if m.cfg.MCP.Enforce && s.PolicyID > 0 {
			_ = m.loader.SetAgentPolicy(pid, s.PolicyID)
			log.Printf("mcp: %s/%s exec'd at pid %d (%s) — bound to policy %d", agent, s.Name, pid, name, s.PolicyID)
		} else {
			log.Printf("mcp: %s/%s exec'd at pid %d (%s) — observing", agent, s.Name, pid, name)
		}
		return
	}
}

// Relabel turns an R11 block from a bound server pid into R24 with the server name.
func (m *mcpService) Relabel(ruleID, payload string) (string, string) {
	if !m.enabled() || ruleID != "R11" {
		return ruleID, payload
	}
	var ev map[string]interface{}
	if json.Unmarshal([]byte(payload), &ev) != nil {
		return ruleID, payload
	}
	pidF, _ := ev["pid"].(float64)
	m.mu.Lock()
	s := m.resolve(uint32(pidF))
	if s != nil {
		s.Blocks++
	}
	m.mu.Unlock()
	if s == nil {
		return ruleID, payload
	}
	ev["rule"] = "mcp-jail"
	ev["server"] = s.Name
	ev["detail"] = fmt.Sprintf("MCP server %q reached a destination outside its declared grants", s.Name)
	b, _ := json.Marshal(ev)
	return "R24", string(b)
}

// ppidOf reads the parent pid from /proc/<pid>/status (0 if unknown).
func ppidOf(pid uint32) uint32 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
			return uint32(n)
		}
	}
	return 0
}

// resolve finds the server a pid belongs to, walking up the parent chain (bounded)
// for pids whose exec event has not been drained yet, and caches the answer.
func (m *mcpService) resolve(pid uint32) *mcpServer {
	if s, ok := m.byPid[pid]; ok {
		return s
	}
	cur := pid
	for i := 0; i < 6 && cur > 1; i++ {
		cur = ppidOf(cur)
		if s, ok := m.byPid[cur]; ok {
			m.byPid[pid] = s
			s.Pids[pid] = time.Now().UnixNano()
			return s
		}
	}
	return nil
}

// Observe records every connect by a known server pid (allowed or not) — from the
// kernel's R11 stream and from the shim's check.socket (which sees allowed ones).
func (m *mcpService) Observe(agent, comm string, pid int, ip string, port uint16, ts int64) {
	if !m.enabled() || pid <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.resolve(uint32(pid)); s != nil {
		s.Observed[fmt.Sprintf("%s:%d", ip, port)] = ts
	}
}

// Status is the mcp.status payload.
func (m *mcpService) Status() map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.servers))
	for k := range m.servers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	list := make([]map[string]interface{}, 0, len(keys))
	for _, k := range keys {
		s := m.servers[k]
		live := 0
		for pid := range s.Pids {
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil {
				live++
			}
		}
		obs := make([]string, 0, len(s.Observed))
		for d := range s.Observed {
			obs = append(obs, d)
		}
		sort.Strings(obs)
		list = append(list, map[string]interface{}{
			"agent": s.Agent, "name": s.Name, "transport": s.Transport, "command": s.Command, "args": s.Args,
			"url": s.URL, "host": s.Host, "source": s.Source, "policy_id": s.PolicyID, "grants": s.Grants,
			"pids_seen": len(s.Pids), "pids_live": live, "observed": obs, "blocks": s.Blocks,
		})
	}
	return map[string]interface{}{"enabled": m.cfg.MCP.Enabled, "enforce": m.cfg.MCP.Enforce, "kernel": m.loader != nil, "servers": list}
}

func mcpStatusHandler(m *mcpService) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		return m.Status(), nil
	}
}
