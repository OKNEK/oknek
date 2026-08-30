package policy

import (
	"fmt"
	"net"
	"strings"
)

// Compiled is the intermediate representation a policy resolves to — the structures the BPF
// maps consume (exec allowlist, file prefix rules, egress CIDR/port + resolvers, caps
// bitmask, the enforce bit). Loading these into the kernel maps is a separate, box-side step;
// Compile is the pure-Go resolution + validation, fully unit-testable.
type Compiled struct {
	Name       string
	Version    int
	Enforce    bool // mode == "enforce" (else observe)
	Exec       []string
	FileRead   []string
	FileWrite  []string
	FileDeny   []string
	Egress     []CompiledNet // allowlist
	EgressDeny []CompiledNet
	Resolvers  []string // approved DNS resolver IPs
	CapsDeny   uint64   // bitmask of denied capabilities (see capBits)
}

// CompiledNet is a validated egress allow/deny entry (CIDR and/or port).
type CompiledNet struct {
	CIDR string
	Port int
}

// capBits maps capability/syscall names to a stable bit. Adding a name here is the only place
// the kernel-side bitmask and the policy vocabulary must agree.
var capBits = map[string]uint64{
	"ptrace":     1 << 0,
	"bpf":        1 << 1,
	"kmod":       1 << 2,
	"mount":      1 << 3,
	"raw_socket": 1 << 4,
	"bind":       1 << 5,
}

// Compile resolves + validates a parsed policy into its IR. It errors on things that cannot
// become kernel rules: a non-absolute exec path, an invalid CIDR/resolver IP, an out-of-range
// port, or an unknown capability name. (Lint covers SAFETY; Compile covers REALIZABILITY.)
func Compile(p *AgentPolicy) (*Compiled, error) {
	if p == nil {
		return nil, fmt.Errorf("nil policy")
	}
	c := &Compiled{
		Name: p.Metadata.Name, Version: p.Metadata.Version, Enforce: p.Mode == "enforce",
		FileRead: p.Allow.Files.Read, FileWrite: p.Allow.Files.Write, FileDeny: p.Allow.Files.Deny,
	}
	for _, e := range p.Allow.Exec {
		if !strings.HasPrefix(e, "/") {
			return nil, fmt.Errorf("exec entry %q must be an absolute path", e)
		}
		c.Exec = append(c.Exec, e)
	}
	var err error
	if c.Egress, c.Resolvers, err = compileEgress(p.Allow.Network.Egress); err != nil {
		return nil, err
	}
	if c.EgressDeny, _, err = compileEgress(p.Allow.Network.Deny); err != nil {
		return nil, err
	}
	for _, cap := range p.Allow.Caps.Deny {
		bit, ok := capBits[cap]
		if !ok {
			return nil, fmt.Errorf("unknown capability %q (known: ptrace bpf kmod mount raw_socket bind)", cap)
		}
		c.CapsDeny |= bit
	}
	return c, nil
}

// compileEgress validates a list of egress rules, splitting out resolvers from CIDR/port nets.
func compileEgress(rules []EgressRule) ([]CompiledNet, []string, error) {
	var nets []CompiledNet
	var resolvers []string
	for _, r := range rules {
		if r.Resolver != "" {
			if net.ParseIP(r.Resolver) == nil {
				return nil, nil, fmt.Errorf("resolver %q is not a valid IP", r.Resolver)
			}
			resolvers = append(resolvers, r.Resolver)
			continue
		}
		if r.CIDR != "" {
			if _, _, e := net.ParseCIDR(r.CIDR); e != nil {
				return nil, nil, fmt.Errorf("invalid cidr %q: %v", r.CIDR, e)
			}
		}
		if r.Port < 0 || r.Port > 65535 {
			return nil, nil, fmt.Errorf("port %d out of range (0-65535)", r.Port)
		}
		if r.CIDR != "" || r.Port != 0 {
			nets = append(nets, CompiledNet{CIDR: r.CIDR, Port: r.Port})
		}
	}
	return nets, resolvers, nil
}
