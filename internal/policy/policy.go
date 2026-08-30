// Package policy is the customer-facing authoring layer (Tier-0 #2): a declarative,
// default-deny AgentPolicy document a customer can write and lint, instead of the owner
// hand-editing kernel rules. This file is the schema + parser; lint.go validates (incl. the
// brick-the-box guard); the compiler (-> BPF map entries) is a separate, later step.
package policy

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// AgentPolicy is a default-deny policy for one agent class/workload.
type AgentPolicy struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Selector   Selector `yaml:"selector"`
	Mode       string   `yaml:"mode"`    // observe | enforce (per-policy)
	Default    string   `yaml:"default"` // deny (the supported spine)
	Allow      Allow    `yaml:"allow"`
	Audit      string   `yaml:"audit"` // full | blocks-only
}

// Metadata names + versions the policy (version bumps on every change; recorded to the audit).
type Metadata struct {
	Name    string `yaml:"name"`
	Version int    `yaml:"version"`
}

// Selector binds a running process to this policy, strongest identity first (see Lint).
type Selector struct {
	AgentID        string `yaml:"agentId"`        // Okredo identity (preferred)
	Cgroup         string `yaml:"cgroup"`         // cgroup path / id
	ContainerImage string `yaml:"containerImage"` // container image ref
	ExePath        string `yaml:"exePath"`        // binary path (+ ancestry, enforced elsewhere)
	EnvLabel       string `yaml:"envLabel"`       // weakest; advisory only
}

// strong reports whether the selector has a non-spoofable binder (anything but envLabel).
func (s Selector) strong() bool {
	return s.AgentID != "" || s.Cgroup != "" || s.ContainerImage != "" || s.ExePath != ""
}

// empty reports whether NO selector field is set (would match host-wide).
func (s Selector) empty() bool {
	return !s.strong() && s.EnvLabel == ""
}

// Allow is the explicit allowlist across the enforcement domains (default-deny otherwise).
type Allow struct {
	Exec    []string     `yaml:"exec"`
	Files   FileRules    `yaml:"files"`
	Network NetworkRules `yaml:"network"`
	Caps    CapRules     `yaml:"caps"`
}

// FileRules: read/write allow prefixes + explicit deny (deny-wins, even inside an allow).
type FileRules struct {
	Read  []string `yaml:"read"`
	Write []string `yaml:"write"`
	Deny  []string `yaml:"deny"`
}

// NetworkRules: egress allowlist + explicit deny (R11 egress jail).
type NetworkRules struct {
	Egress []EgressRule `yaml:"egress"`
	Deny   []EgressRule `yaml:"deny"`
}

// EgressRule is one egress entry. A `resolver` marks the one allowed DNS resolver.
type EgressRule struct {
	CIDR     string `yaml:"cidr"`
	Port     int    `yaml:"port"`
	Resolver string `yaml:"resolver"`
	Domain   string `yaml:"domain"` // v2 (DNS-aware); flagged by lint as not-yet-enforced
}

// CapRules denies capabilities/syscalls (ptrace/bpf/kmod/mount/raw_socket).
type CapRules struct {
	Deny []string `yaml:"deny"`
}

// Parse unmarshals an AgentPolicy from YAML. It does not validate — call Lint for that.
func Parse(b []byte) (*AgentPolicy, error) {
	var p AgentPolicy
	if err := yaml.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	return &p, nil
}
