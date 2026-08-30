package configpull

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// Overlay is the effective, human-approved policy folded from applied diffs. It is
// the honest record of "what has been applied" and is persisted next to the daemon's
// config so it survives restart. The daemon reads its tunables from the base
// oknek.yaml plus this overlay. (A Linux build may additionally hot-apply the fields
// the eBPF loader supports — R11 egress adds — for zero-restart effect; the overlay
// remains the source of truth.)
type Overlay struct {
	EgressAllow  map[string][]string `yaml:"egress_allow"`  // agent -> ["host:port", ...]  (R11)
	R1ChainLimit R1Limits            `yaml:"r1_chain_limit"` // R1 sub-command chain limit
	HostMode     map[string]string   `yaml:"host_mode"`      // host -> "enforce"|"observe"
	R3Exceptions map[string][]string `yaml:"r3_exceptions"`  // agent -> [path, ...]  (R3)
}

// R1Limits carries the default chain limit and per-host overrides.
type R1Limits struct {
	Default int            `yaml:"default"`
	Hosts   map[string]int `yaml:"hosts"`
}

func emptyOverlay() Overlay {
	return Overlay{
		EgressAllow:  map[string][]string{},
		R1ChainLimit: R1Limits{Default: 8, Hosts: map[string]int{}},
		HostMode:     map[string]string{},
		R3Exceptions: map[string][]string{},
	}
}

// OverlayStore is a persisted, concurrency-safe Applier: it folds each validated diff
// into the overlay and atomically rewrites the overlay file.
type OverlayStore struct {
	mu   sync.Mutex
	path string
	o    Overlay
}

// OpenOverlay loads (or initializes) the overlay at path.
func OpenOverlay(path string) (*OverlayStore, error) {
	s := &OverlayStore{path: path, o: emptyOverlay()}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("read overlay %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &s.o); err != nil {
		return nil, fmt.Errorf("parse overlay %s: %w", path, err)
	}
	s.normalize()
	return s, nil
}

// Snapshot returns a copy of the current effective overlay (for tests / inspection).
func (s *OverlayStore) Snapshot() Overlay {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.o
}

func (s *OverlayStore) normalize() {
	if s.o.EgressAllow == nil {
		s.o.EgressAllow = map[string][]string{}
	}
	if s.o.HostMode == nil {
		s.o.HostMode = map[string]string{}
	}
	if s.o.R3Exceptions == nil {
		s.o.R3Exceptions = map[string][]string{}
	}
	if s.o.R1ChainLimit.Hosts == nil {
		s.o.R1ChainLimit.Hosts = map[string]int{}
	}
	if s.o.R1ChainLimit.Default == 0 {
		s.o.R1ChainLimit.Default = 8
	}
}

// Apply folds one validated diff into the overlay and persists it. Assumes Validate
// has already passed (the Puller enforces this).
func (s *OverlayStore) Apply(d Diff) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.normalize()
	switch d.Op {
	case "egress_allow_add":
		s.o.EgressAllow[d.Agent] = addUnique(s.o.EgressAllow[d.Agent], d.Dest)
	case "egress_allow_remove":
		s.o.EgressAllow[d.Agent] = remove(s.o.EgressAllow[d.Agent], d.Dest)
		if len(s.o.EgressAllow[d.Agent]) == 0 {
			delete(s.o.EgressAllow, d.Agent)
		}
	case "r1_chain_limit":
		if d.Host != "" {
			s.o.R1ChainLimit.Hosts[d.Host] = d.Limit
		} else {
			s.o.R1ChainLimit.Default = d.Limit
		}
	case "host_mode":
		s.o.HostMode[d.Host] = d.Mode
	case "r3_exception_add":
		s.o.R3Exceptions[d.Agent] = addUnique(s.o.R3Exceptions[d.Agent], d.Path)
	case "r3_exception_remove":
		s.o.R3Exceptions[d.Agent] = remove(s.o.R3Exceptions[d.Agent], d.Path)
		if len(s.o.R3Exceptions[d.Agent]) == 0 {
			delete(s.o.R3Exceptions, d.Agent)
		}
	default:
		return fmt.Errorf("unapplicable op: %q", d.Op)
	}
	return s.persist()
}

// persist atomically rewrites the overlay file (temp + rename).
func (s *OverlayStore) persist() error {
	data, err := yaml.Marshal(&s.o)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func addUnique(xs []string, v string) []string {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}

func remove(xs []string, v string) []string {
	out := xs[:0:0]
	for _, x := range xs {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}
