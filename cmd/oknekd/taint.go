package main

// R21 Rule of Two — daemon half. Resolves the configured untrusted/private sets to
// (dev, ino) for the kernel maps, sets each Okredo profile's mode, and serves
// `taint.show` / `taint.clear` (the human checkpoint, sealed to Okular).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/oknek/oknek/internal/config"
	"github.com/oknek/oknek/internal/hooks/ebpf"
	"github.com/oknek/oknek/internal/ipc"
	"github.com/oknek/oknek/internal/okular"
)

// r2ModeOf maps the profile's yaml word to the kernel mode byte.
func r2ModeOf(word string) uint8 {
	switch strings.ToLower(strings.TrimSpace(word)) {
	case "enforce":
		return 2
	case "observe":
		return 1
	}
	return 0
}

func expandHome(p, home string) string {
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

// statKernel returns (dev, ino) in the kernel MKDEV form the BPF hooks read.
func statKernel(path string) (dev uint32, ino uint64, err error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, 0, err
	}
	major, minor := unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev))
	return (major << 20) | minor, uint64(st.Ino), nil
}

type r2Summary struct {
	Files, Dirs, Enforce, Observe int
}

// armRuleOfTwo loads the untrusted/private sets and per-profile modes into the kernel.
// nil-safe: without BPF it only reports what would have been armed.
func armRuleOfTwo(cfg *config.Config, loader *ebpf.Loader, profiles map[string]uint16) r2Summary {
	var sum r2Summary
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/root"
	}
	load := func(kind uint8, list []string, isDir bool) {
		for _, raw := range list {
			p := expandHome(raw, home)
			dev, ino, err := statKernel(p)
			if err != nil {
				log.Printf("rule_of_two: %s not found (%v) — skipped", p, err)
				continue
			}
			if loader != nil {
				if err := loader.AddR2Inode(kind, dev, ino); err != nil {
					log.Printf("rule_of_two: %s: %v", p, err)
					continue
				}
			}
			if isDir {
				sum.Dirs++
			} else {
				sum.Files++
			}
		}
	}
	load(ebpf.R2UntrustedFile, cfg.RuleOfTwo.UntrustedFiles, false)
	load(ebpf.R2UntrustedDir, cfg.RuleOfTwo.UntrustedDirs, true)
	load(ebpf.R2PrivateFile, cfg.RuleOfTwo.PrivateFiles, false)
	load(ebpf.R2PrivateDir, cfg.RuleOfTwo.PrivateDirs, true)
	if loader != nil {
		_ = loader.SetR2NetworkTrusted(cfg.RuleOfTwo.NetworkTrusted)
	}
	for name, id := range profiles {
		mode := r2ModeOf(cfg.Okredo.Profiles[name].RuleOfTwo)
		if mode == 0 {
			continue
		}
		if loader != nil {
			_ = loader.SetR2Mode(id, mode)
		}
		if mode == 2 {
			sum.Enforce++
		} else {
			sum.Observe++
		}
	}
	if sum.Enforce+sum.Observe > 0 || sum.Files+sum.Dirs > 0 {
		net := "network=untrusted (connect = U+X)"
		if cfg.RuleOfTwo.NetworkTrusted {
			net = "network=trusted (connect = X)"
		}
		log.Printf("rule_of_two: R21 armed · %d file(s) + %d dir(s) classified · profiles: %d enforce, %d observe · %s · kernel=%v",
			sum.Files, sum.Dirs, sum.Enforce, sum.Observe, net, loader != nil)
	}
	return sum
}

type taintRow struct {
	Agent string `json:"agent"`
	Bits  uint8  `json:"bits"`
	U     bool   `json:"u"`
	P     bool   `json:"p"`
	X     bool   `json:"x"`
}

func taintRows(loader *ebpf.Loader) []taintRow {
	rows := []taintRow{}
	if loader == nil {
		return rows
	}
	m := loader.Taints()
	names := make([]string, 0, len(m))
	for a := range m {
		names = append(names, a)
	}
	sort.Strings(names)
	for _, a := range names {
		b := m[a]
		rows = append(rows, taintRow{Agent: a, Bits: b, U: b&1 != 0, P: b&2 != 0, X: b&4 != 0})
	}
	return rows
}

func taintShowHandler(cfg *config.Config, loader *ebpf.Loader, db interface {
	CountByRule(string) (int, error)
}) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		n, _ := db.CountByRule("R21")
		enf, obs := 0, 0
		for _, p := range cfg.Okredo.Profiles {
			switch r2ModeOf(p.RuleOfTwo) {
			case 2:
				enf++
			case 1:
				obs++
			}
		}
		return map[string]interface{}{
			"kernel":     loader != nil,
			"enforce":    enf,
			"observe":    obs,
			"sessions":   taintRows(loader),
			"r21_events": n,
		}, nil
	}
}

func taintClearHandler(loader *ebpf.Loader, ledger *okular.Ledger, idSvc *identityService) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		var in struct {
			Agent string `json:"agent"`
			Note  string `json:"note"`
		}
		if len(req.Params) > 0 {
			_ = json.Unmarshal(req.Params, &in)
		}
		if in.Agent == "" {
			return nil, errors.New("taint.clear: agent required")
		}
		if loader == nil {
			return nil, errors.New("taint.clear: kernel BPF-LSM not attached")
		}
		if err := loader.ClearTaint(in.Agent); err != nil {
			return nil, err
		}
		if ledger != nil {
			b, _ := json.Marshal(map[string]interface{}{"agent": in.Agent, "note": in.Note, "rule": "rule-of-two", "detail": "session taint cleared by operator (human checkpoint)"})
			_ = ledger.Append(time.Now().UnixNano(), "oknekd", "taint_clear", "sealed", string(b))
		}
		log.Printf("rule_of_two: taint CLEARED for agent %q — %s", in.Agent, in.Note)
		idSvc.Push(in.Agent, "clear")
		return map[string]interface{}{"ok": true, "agent": in.Agent, "cleared_at": fmt.Sprint(time.Now().Unix())}, nil
	}
}
