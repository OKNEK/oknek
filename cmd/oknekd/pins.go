package main

// R22 supply-chain pins + R23 canaries — the daemon half. Loads pinned /
// quarantined / canary inodes into the kernel maps at boot, runs the integrity
// sweep, and serves the pin.* / canary.* RPCs. Every state change is sealed into
// Okular so the pin history (who pinned, what tampered, who accepted) is itself
// tamper-evident.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oknek/oknek/internal/canary"
	"github.com/oknek/oknek/internal/config"
	"github.com/oknek/oknek/internal/hooks/ebpf"
	"github.com/oknek/oknek/internal/ipc"
	"github.com/oknek/oknek/internal/okular"
	"github.com/oknek/oknek/internal/pins"
	"github.com/oknek/oknek/internal/store"
)

type insertFn func(id string, ts int64, agentID, ruleID, verdict, payload string) error

type pinService struct {
	cfg    *config.Config
	db     *store.Store
	loader *ebpf.Loader // nil-safe: every map op is a no-op without BPF
	ledger *okular.Ledger
	insert insertFn
	home   string
	mu     sync.Mutex
	// missing pins already reported, so the sweep alerts once, not every tick
	missingSeen map[string]bool
	// canary registry mirror for the hot userspace check.fileopen path (the shim)
	canaryMu sync.RWMutex
	canaries map[string]store.Canary
}

// IsCanary reports whether path is a planted decoy (exact path match).
func (p *pinService) IsCanary(path string) (store.Canary, bool) {
	p.canaryMu.RLock()
	defer p.canaryMu.RUnlock()
	c, ok := p.canaries[path]
	return c, ok
}

func (p *pinService) reloadCanaries() {
	cs, _ := p.db.Canaries()
	m := make(map[string]store.Canary, len(cs))
	for _, c := range cs {
		m[c.Path] = c
	}
	p.canaryMu.Lock()
	p.canaries = m
	p.canaryMu.Unlock()
}

func newPinService(cfg *config.Config, db *store.Store, loader *ebpf.Loader, ledger *okular.Ledger, insert insertFn) *pinService {
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/root"
	}
	ps := &pinService{cfg: cfg, db: db, loader: loader, ledger: ledger, insert: insert, home: home, missingSeen: map[string]bool{}, canaries: map[string]store.Canary{}}
	ps.reloadCanaries()
	return ps
}

func (p *pinService) seal(kind string, payload interface{}) {
	if p.ledger == nil {
		return
	}
	b, _ := json.Marshal(payload)
	_ = p.ledger.Append(time.Now().UnixNano(), "oknekd", kind, "sealed", string(b))
}

// Arm pushes persisted state into the kernel maps (boot / daemon restart).
func (p *pinService) Arm() (pinned, quarantined, canaries int) {
	ps, _ := p.db.Pins()
	for _, pin := range ps {
		if pin.Quarantined {
			_ = p.loader.AddQuarantineInode(pin.Dev, pin.Ino)
			quarantined++
		} else {
			_ = p.loader.AddPinnedInode(pin.Dev, pin.Ino)
			pinned++
		}
	}
	cs, _ := p.db.Canaries()
	for _, c := range cs {
		_ = p.loader.AddCanaryInode(c.Dev, c.Ino, p.cfg.Canary.Mode == "block")
		canaries++
	}
	p.reloadCanaries()
	return
}

// Set resolves the configured globs (against the daemon HOME and the given cwds),
// hashes every artifact, and (re)pins it. Existing pins are refreshed in place.
func (p *pinService) Set(cwds []string) ([]store.Pin, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	files, err := pins.Resolve(p.cfg.Pins.Paths, p.home, cwds)
	if err != nil {
		return nil, err
	}
	old := map[string]store.Pin{}
	if ps, err := p.db.Pins(); err == nil {
		for _, pin := range ps {
			old[pin.Path] = pin
		}
	}
	now := time.Now().UnixNano()
	var out []store.Pin
	for _, f := range files {
		sha, size, dev, ino, err := pins.HashFile(f)
		if err != nil {
			continue
		}
		if o, ok := old[f]; ok && (o.Dev != dev || o.Ino != ino || o.Quarantined) {
			_ = p.loader.RemovePinnedInode(o.Dev, o.Ino)
			_ = p.loader.RemoveQuarantineInode(o.Dev, o.Ino)
		}
		pin := store.Pin{Path: f, Dev: dev, Ino: ino, SHA256: sha, Size: size, PinnedAt: now}
		if err := p.db.UpsertPin(pin); err != nil {
			return nil, err
		}
		_ = p.loader.AddPinnedInode(dev, ino)
		p.seal("pin_set", map[string]interface{}{"path": f, "sha256": sha, "size": size})
		delete(p.missingSeen, f)
		out = append(out, pin)
	}
	log.Printf("pins: %d artifact(s) pinned (R22)", len(out))
	return out, nil
}

// Accept re-pins the given paths after a human reviewed a tamper: quarantine is
// lifted, the new content becomes the pin, and the acceptance is sealed with the note.
func (p *pinService) Accept(paths []string, note string) ([]store.Pin, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	old := map[string]store.Pin{}
	if ps, err := p.db.Pins(); err == nil {
		for _, pin := range ps {
			old[pin.Path] = pin
		}
	}
	now := time.Now().UnixNano()
	var out []store.Pin
	for _, f := range paths {
		f = p.expand(f)
		sha, size, dev, ino, err := pins.HashFile(f)
		if err != nil {
			return out, fmt.Errorf("accept %s: %w", f, err)
		}
		if o, ok := old[f]; ok {
			_ = p.loader.RemoveQuarantineInode(o.Dev, o.Ino)
			_ = p.loader.RemovePinnedInode(o.Dev, o.Ino)
		}
		pin := store.Pin{Path: f, Dev: dev, Ino: ino, SHA256: sha, Size: size, PinnedAt: now}
		if err := p.db.UpsertPin(pin); err != nil {
			return out, err
		}
		_ = p.loader.AddPinnedInode(dev, ino)
		p.seal("pin_accept", map[string]interface{}{"path": f, "sha256": sha, "note": note})
		log.Printf("pins: %s ACCEPTED (re-pinned) — %s", f, note)
		out = append(out, pin)
	}
	return out, nil
}

// SweepOnce re-hashes every pin and acts on what changed.
func (p *pinService) SweepOnce() []pins.Change {
	p.mu.Lock()
	defer p.mu.Unlock()
	ps, err := p.db.Pins()
	if err != nil || len(ps) == 0 {
		return nil
	}
	byPath := map[string]store.Pin{}
	for _, pin := range ps {
		byPath[pin.Path] = pin
	}
	changes := pins.Sweep(ps)
	ts := time.Now().UnixNano()
	var acted []pins.Change
	for _, c := range changes {
		pin := byPath[c.Path]
		switch c.Kind {
		case "moved":
			if pin.Quarantined {
				// content restored to the pinned bytes at a new inode: still needs a human accept
				continue
			}
			_ = p.loader.RemovePinnedInode(pin.Dev, pin.Ino)
			_ = p.loader.AddPinnedInode(c.Dev, c.Ino)
			_ = p.db.UpdatePinInode(c.Path, c.Dev, c.Ino)
		case "tampered":
			if pin.Quarantined && pin.Dev == c.Dev && pin.Ino == c.Ino {
				continue // already quarantined at this inode; don't re-alert every tick
			}
			_ = p.loader.RemovePinnedInode(pin.Dev, pin.Ino)
			_ = p.loader.RemoveQuarantineInode(pin.Dev, pin.Ino)
			_ = p.loader.AddQuarantineInode(c.Dev, c.Ino)
			_ = p.db.MarkPinTampered(c.Path, ts, c.Dev, c.Ino)
			ev := map[string]interface{}{
				"path": c.Path, "old_sha256": c.OldSHA, "new_sha256": c.NewSHA,
				"rule": "supply-chain-guard", "detail": "pinned artifact TAMPERED — quarantined (watched agents can no longer open/exec it)",
				"enforcement": p.enfWord(),
			}
			b, _ := json.Marshal(ev)
			_ = p.insert(fmt.Sprintf("e_%d_R22_tamper_%x", ts, hashID(c.Path)), ts, "", "R22", "alert", string(b))
			p.seal("pin_tamper", ev)
			log.Printf("pins: TAMPERED %s (sha %s… -> %s…) — QUARANTINED", c.Path, short(c.OldSHA), short(c.NewSHA))
		case "missing":
			if p.missingSeen[c.Path] {
				continue
			}
			p.missingSeen[c.Path] = true
			ev := map[string]interface{}{"path": c.Path, "old_sha256": c.OldSHA, "rule": "supply-chain-guard", "detail": "pinned artifact MISSING"}
			b, _ := json.Marshal(ev)
			_ = p.insert(fmt.Sprintf("e_%d_R22_missing_%x", ts, hashID(c.Path)), ts, "", "R22", "alert", string(b))
			p.seal("pin_missing", ev)
			log.Printf("pins: MISSING %s", c.Path)
		}
		acted = append(acted, c)
	}
	return acted
}

func (p *pinService) enfWord() string {
	if p.cfg.Pins.Enforce && p.loader != nil {
		return "ebpf"
	}
	return "observe"
}

// RunSweeper runs SweepOnce every pins.sweep_seconds until ctx ends.
func (p *pinService) RunSweeper(ctx context.Context) {
	iv := time.Duration(p.cfg.Pins.SweepSeconds) * time.Second
	if iv <= 0 {
		iv = 30 * time.Second
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.SweepOnce()
		}
	}
}

// Status is the pin.status / canary.status payload.
func (p *pinService) Status() map[string]interface{} {
	ps, _ := p.db.Pins()
	cs, _ := p.db.Canaries()
	tampered, quarantined := 0, 0
	for _, pin := range ps {
		if pin.TamperedAt > 0 {
			tampered++
		}
		if pin.Quarantined {
			quarantined++
		}
	}
	r22, _ := p.db.CountByRule("R22")
	r23, _ := p.db.CountByRule("R23")
	if ps == nil {
		ps = []store.Pin{}
	}
	if cs == nil {
		cs = []store.Canary{}
	}
	return map[string]interface{}{
		"pins_enabled":   p.cfg.Pins.Enabled,
		"pins_enforce":   p.cfg.Pins.Enforce,
		"kernel":         p.loader != nil,
		"pinned":         len(ps),
		"tampered":       tampered,
		"quarantined":    quarantined,
		"pins":           ps,
		"r22_events":     r22,
		"canary_enabled": p.cfg.Canary.Enabled,
		"canary_mode":    p.cfg.Canary.Mode,
		"canaries":       cs,
		"canary_hits":    r23,
	}
}

// PlantCanaries plants decoys at the given paths (default: canary.plant). A path
// occupied by a real file is skipped and reported, never overwritten.
func (p *pinService) PlantCanaries(paths []string) (planted, skipped []string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(paths) == 0 {
		paths = p.cfg.Canary.Plant
	}
	block := p.cfg.Canary.Mode == "block"
	now := time.Now().UnixNano()
	for _, raw := range paths {
		f := p.expand(raw)
		sha, perr := canary.Plant(f)
		if errors.Is(perr, canary.ErrExists) {
			skipped = append(skipped, f)
			continue
		}
		if perr != nil {
			return planted, skipped, fmt.Errorf("plant %s: %w", f, perr)
		}
		_, _, dev, ino, herr := pins.HashFile(f)
		if herr != nil {
			return planted, skipped, herr
		}
		if err := p.db.UpsertCanary(store.Canary{Path: f, Dev: dev, Ino: ino, SHA256: sha, PlantedAt: now}); err != nil {
			return planted, skipped, err
		}
		_ = p.loader.AddCanaryInode(dev, ino, block)
		p.seal("canary_plant", map[string]interface{}{"path": f, "mode": p.cfg.Canary.Mode})
		planted = append(planted, f)
	}
	if planted == nil {
		planted = []string{}
	}
	if skipped == nil {
		skipped = []string{}
	}
	p.reloadCanaries()
	log.Printf("canary: %d decoy(s) planted, %d skipped (real file present) · mode=%s", len(planted), len(skipped), p.cfg.Canary.Mode)
	return planted, skipped, nil
}

// RemoveCanaries deletes every decoy whose bytes are still ours; a decoy that was
// overwritten by real content is left alone and reported.
func (p *pinService) RemoveCanaries() (removed, kept []string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cs, err := p.db.Canaries()
	if err != nil {
		return nil, nil, err
	}
	removed, kept = []string{}, []string{}
	for _, c := range cs {
		rerr := canary.Remove(c.Path, c.SHA256)
		_ = p.loader.RemoveCanaryInode(c.Dev, c.Ino)
		if errors.Is(rerr, canary.ErrChanged) {
			kept = append(kept, c.Path)
			_ = p.db.DeleteCanary(c.Path)
			continue
		}
		if rerr != nil {
			return removed, kept, rerr
		}
		_ = p.db.DeleteCanary(c.Path)
		p.seal("canary_remove", map[string]interface{}{"path": c.Path})
		removed = append(removed, c.Path)
	}
	p.reloadCanaries()
	return removed, kept, nil
}

// CanaryTouched is the userspace (LD_PRELOAD shim) verdict for an open of a planted
// decoy: it must NOT fall through to R3's credential-name block, or the kernel
// canary hook never sees the open. alert -> allow (the kernel hook records the hit
// when attached; without a kernel we record it here); block -> deny.
func (p *pinService) CanaryTouched(agentID, process, path string, kernelAttached bool) (block bool) {
	block = p.cfg.Canary.Mode == "block"
	if kernelAttached && !block {
		return false // allowed through: the BPF hook records the hit itself (no double-count)
	}
	// blocked here in userspace (the syscall never reaches the kernel hook), or no
	// kernel at all -> this is the only place the event can be recorded.
	ts := time.Now().UnixNano()
	verdict := "alert"
	if block {
		verdict = "block"
	}
	ev := map[string]interface{}{"path": path, "process": process, "agent_identifier": agentID, "enforcement": "ld_preload", "rule": "canary", "severity": "critical", "mode": p.cfg.Canary.Mode}
	b, _ := json.Marshal(ev)
	_ = p.insert(fmt.Sprintf("e_%d_R23_%x", ts, hashID(path)), ts, agentID, "R23", verdict, string(b))
	return block
}

func (p *pinService) expand(f string) string {
	if strings.HasPrefix(f, "~/") {
		return filepath.Join(p.home, f[2:])
	}
	return f
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func hashID(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// --- RPC handlers ---------------------------------------------------------------

func pinSetHandler(p *pinService) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		var in struct {
			Cwds []string `json:"cwds"`
		}
		if len(req.Params) > 0 {
			_ = json.Unmarshal(req.Params, &in)
		}
		ps, err := p.Set(in.Cwds)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"ok": true, "pinned": len(ps), "pins": ps}, nil
	}
}

func pinAcceptHandler(p *pinService) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		var in struct {
			Paths []string `json:"paths"`
			Note  string   `json:"note"`
		}
		if len(req.Params) > 0 {
			_ = json.Unmarshal(req.Params, &in)
		}
		if len(in.Paths) == 0 {
			return nil, errors.New("pin.accept: no paths")
		}
		ps, err := p.Accept(in.Paths, in.Note)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"ok": true, "accepted": len(ps), "pins": ps}, nil
	}
}

func pinStatusHandler(p *pinService) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		return p.Status(), nil
	}
}

func canaryPlantHandler(p *pinService) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		var in struct {
			Paths []string `json:"paths"`
		}
		if len(req.Params) > 0 {
			_ = json.Unmarshal(req.Params, &in)
		}
		planted, skipped, err := p.PlantCanaries(in.Paths)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"ok": true, "planted": planted, "skipped": skipped, "mode": p.cfg.Canary.Mode}, nil
	}
}

func canaryRemoveHandler(p *pinService) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		removed, kept, err := p.RemoveCanaries()
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"ok": true, "removed": removed, "kept": kept}, nil
	}
}
