package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/oknek/oknek/internal/config"
	"github.com/oknek/oknek/internal/ipc"
	"github.com/oknek/oknek/internal/rules"
	"github.com/oknek/oknek/internal/store"
)

func testEngine() *rules.Engine {
	e := rules.NewEngine()
	e.Register(rules.NewR1())
	e.Register(rules.NewR3())
	e.Register(rules.NewR5())
	return e
}

func testCfg(t *testing.T) *config.Config {
	return &config.Config{Socket: "/tmp/x.sock", DBPath: "/tmp/x.db"}
}

func call(t *testing.T, h ipc.Handler, params interface{}) map[string]interface{} {
	t.Helper()
	raw, _ := json.Marshal(params)
	res, err := h(context.Background(), &ipc.Request{Params: raw})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	return res.(map[string]interface{})
}

func TestCheckExecPersistsBlock(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	eng := testEngine()

	// A 12-deep chain trips R1 (threshold 8) → block.
	chain := "a && b && c && d && e && f && g && h && i && j && k && l"
	out := call(t, checkExecHandler(eng, db, nil), map[string]string{"command": chain, "agent_id": "claude-x"})
	if out["matched"] != true {
		t.Fatalf("expected R1 to fire on 12-deep chain, got %+v", out)
	}
	if got, _ := db.CountByVerdict("block"); got != 1 {
		t.Errorf("block count = %d, want 1 (event persisted)", got)
	}
	if got, _ := db.DistinctAgentCount(); got != 1 {
		t.Errorf("distinct agents = %d, want 1", got)
	}
}

func TestHookAttachAndStatus(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	eng := testEngine()
	hs := newHookState()

	// Before any attach, status reports stub.
	st := call(t, statusHandler(testCfg(t), db, eng, hs), nil)
	if st["hook_mode"] != "stub" {
		t.Errorf("hook_mode before attach = %v, want stub", st["hook_mode"])
	}

	// Shim attaches.
	call(t, hookAttachHandler(hs, nil, nil, nil, nil), map[string]string{"mode": "ld_preload", "agent_id": "claude-x"})

	st = call(t, statusHandler(testCfg(t), db, eng, hs), nil)
	if st["hook_mode"] != "ld_preload" {
		t.Errorf("hook_mode after attach = %v, want ld_preload", st["hook_mode"])
	}
	if st["agents"] != 1 {
		t.Errorf("agents after attach = %v, want 1", st["agents"])
	}
}
