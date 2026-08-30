package configpull

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
)

// fakeSealer records seal calls and can be told to fail (escrow down).
type fakeSealer struct {
	mu      sync.Mutex
	calls   []string
	enforce []bool
	failNow bool
}

func (f *fakeSealer) Seal(name string, version int, enforce bool) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNow {
		return "", fmt.Errorf("off-box escrow failed")
	}
	f.calls = append(f.calls, name)
	f.enforce = append(f.enforce, enforce)
	return fmt.Sprintf("anchor#%d %s", version, name), nil
}

func TestValidate_AllowlistBoundary(t *testing.T) {
	good := []Diff{
		{Op: "egress_allow_add", Agent: "cursor-agent", Dest: "api.stripe.com:443"},
		{Op: "egress_allow_remove", Agent: "a", Dest: "*.stripe.com"},
		{Op: "r1_chain_limit", Limit: 12},
		{Op: "r1_chain_limit", Limit: 12, Host: "api-2"},
		{Op: "host_mode", Host: "api-2", Mode: "enforce"},
		{Op: "r3_exception_add", Agent: "billing", Path: "/etc/billing/token"},
	}
	for _, d := range good {
		if err := Validate(d); err != nil {
			t.Errorf("expected valid: %+v got %v", d, err)
		}
	}
	bad := []Diff{
		{Op: "disable_self_guard"},
		{Op: "disarm"},
		{Op: "set_config", Host: "x"},
		{Op: "egress_allow_add", Agent: "a b", Dest: "x.com"},
		{Op: "egress_allow_add", Agent: "a", Dest: "not a host!"},
		{Op: "r1_chain_limit", Limit: 0},
		{Op: "r1_chain_limit", Limit: 65},
		{Op: "host_mode", Host: "h", Mode: "yolo"},
		{Op: "r3_exception_add", Agent: "a", Path: "relative"},
		{Op: "r3_exception_add", Agent: "a", Path: "/etc/../boot"},
	}
	for _, d := range bad {
		if err := Validate(d); err == nil {
			t.Errorf("expected REJECT: %+v", d)
		}
	}
}

func TestOverlay_ApplyAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.overlay.yaml")
	s, err := OpenOverlay(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []Diff{
		{Op: "egress_allow_add", Agent: "cursor-agent", Dest: "api.stripe.com:443"},
		{Op: "egress_allow_add", Agent: "cursor-agent", Dest: "api.stripe.com:443"}, // idempotent
		{Op: "r1_chain_limit", Limit: 12, Host: "api-2"},
		{Op: "host_mode", Host: "dev-box", Mode: "enforce"},
		{Op: "r3_exception_add", Agent: "billing", Path: "/etc/billing/token"},
	} {
		if err := s.Apply(d); err != nil {
			t.Fatalf("apply %+v: %v", d, err)
		}
	}
	// reload from disk → persistence round-trips
	s2, err := OpenOverlay(path)
	if err != nil {
		t.Fatal(err)
	}
	o := s2.Snapshot()
	if got := o.EgressAllow["cursor-agent"]; len(got) != 1 || got[0] != "api.stripe.com:443" {
		t.Errorf("egress allow = %v", got)
	}
	if o.R1ChainLimit.Hosts["api-2"] != 12 {
		t.Errorf("r1 host limit = %d", o.R1ChainLimit.Hosts["api-2"])
	}
	if o.HostMode["dev-box"] != "enforce" {
		t.Errorf("host mode = %q", o.HostMode["dev-box"])
	}
	if len(o.R3Exceptions["billing"]) != 1 {
		t.Errorf("r3 exceptions = %v", o.R3Exceptions["billing"])
	}
}

// endToEnd: pending server hands two changes; puller validates→seals→applies→acks.
func TestPuller_PullOnce_SealsAppliesAcks(t *testing.T) {
	var acked []string
	var authHeaders []string
	var mu sync.Mutex

	mux := http.NewServeMux()
	mux.HandleFunc("/api/config/pending", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authHeaders = append(authHeaders, r.Header.Get("authorization"))
		mu.Unlock()
		json.NewEncoder(w).Encode(pendingResp{OK: true, Changes: []change{
			{ID: "chg_1", Diff: Diff{Op: "egress_allow_add", Agent: "cursor-agent", Dest: "api.stripe.com:443"}},
			{ID: "chg_2", Diff: Diff{Op: "host_mode", Host: "api-2", Mode: "enforce"}},
		}})
	})
	mux.HandleFunc("/api/config/ack", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID   string `json:"id"`
			Seal string `json:"seal"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		if body.Seal == "" {
			t.Errorf("ack for %s missing seal receipt", body.ID)
		}
		acked = append(acked, body.ID)
		mu.Unlock()
		w.Write([]byte(`{"ok":true}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	overlay, _ := OpenOverlay(filepath.Join(t.TempDir(), "o.yaml"))
	sealer := &fakeSealer{}
	p := New(srv.URL+"/api/config/pending", srv.URL+"/api/config/ack", "okik_test", overlay, sealer, nil)
	if p == nil {
		t.Fatal("puller nil")
	}
	if err := p.PullOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	if len(acked) != 2 {
		t.Fatalf("acked %v, want 2", acked)
	}
	if len(sealer.calls) != 2 {
		t.Fatalf("sealed %d, want 2", len(sealer.calls))
	}
	// host_mode enforce must be the loud (enforce) seal
	if !(sealer.enforce[0] == false && sealer.enforce[1] == true) {
		t.Errorf("enforce flags = %v", sealer.enforce)
	}
	if got := overlay.Snapshot().EgressAllow["cursor-agent"]; len(got) != 1 {
		t.Errorf("egress not applied: %v", got)
	}
	if authHeaders[0] != "Bearer okik_test" {
		t.Errorf("bearer = %q", authHeaders[0])
	}
}

// A seal failure (off-box escrow down) must NOT apply and must NOT ack — fail-closed.
func TestPuller_SealFailure_DoesNotApplyOrAck(t *testing.T) {
	var acked int
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config/pending", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(pendingResp{OK: true, Changes: []change{
			{ID: "chg_1", Diff: Diff{Op: "egress_allow_add", Agent: "a", Dest: "x.com:443"}},
		}})
	})
	mux.HandleFunc("/api/config/ack", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		acked++
		mu.Unlock()
		w.Write([]byte(`{"ok":true}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	overlay, _ := OpenOverlay(filepath.Join(t.TempDir(), "o.yaml"))
	p := New(srv.URL+"/api/config/pending", srv.URL+"/api/config/ack", "k", overlay, &fakeSealer{failNow: true}, nil)
	if err := p.PullOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if acked != 0 {
		t.Errorf("acked %d despite seal failure — must be fail-closed", acked)
	}
	if len(overlay.Snapshot().EgressAllow) != 0 {
		t.Errorf("applied despite seal failure: %v", overlay.Snapshot().EgressAllow)
	}
}

// An out-of-allowlist change served by a tampered/rogue server is never sealed,
// applied, or acked (defense in depth on the daemon).
func TestPuller_RejectsOutOfAllowlist(t *testing.T) {
	var acked int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config/pending", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(pendingResp{OK: true, Changes: []change{
			{ID: "evil", Diff: Diff{Op: "disable_self_guard"}},
		}})
	})
	mux.HandleFunc("/api/config/ack", func(w http.ResponseWriter, r *http.Request) { acked++; w.Write([]byte(`{"ok":true}`)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	overlay, _ := OpenOverlay(filepath.Join(t.TempDir(), "o.yaml"))
	sealer := &fakeSealer{}
	p := New(srv.URL+"/api/config/pending", srv.URL+"/api/config/ack", "k", overlay, sealer, nil)
	if err := p.PullOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if acked != 0 || len(sealer.calls) != 0 {
		t.Errorf("rogue change touched: acked=%d sealed=%d", acked, len(sealer.calls))
	}
}
