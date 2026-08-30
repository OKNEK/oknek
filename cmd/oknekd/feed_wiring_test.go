package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/oknek/oknek/internal/feed"
	"github.com/oknek/oknek/internal/rules"
	"github.com/oknek/oknek/internal/store"
)

func TestLogMatches_StoresAndFeeds(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	got := make(chan map[string]interface{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]interface{}
		_ = json.Unmarshal(b, &m)
		got <- m
		w.WriteHeader(200)
	}))
	defer srv.Close()

	poster := feed.New(srv.URL, "okik_test")
	ev := rules.Event{Timestamp: 100, PID: 42, AgentID: "claude-a"}
	matches := []rules.Match{{RuleID: "R3", Verdict: rules.VerdictBlock, Evidence: map[string]interface{}{"path": "/etc/shadow"}}}

	logMatches(db, poster, ev, matches)

	// stored locally
	if n, _ := db.CountByVerdict("block"); n != 1 {
		t.Errorf("stored block count = %d, want 1", n)
	}
	// fed to the dashboard
	select {
	case m := <-got:
		if m["rule_id"] != "R3" || m["agent_id"] != "claude-a" || m["verdict"] != "block" {
			t.Errorf("fed event wrong: %+v", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("event was not fed to the dashboard")
	}
}
