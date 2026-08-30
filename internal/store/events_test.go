package store

import (
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestInsertEventAndCounts(t *testing.T) {
	s := newTestStore(t)

	if err := s.InsertEvent("e1", 100, "claude-a", "R3", "block", `{"path":"/x"}`); err != nil {
		t.Fatalf("insert e1: %v", err)
	}
	if err := s.InsertEvent("e2", 200, "claude-a", "R1", "warn", `{"depth":9}`); err != nil {
		t.Fatalf("insert e2: %v", err)
	}
	if err := s.InsertEvent("e3", 300, "cursor-b", "R5", "block", `{"host":"evil.test"}`); err != nil {
		t.Fatalf("insert e3: %v", err)
	}

	if got, _ := s.CountByVerdict("block"); got != 2 {
		t.Errorf("block count = %d, want 2", got)
	}
	if got, _ := s.CountByVerdict("warn"); got != 1 {
		t.Errorf("warn count = %d, want 1", got)
	}
	if got, _ := s.DistinctAgentCount(); got != 2 {
		t.Errorf("distinct agents = %d, want 2", got)
	}

	recent, err := s.RecentEvents(10)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(recent) != 3 {
		t.Fatalf("recent len = %d, want 3", len(recent))
	}
	if recent[0].ID != "e3" { // newest first (ts DESC)
		t.Errorf("recent[0].ID = %q, want e3", recent[0].ID)
	}
	if recent[0].RuleID != "R5" || recent[0].Verdict != "block" {
		t.Errorf("recent[0] = %+v, want R5/block", recent[0])
	}
}

func TestInsertEventIdempotent(t *testing.T) {
	s := newTestStore(t)
	_ = s.InsertEvent("dup", 100, "a", "R3", "block", "{}")
	_ = s.InsertEvent("dup", 100, "a", "R3", "block", "{}")
	if got, _ := s.CountByVerdict("block"); got != 1 {
		t.Errorf("block count after dup = %d, want 1 (INSERT OR REPLACE)", got)
	}
}

func TestEventsByRule(t *testing.T) {
	s := newTestStore(t)
	_ = s.InsertEvent("a", 100, "agent-x", "R11", "block", `{"dest":"1.2.3.4:443"}`)
	_ = s.InsertEvent("b", 300, "agent-x", "R11", "block", `{"dest":"5.6.7.8:443"}`)
	_ = s.InsertEvent("c", 200, "agent-y", "R3", "block", `{"path":"/x"}`)
	_ = s.InsertEvent("d", 400, "agent-x", "R11", "block", `{"dest":"9.9.9.9:53"}`)

	got, err := s.EventsByRule("R11", 10)
	if err != nil {
		t.Fatalf("EventsByRule: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("EventsByRule(R11) len = %d, want 3 (R3 excluded)", len(got))
	}
	if got[0].ID != "d" || got[1].ID != "b" || got[2].ID != "a" {
		t.Errorf("EventsByRule order = %s,%s,%s; want d,b,a (ts DESC)", got[0].ID, got[1].ID, got[2].ID)
	}
	if lim, _ := s.EventsByRule("R11", 2); len(lim) != 2 {
		t.Errorf("EventsByRule limit=2 returned %d, want 2", len(lim))
	}
}

func TestCountByRule(t *testing.T) {
	s, err := Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_ = s.InsertEvent("a", 1, "ag", "R10", "warn", "{}")
	_ = s.InsertEvent("b", 2, "ag", "R10", "warn", "{}")
	_ = s.InsertEvent("c", 3, "ag", "R5", "block", "{}")
	n, err := s.CountByRule("R10")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("CountByRule(R10) = %d, want 2", n)
	}
}
