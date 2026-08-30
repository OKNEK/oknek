package store

import (
	"path/filepath"
	"testing"
)

func TestObserveAndScore(t *testing.T) {
	s := mustOpen(t)
	defer s.Close()

	agent := "claude-code-7f3a"

	// Train: agent has done git status many times, ls -la a few times
	for i := 0; i < 10; i++ {
		if err := s.ObserveBaseline(agent, "exec:git"); err != nil {
			t.Fatalf("observe: %v", err)
		}
	}
	for i := 0; i < 5; i++ {
		_ = s.ObserveBaseline(agent, "exec:ls")
	}
	// Only one observation of curl — should count as "rare" (+0.5)
	_ = s.ObserveBaseline(agent, "exec:curl")

	// Score scenarios
	cases := []struct {
		name       string
		features   []string
		wantScore  float64
		wantNovel  []string
	}{
		{"all familiar", []string{"exec:git", "exec:ls"}, 0, nil},
		{"one rare", []string{"exec:git", "exec:curl"}, 0.5, nil},
		{"one novel", []string{"exec:nc"}, 1, []string{"exec:nc"}},
		{"mixed novel + rare + familiar", []string{"exec:nc", "exec:curl", "exec:git"}, 1.5, []string{"exec:nc"}},
		{"three novel", []string{"exec:nc", "exec:base64", "exec:ssh-add"}, 3, []string{"exec:nc", "exec:base64", "exec:ssh-add"}},
		{"empty", []string{}, 0, nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			score, novel, err := s.BaselineScore(agent, c.features)
			if err != nil {
				t.Fatalf("score: %v", err)
			}
			if score != c.wantScore {
				t.Errorf("score = %v, want %v", score, c.wantScore)
			}
			if len(novel) != len(c.wantNovel) {
				t.Errorf("novel = %v, want %v", novel, c.wantNovel)
			}
		})
	}
}

func TestBaseline_AgentIsolation(t *testing.T) {
	s := mustOpen(t)
	defer s.Close()

	_ = s.ObserveBaseline("agent-a", "exec:git")
	_ = s.ObserveBaseline("agent-a", "exec:git")
	_ = s.ObserveBaseline("agent-a", "exec:git")

	// agent-b has never seen exec:git
	score, novel, err := s.BaselineScore("agent-b", []string{"exec:git"})
	if err != nil {
		t.Fatalf("score: %v", err)
	}
	if score != 1.0 {
		t.Errorf("expected novel score 1.0 for unrelated agent, got %v", score)
	}
	if len(novel) != 1 || novel[0] != "exec:git" {
		t.Errorf("novel = %v, expected [exec:git]", novel)
	}
}

func TestBaseline_Size(t *testing.T) {
	s := mustOpen(t)
	defer s.Close()
	if s.BaselineSize() != 0 {
		t.Errorf("fresh size != 0")
	}
	_ = s.ObserveBaseline("a", "f1")
	_ = s.ObserveBaseline("a", "f2")
	_ = s.ObserveBaseline("b", "f1")
	if got := s.BaselineSize(); got != 3 {
		t.Errorf("size = %d, want 3", got)
	}
}

// ─── helpers ──────────────────────────────────

func mustOpen(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}
