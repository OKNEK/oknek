package rules

import (
	"context"
	"strings"
	"testing"
)

func TestChainDepth(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want int
	}{
		{"empty", "", 0},
		{"whitespace only", "   \t\n", 0},
		{"single", "ls -la", 1},
		{"semicolons", "a; b; c", 3},
		{"and", "a && b && c", 3},
		{"or", "a || b", 2},
		{"mixed and-or", "a && b || c", 3},
		{"pipes", "a | b | c | d", 4},
		{"newlines", "a\nb\nc", 3},
		{"background", "a & b", 2},
		{"quoted semicolons double", `echo "a; b; c"`, 1},
		{"quoted semicolons single", `echo 'a; b; c'`, 1},
		{"escaped semicolon", `echo a\;b`, 1},
		{"ten chain", "a;b;c;d;e;f;g;h;i;j", 10},
		{"50 chain matches Adversa CC-643", repeatChain(50), 50},
		{"nested substitution counts inner", "a; $(b; c; d; e; f)", 6},
		{"backticks count inner", "a; `b; c; d`", 4},
		{"realistic mixed", `git status; echo "log: $(date)"; ls -la; cat file.txt`, 4},
		{"piped grep chain", `cat file | grep foo | awk '{print $1}' | sort | uniq`, 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ChainDepth(c.cmd)
			if got != c.want {
				t.Errorf("ChainDepth(%q) = %d, want %d", c.cmd, got, c.want)
			}
		})
	}
}

func repeatChain(n int) string {
	if n == 0 {
		return ""
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "cmd"
	}
	return strings.Join(parts, "; ")
}

func TestR1_Match(t *testing.T) {
	r := NewR1() // threshold 8, action Block

	cases := []struct {
		name      string
		cmd       string
		wantMatch bool
	}{
		{"single command", "ls", false},
		{"three commands below threshold", "a; b; c", false},
		{"seven commands just below threshold", "a;b;c;d;e;f;g", false},
		{"eight commands at threshold", "a;b;c;d;e;f;g;h", true},
		{"ten commands above", "a;b;c;d;e;f;g;h;i;j", true},
		{"50-chain (Adversa pattern)", repeatChain(50), true},
		{"empty", "", false},
		{"50-chain quoted out", `echo "` + repeatChain(50) + `"`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := Event{
				Kind:    KindExecObserved,
				AgentID: "test-agent",
				PID:     1234,
				Payload: ExecPayload{Command: c.cmd},
			}
			m, ok := r.Match(context.Background(), ev)
			if ok != c.wantMatch {
				t.Errorf("R1.Match(%q) ok = %v, want %v (depth=%d)",
					c.cmd, ok, c.wantMatch, ChainDepth(c.cmd))
				return
			}
			if ok {
				if m.RuleID != "R1" {
					t.Errorf("RuleID = %q, want R1", m.RuleID)
				}
				if m.Verdict != VerdictBlock {
					t.Errorf("Verdict = %v, want Block", m.Verdict)
				}
				if _, has := m.Evidence["chain_depth"]; !has {
					t.Errorf("Evidence missing chain_depth")
				}
			}
		})
	}
}

func TestR1_WrongPayloadKind_ReturnsFalse(t *testing.T) {
	r := NewR1()
	ev := Event{
		Kind:    KindExecObserved,
		Payload: "not an ExecPayload",
	}
	if _, ok := r.Match(context.Background(), ev); ok {
		t.Errorf("R1 matched on wrong payload type")
	}
}

func TestEngine_Register_Evaluate(t *testing.T) {
	e := NewEngine()
	if e.Count() != 0 {
		t.Fatalf("fresh engine should have 0 rules, got %d", e.Count())
	}
	e.Register(NewR1())
	if e.Count() != 1 {
		t.Fatalf("Count() = %d, want 1", e.Count())
	}

	list := e.List()
	if len(list) != 1 || list[0].ID != "R1" {
		t.Errorf("List() = %+v, want one R1 entry", list)
	}

	// non-matching event → no matches
	ev := Event{
		Kind:    KindExecObserved,
		Payload: ExecPayload{Command: "ls"},
	}
	if matches := e.Evaluate(context.Background(), ev); len(matches) != 0 {
		t.Errorf("expected 0 matches for short cmd, got %d", len(matches))
	}

	// matching event → one Block
	ev.Payload = ExecPayload{Command: repeatChain(20)}
	matches := e.Evaluate(context.Background(), ev)
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1", len(matches))
	}
	if matches[0].RuleID != "R1" || matches[0].Verdict != VerdictBlock {
		t.Errorf("match = %+v, want R1/Block", matches[0])
	}

	// event of a different Kind → no matches (Engine dispatches by Kind)
	noise := Event{Kind: KindSocketConnect, Payload: ExecPayload{Command: repeatChain(20)}}
	if matches := e.Evaluate(context.Background(), noise); len(matches) != 0 {
		t.Errorf("expected 0 matches for wrong Kind, got %d", len(matches))
	}
}

func TestVerdict_String(t *testing.T) {
	cases := map[Verdict]string{
		VerdictAllow: "allow",
		VerdictWarn:  "warn",
		VerdictBlock: "block",
	}
	for v, want := range cases {
		if got := v.String(); got != want {
			t.Errorf("Verdict(%d).String() = %q, want %q", v, got, want)
		}
	}
}
