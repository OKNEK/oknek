package rules

import (
	"context"
	"testing"
)

// ─── R2 ────────────────────────────────────────────────────

func TestR2_Match(t *testing.T) {
	r := NewR2()
	cases := []struct {
		name      string
		path      string
		op        FileOp
		wantMatch bool
	}{
		{"claude settings modify", "/home/u/.claude/settings.json", FileOpModify, true},
		{"claude settings create", "/home/u/.claude/settings.json", FileOpCreate, true},
		{"claude settings delete (informational only)", "/home/u/.claude/settings.json", FileOpDelete, false},
		{"claude local settings", "/home/u/.claude/settings.local.json", FileOpModify, true},
		{"cursor mcp.json", "/repo/.cursor/mcp.json", FileOpModify, true},
		{"cursor settings", "/repo/.cursor/settings.json", FileOpModify, true},
		{"cursor rules", "/repo/.cursor/rules", FileOpCreate, true},
		{"clinerules", "/repo/.clinerules", FileOpModify, true},
		{"continue config json", "/repo/.continue/config.json", FileOpModify, true},
		{"continue config ts", "/repo/.continue/config.ts", FileOpModify, true},
		{"aider conf", "/repo/.aider.conf.yml", FileOpModify, true},
		{"vscode settings", "/repo/.vscode/settings.json", FileOpModify, true},
		{"github copilot config", "/home/u/.config/github-copilot/config.json", FileOpModify, true},

		{"unrelated readme", "/repo/README.md", FileOpModify, false},
		{"random json", "/repo/data.json", FileOpModify, false},
		{"settings.json in unrelated path", "/repo/src/settings.json", FileOpModify, false},
		{"empty path", "", FileOpModify, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := Event{
				Kind:    KindFileChanged,
				AgentID: "test-agent",
				PID:     1234,
				Payload: FileChangePayload{Path: c.path, Op: c.op, NewHash: "abc123"},
			}
			m, ok := r.Match(context.Background(), ev)
			if ok != c.wantMatch {
				t.Errorf("R2.Match(%q, %s) ok = %v, want %v", c.path, c.op, ok, c.wantMatch)
				return
			}
			if ok {
				if m.RuleID != "R2" {
					t.Errorf("RuleID = %q, want R2", m.RuleID)
				}
				if m.Verdict != VerdictBlock {
					t.Errorf("Verdict = %v, want Block", m.Verdict)
				}
				if m.Evidence["matched_suffix"] == "" {
					t.Errorf("evidence missing matched_suffix")
				}
			}
		})
	}
}

func TestR2_WrongPayloadKind(t *testing.T) {
	r := NewR2()
	ev := Event{Kind: KindFileChanged, Payload: "not a FileChangePayload"}
	if _, ok := r.Match(context.Background(), ev); ok {
		t.Errorf("R2 matched on wrong payload type")
	}
}

// ─── R3 ────────────────────────────────────────────────────

func TestR3_Match(t *testing.T) {
	r := NewR3()
	cases := []struct {
		name      string
		path      string
		wantMatch bool
		wantCat   string
	}{
		// Exact paths
		{"shadow", "/etc/shadow", true, "exact"},
		{"passwd", "/etc/passwd", true, "exact"},

		// Suffixes
		{"aws credentials", "/home/u/.aws/credentials", true, "suffix"},
		{"aws config", "/home/u/.aws/config", true, "suffix"},
		{"claude.json", "/home/u/.claude.json", true, "suffix"},
		{"netrc", "/home/u/.netrc", true, "suffix"},
		{"npmrc", "/home/u/.npmrc", true, "suffix"},

		// Substrings
		{"ssh id_rsa", "/home/u/.ssh/id_rsa", true, "substring"},
		{"ssh id_ed25519", "/home/u/.ssh/id_ed25519", true, "substring"},
		{"gpg keyring", "/home/u/.gnupg/secring.gpg", true, "substring"},
		{"kube config", "/home/u/.kube/config", true, "substring"},
		{"docker config", "/home/u/.docker/config.json", true, "substring"},
		{"gemini dir", "/home/u/.gemini/cred.json", true, "substring"},
		{"codex dir", "/home/u/.codex/auth.json", true, "substring"},
		{"claude credentials subpath", "/home/u/.claude/credentials/token", true, "substring"},

		// Basenames
		{".env", "/repo/.env", true, "basename"},
		{".env.local", "/repo/.env.local", true, "basename"},
		{".env.production", "/repo/.env.production", true, "basename"},
		{".env.staging", "/srv/app/.env.staging", true, "basename"},

		// Non-matches — including the .pub-key exclusion (public keys aren't credentials)
		{"ordinary file", "/home/u/Documents/notes.txt", false, ""},
		{"public ssh key", "/home/u/.ssh/id_rsa.pub", false, ""},
		{"public ed25519 key", "/home/u/.ssh/id_ed25519.pub", false, ""},
		{"tls cert", "/etc/ssl/cert.crt", false, ""},
		{"README", "/repo/README.md", false, ""},
		{"empty path", "", false, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := Event{
				Kind:    KindFileOpened,
				AgentID: "test-agent",
				PID:     1234,
				Payload: FileOpenPayload{Path: c.path, Mode: "read", Process: "claude"},
			}
			m, ok := r.Match(context.Background(), ev)
			if ok != c.wantMatch {
				t.Errorf("R3.Match(%q) ok = %v, want %v", c.path, ok, c.wantMatch)
				return
			}
			if ok {
				if m.RuleID != "R3" {
					t.Errorf("RuleID = %q, want R3", m.RuleID)
				}
				if m.Verdict != VerdictBlock {
					t.Errorf("Verdict = %v, want Block", m.Verdict)
				}
				if cat := m.Evidence["matched_category"]; cat != c.wantCat {
					t.Errorf("matched_category = %v, want %q", cat, c.wantCat)
				}
			}
		})
	}
}

func TestR3_WrongPayloadKind(t *testing.T) {
	r := NewR3()
	ev := Event{Kind: KindFileOpened, Payload: "not a FileOpenPayload"}
	if _, ok := r.Match(context.Background(), ev); ok {
		t.Errorf("R3 matched on wrong payload type")
	}
}

// ─── Engine integration ────────────────────────────────────

func TestEngine_AllThreeRulesRegistered(t *testing.T) {
	e := NewEngine()
	e.Register(NewR1())
	e.Register(NewR2())
	e.Register(NewR3())
	if e.Count() != 3 {
		t.Fatalf("Count() = %d, want 3", e.Count())
	}
	list := e.List()
	ids := map[string]bool{}
	for _, r := range list {
		ids[r.ID] = true
	}
	for _, id := range []string{"R1", "R2", "R3"} {
		if !ids[id] {
			t.Errorf("rule %s not registered", id)
		}
	}

	// Exec event → only R1 evaluates
	execEv := Event{Kind: KindExecObserved, Payload: ExecPayload{Command: repeatChain(10)}}
	if m := e.Evaluate(context.Background(), execEv); len(m) != 1 || m[0].RuleID != "R1" {
		t.Errorf("expected exactly R1 match on exec event, got %+v", m)
	}

	// FileChanged event → only R2 evaluates
	fcEv := Event{Kind: KindFileChanged, Payload: FileChangePayload{Path: "/home/u/.claude/settings.json", Op: FileOpModify}}
	if m := e.Evaluate(context.Background(), fcEv); len(m) != 1 || m[0].RuleID != "R2" {
		t.Errorf("expected exactly R2 match on filechange event, got %+v", m)
	}

	// FileOpened event → only R3 evaluates
	foEv := Event{Kind: KindFileOpened, Payload: FileOpenPayload{Path: "/home/u/.aws/credentials", Mode: "read"}}
	if m := e.Evaluate(context.Background(), foEv); len(m) != 1 || m[0].RuleID != "R3" {
		t.Errorf("expected exactly R3 match on fileopen event, got %+v", m)
	}
}
