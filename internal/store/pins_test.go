package store

import (
	"path/filepath"
	"testing"
)

func TestPinsRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.UpsertPin(Pin{Path: "/w/.claude/settings.json", Dev: 7, Ino: 42, SHA256: "aa", Size: 10, PinnedAt: 100}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertPin(Pin{Path: "/w/.claude/skills/x.sh", Dev: 7, Ino: 43, SHA256: "bb", Size: 20, PinnedAt: 100}); err != nil {
		t.Fatal(err)
	}
	ps, err := s.Pins()
	if err != nil || len(ps) != 2 {
		t.Fatalf("pins: %v %d", err, len(ps))
	}
	if ps[0].Path != "/w/.claude/settings.json" || ps[0].Quarantined {
		t.Fatalf("row0: %+v", ps[0])
	}
	if err := s.MarkPinTampered("/w/.claude/skills/x.sh", 200, 7, 99); err != nil {
		t.Fatal(err)
	}
	ps, _ = s.Pins()
	if !ps[1].Quarantined || ps[1].TamperedAt != 200 || ps[1].Ino != 99 {
		t.Fatalf("tampered row: %+v", ps[1])
	}
	// re-pin (accept) clears quarantine
	if err := s.UpsertPin(Pin{Path: "/w/.claude/skills/x.sh", Dev: 7, Ino: 99, SHA256: "cc", Size: 21, PinnedAt: 300}); err != nil {
		t.Fatal(err)
	}
	ps, _ = s.Pins()
	if ps[1].Quarantined || ps[1].TamperedAt != 0 || ps[1].SHA256 != "cc" {
		t.Fatalf("re-pinned row: %+v", ps[1])
	}
	if err := s.UpdatePinInode("/w/.claude/settings.json", 7, 77); err != nil {
		t.Fatal(err)
	}
	ps, _ = s.Pins()
	if ps[0].Ino != 77 || ps[0].SHA256 != "aa" {
		t.Fatalf("moved row: %+v", ps[0])
	}
	if err := s.DeletePin("/w/.claude/settings.json"); err != nil {
		t.Fatal(err)
	}
	if ps, _ = s.Pins(); len(ps) != 1 {
		t.Fatalf("after delete: %d", len(ps))
	}
}

func TestCanariesRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.UpsertCanary(Canary{Path: "/root/.aws/credentials", Dev: 1, Ino: 2, SHA256: "dd", PlantedAt: 5}); err != nil {
		t.Fatal(err)
	}
	cs, err := s.Canaries()
	if err != nil || len(cs) != 1 || cs[0].Ino != 2 {
		t.Fatalf("canaries: %v %+v", err, cs)
	}
	if err := s.DeleteCanary("/root/.aws/credentials"); err != nil {
		t.Fatal(err)
	}
	if cs, _ = s.Canaries(); len(cs) != 0 {
		t.Fatalf("after delete: %d", len(cs))
	}
}
