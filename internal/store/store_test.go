package store

import (
	"path/filepath"
	"testing"
)

func TestOpen_CreatesSchemaAndMeta(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if s.Meta("schema_version") != "1" {
		t.Errorf("schema_version meta missing or wrong: %q", s.Meta("schema_version"))
	}
	if s.Meta("install_id") == "" {
		t.Errorf("install_id was not set on first open")
	}

	count, err := s.EventCount()
	if err != nil {
		t.Fatalf("EventCount: %v", err)
	}
	if count != 0 {
		t.Errorf("fresh store should have 0 events, got %d", count)
	}
	if s.FileSize() == 0 {
		t.Errorf("FileSize should be > 0 after Open")
	}
}

func TestOpen_IdempotentSchema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s1, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open 1: %v", err)
	}
	installID := s1.Meta("install_id")
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open 2: %v", err)
	}
	defer s2.Close()
	if got := s2.Meta("install_id"); got != installID {
		t.Errorf("install_id changed across re-open: %q → %q", installID, got)
	}
}
