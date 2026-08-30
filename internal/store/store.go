// Package store wraps the daemon's local SQLite event + baseline + meta tables.
//
// Backed by modernc.org/sqlite (pure-Go SQLite, no CGO) so oknekd remains a
// single static binary on every target architecture.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const schemaSQL = `
CREATE TABLE IF NOT EXISTS events (
    id           TEXT PRIMARY KEY,
    ts           INTEGER NOT NULL,
    agent_id     TEXT,
    rule_id      TEXT,
    verdict      TEXT,
    payload_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts    ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id);
CREATE INDEX IF NOT EXISTS idx_events_rule  ON events(rule_id);

CREATE TABLE IF NOT EXISTS baseline (
    agent_id     TEXT NOT NULL,
    feature      TEXT NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    observed_at  INTEGER NOT NULL,
    PRIMARY KEY (agent_id, feature)
);
CREATE INDEX IF NOT EXISTS idx_baseline_observed ON baseline(observed_at);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pins (
    path        TEXT PRIMARY KEY,
    dev         INTEGER NOT NULL,
    ino         INTEGER NOT NULL,
    sha256      TEXT NOT NULL,
    size        INTEGER NOT NULL,
    pinned_at   INTEGER NOT NULL,
    tampered_at INTEGER NOT NULL DEFAULT 0,
    quarantined INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS canaries (
    path       TEXT PRIMARY KEY,
    dev        INTEGER NOT NULL,
    ino        INTEGER NOT NULL,
    sha256     TEXT NOT NULL,
    planted_at INTEGER NOT NULL
);
`

// Store is the local event + baseline store backed by SQLite.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens (or creates) the SQLite database at path and applies the schema.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir db dir: %w", err)
	}
	// WAL + NORMAL synchronous = fast, safe-enough for our event-log use case.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), schemaSQL); err != nil {
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	s := &Store{db: db, path: path}
	if err := s.setMeta("schema_version", "1"); err != nil {
		return nil, err
	}
	if err := s.setMetaIfMissing("install_id", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return nil, err
	}
	return s, nil
}

// Close shuts down the underlying database connection pool.
func (s *Store) Close() error { return s.db.Close() }

// Path returns the on-disk SQLite path.
func (s *Store) Path() string { return s.path }

// FileSize returns the SQLite DB file size in bytes (best-effort).
func (s *Store) FileSize() int64 {
	info, err := os.Stat(s.path)
	if err != nil {
		return 0
	}
	return info.Size()
}

// EventCount returns the number of rows in events.
func (s *Store) EventCount() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&n)
	return n, err
}

// Meta returns a single meta value by key, or "" if missing.
func (s *Store) Meta(key string) string {
	var v string
	_ = s.db.QueryRow("SELECT value FROM meta WHERE key = ?", key).Scan(&v)
	return v
}

func (s *Store) setMeta(key, value string) error {
	_, err := s.db.Exec(
		"INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value,
	)
	return err
}

func (s *Store) setMetaIfMissing(key, value string) error {
	_, err := s.db.Exec(
		"INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)",
		key, value,
	)
	return err
}
