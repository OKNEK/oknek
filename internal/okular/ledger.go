// Package okular is the tamper-proof flight recorder — the Audit pillar. It keeps a
// hash-chained, append-only ledger of every action an agent took at the kernel, so
// the record is provably complete and any alteration is detectable. The chain: each
// entry's hash = SHA-256(prev_hash || the entry). Break, edit, or delete any entry
// and Verify() finds the exact seq where the chain snaps.
package okular

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS okular_ledger (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    agent     TEXT,
    rule      TEXT,
    verdict   TEXT,
    payload   TEXT,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_okular_agent ON okular_ledger(agent);
`

// genesis is the chain's anchor — the prev_hash of the very first entry.
const genesis = "okular-genesis-v1"

// Ledger is the append-only, hash-chained audit log.
type Ledger struct {
	lastAnchor *Anchor // newest published anchor (cache for Okredo Attest)
	db         *sql.DB
	path       string
	mu         sync.Mutex
	lastHash   string
	lastSeq    int64
	priv       ed25519.PrivateKey // signing key for sealed exports + anchors
	pub        ed25519.PublicKey
	// anchoring: periodic signed, chained head-hash checkpoints to an append-only file
	anchorPath    string
	anchorSeq     int64
	anchorHash    string
	anchorHeadSeq int64        // ledger head_seq of the last anchor (skip re-anchoring if unchanged)
	shipper       *WORMShipper // optional off-box WORM escrow for anchors
}

// SetShipper enables off-box WORM escrow: each emitted anchor is also PUT to the
// configured Object-Lock store. nil disables it (local-only anchoring).
func (l *Ledger) SetShipper(s *WORMShipper) { l.shipper = s }

// Entry is one row of the ledger.
type Entry struct {
	Seq      int64  `json:"seq"`
	TS       int64  `json:"ts"`
	Agent    string `json:"agent"`
	Rule     string `json:"rule"`
	Verdict  string `json:"verdict"`
	Payload  string `json:"payload"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Open opens (or creates) the ledger and resumes the hash chain from the last entry.
func Open(path string) (*Ledger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir okular dir: %w", err)
	}
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open okular ledger: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("okular schema: %w", err)
	}
	l := &Ledger{db: db, path: path, lastHash: genesis}
	// resume: load the head (seq, hash) so new appends chain onto the existing log.
	var seq sql.NullInt64
	var h sql.NullString
	_ = db.QueryRow("SELECT seq, hash FROM okular_ledger ORDER BY seq DESC LIMIT 1").Scan(&seq, &h)
	if seq.Valid {
		l.lastSeq = seq.Int64
		l.lastHash = h.String
	}
	if err := l.loadOrCreateKey(path + ".key"); err != nil {
		db.Close()
		return nil, fmt.Errorf("okular signing key: %w", err)
	}
	l.anchorPath = path + ".anchors"
	l.loadAnchorHead()
	return l, nil
}

// Close closes the ledger.
func (l *Ledger) Close() error { return l.db.Close() }

// hashEntry computes the chain hash for an entry given the prior hash.
func hashEntry(prev string, ts int64, agent, rule, verdict, payload string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x1f%d\x1f%s\x1f%s\x1f%s\x1f%s",
		prev, ts, agent, rule, verdict, payload)))
	return hex.EncodeToString(sum[:])
}

// Append seals one action into the chain. Safe for concurrent callers.
func (l *Ledger) Append(ts int64, agent, rule, verdict, payload string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := l.lastHash
	h := hashEntry(prev, ts, agent, rule, verdict, payload)
	_, err := l.db.Exec(
		"INSERT INTO okular_ledger (ts, agent, rule, verdict, payload, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
		ts, agent, rule, verdict, payload, prev, h)
	if err != nil {
		return err
	}
	l.lastHash = h
	l.lastSeq++
	return nil
}

// Head returns the current chain head (seq, hash).
func (l *Ledger) Head() (int64, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastSeq, l.lastHash
}

// Verify walks the whole chain and confirms integrity. Returns ok=false with the
// seq where the chain first breaks if any entry was altered, deleted, or reordered.
func (l *Ledger) Verify() (ok bool, brokenSeq int64, total int64, err error) {
	rows, err := l.db.Query("SELECT seq, ts, agent, rule, verdict, payload, prev_hash, hash FROM okular_ledger ORDER BY seq ASC")
	if err != nil {
		return false, 0, 0, err
	}
	defer rows.Close()
	prev := genesis
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Seq, &e.TS, &e.Agent, &e.Rule, &e.Verdict, &e.Payload, &e.PrevHash, &e.Hash); err != nil {
			return false, 0, total, err
		}
		total++
		want := hashEntry(prev, e.TS, e.Agent, e.Rule, e.Verdict, e.Payload)
		// the stored prev_hash must match the running chain AND the stored hash must
		// equal the recomputed hash of (prev || entry). Either mismatch = tampered.
		if e.PrevHash != prev || e.Hash != want {
			return false, e.Seq, total, nil
		}
		prev = e.Hash
	}
	return true, 0, total, rows.Err()
}

// Timeline returns up to limit entries (most recent first), optionally filtered by
// agent — the replay of what an agent did.
func (l *Ledger) Timeline(agent string, limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 100
	}
	var (
		rows *sql.Rows
		err  error
	)
	if agent != "" {
		rows, err = l.db.Query("SELECT seq, ts, agent, rule, verdict, payload, prev_hash, hash FROM okular_ledger WHERE agent = ? ORDER BY seq DESC LIMIT ?", agent, limit)
	} else {
		rows, err = l.db.Query("SELECT seq, ts, agent, rule, verdict, payload, prev_hash, hash FROM okular_ledger ORDER BY seq DESC LIMIT ?", limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Seq, &e.TS, &e.Agent, &e.Rule, &e.Verdict, &e.Payload, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
