package okular

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const anchorGenesis = "okular-anchor-genesis-v1"

// Anchor is a signed, chained checkpoint of the ledger head, published to an
// append-only sink. Anchors chain to each other (prev_anchor_hash), so the SEQUENCE
// of checkpoints is itself tamper-evident. Because anchors are emitted over time to
// an external sink (file + daemon log/journald), an attacker who later rewrites the
// whole ledger.db — even re-signing every entry — cannot make the rewritten history
// match the head-hashes already published in older anchors.
type Anchor struct {
	Seq            int64  `json:"anchor_seq"`
	TS             int64  `json:"ts"`
	HeadSeq        int64  `json:"head_seq"`
	HeadHash       string `json:"head_hash"`
	PrevAnchorHash string `json:"prev_anchor_hash"`
	Hash           string `json:"hash"`
	Signature      string `json:"signature"`
}

func anchorContentHash(prev string, seq, ts, headSeq int64, headHash string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x1f%d\x1f%d\x1f%d\x1f%s", prev, seq, ts, headSeq, headHash)))
	return hex.EncodeToString(sum[:])
}

// loadAnchorHead reads the append-only anchor file to resume the anchor chain.
func (l *Ledger) loadAnchorHead() {
	l.anchorSeq = 0
	l.anchorHash = anchorGenesis
	l.anchorHeadSeq = 0
	f, err := os.Open(l.anchorPath)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var a Anchor
		if json.Unmarshal(sc.Bytes(), &a) == nil && a.Hash != "" {
			l.anchorSeq = a.Seq
			l.anchorHash = a.Hash
			l.anchorHeadSeq = a.HeadSeq
		}
	}
}

// EmitAnchor appends a signed, chained checkpoint of the current ledger head to the
// append-only anchor file. Returns nil (no error) if the ledger hasn't advanced
// since the last anchor — nothing new to checkpoint.
func (l *Ledger) EmitAnchor(ts int64) (*Anchor, error) {
	l.mu.Lock()
	headSeq, headHash := l.lastSeq, l.lastHash
	if headSeq == 0 || headSeq == l.anchorHeadSeq {
		l.mu.Unlock()
		return nil, nil
	}
	a := Anchor{
		Seq: l.anchorSeq + 1, TS: ts, HeadSeq: headSeq, HeadHash: headHash,
		PrevAnchorHash: l.anchorHash,
	}
	a.Hash = anchorContentHash(a.PrevAnchorHash, a.Seq, a.TS, a.HeadSeq, a.HeadHash)
	hb, _ := hex.DecodeString(a.Hash)
	a.Signature = hex.EncodeToString(ed25519.Sign(l.priv, hb))

	line, _ := json.Marshal(&a)
	f, err := os.OpenFile(l.anchorPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		l.mu.Unlock()
		return nil, err
	}
	_, werr := f.Write(append(line, '\n'))
	f.Close()
	if werr != nil {
		l.mu.Unlock()
		return nil, werr
	}
	l.anchorSeq = a.Seq
	l.anchorHash = a.Hash
	l.anchorHeadSeq = a.HeadSeq
	shipper := l.shipper
	l.mu.Unlock()
	// Off-box WORM escrow: PUT the anchor to immutable storage — OUTSIDE the lock. The
	// chain state is already committed; shipping under l.mu would block Append()/Head()
	// (Append runs on the single ringbuf drain goroutine) for up to the HTTP timeout on a
	// slow/unreachable escrow → dropped audit events. On ship failure the anchor is local
	// but its seq is MISSING off-box (the verifier's gap/trailing-stop check sees it); the
	// returned error makes the daemon log it loudly.
	if shipper != nil {
		if err := shipper.Ship(&a); err != nil {
			return &a, err
		}
	}
	l.mu.Lock()
	l.lastAnchor = &a
	l.mu.Unlock()
	return &a, nil
}

// LatestAnchor returns the newest published anchor (nil if none yet). Cached after
// the first read; EmitAnchor refreshes it.
func (l *Ledger) LatestAnchor() *Anchor {
	l.mu.Lock()
	cached := l.lastAnchor
	l.mu.Unlock()
	if cached != nil {
		return cached
	}
	as, err := l.Anchors()
	if err != nil || len(as) == 0 {
		return nil
	}
	a := as[len(as)-1]
	l.mu.Lock()
	l.lastAnchor = &a
	l.mu.Unlock()
	return &a
}

// Anchors returns all published anchors in order.
func (l *Ledger) Anchors() ([]Anchor, error) {
	f, err := os.Open(l.anchorPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Anchor
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var a Anchor
		if json.Unmarshal(sc.Bytes(), &a) == nil && a.Hash != "" {
			out = append(out, a)
		}
	}
	return out, sc.Err()
}

// VerifyAnchors checks the full anchor chain AND that the live ledger still agrees
// with every published checkpoint. Returns ok=false with a reason if (a) an anchor's
// signature or chain link is broken, or (b) the ledger entry at an anchored head_seq
// no longer has the anchored head_hash — i.e. the ledger was rewritten after that
// checkpoint was published.
func (l *Ledger) VerifyAnchors() (ok bool, count int, reason string, err error) {
	anchors, err := l.Anchors()
	if err != nil {
		return false, 0, "", err
	}
	prev := anchorGenesis
	for _, a := range anchors {
		count++
		want := anchorContentHash(a.PrevAnchorHash, a.Seq, a.TS, a.HeadSeq, a.HeadHash)
		if a.PrevAnchorHash != prev || a.Hash != want {
			return false, count, fmt.Sprintf("anchor #%d chain/hash mismatch", a.Seq), nil
		}
		sig, _ := hex.DecodeString(a.Signature)
		hb, _ := hex.DecodeString(a.Hash)
		if !ed25519.Verify(l.pub, hb, sig) {
			return false, count, fmt.Sprintf("anchor #%d bad signature", a.Seq), nil
		}
		// the ledger entry at the anchored head_seq must still carry the anchored hash.
		// A DELETED row (ErrNoRows) is truncation; any other DB error fails CLOSED — never
		// silently skip (the old `e == nil` guard let a truncation/locked-db read pass).
		var h string
		switch e := l.db.QueryRow("SELECT hash FROM okular_ledger WHERE seq = ?", a.HeadSeq).Scan(&h); {
		case e == nil:
			if h != a.HeadHash {
				return false, count, fmt.Sprintf("LEDGER REWRITTEN below anchor #%d (seq %d): live hash != anchored hash", a.Seq, a.HeadSeq), nil
			}
		case errors.Is(e, sql.ErrNoRows):
			return false, count, fmt.Sprintf("LEDGER TRUNCATED below anchor #%d (seq %d missing)", a.Seq, a.HeadSeq), nil
		default:
			return false, count, fmt.Sprintf("cannot read ledger seq %d: %v", a.HeadSeq, e), nil
		}
		prev = a.Hash
	}
	return true, count, "", nil
}
