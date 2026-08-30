package okular

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// RemoteVerifyResult is the outcome of checking the off-box WORM escrow.
type RemoteVerifyResult struct {
	Anchors    int       // anchors found in the escrow
	NewestSeq  int64     // highest anchor seq seen
	NewestTime time.Time // server-side time the newest anchor was escrowed (staleness check)
	OK         bool      // true iff Anchors>0 and no issues
	Issues     []string  // every problem found (chain/sig/gap/backfill/divergence)
}

// VerifyRemote pulls the escrowed anchors from the WORM store and checks them as the
// IMMUTABLE source of truth against the local ledger. It catches:
//   - broken anchor chain or bad signature (escrow not authentic),
//   - a GAP in anchor seq (a blocked ship / hidden object — enforcement may have been off),
//   - BACK-DATING (object escrowed far later than its claimed ts — a root who read the key
//     and minted an old-looking "nothing happened" anchor),
//   - LEDGER REWRITE (the local entry at an escrowed head_seq no longer carries the
//     escrowed head_hash).
//
// Run it from a TRUSTED machine (read-only bucket creds + a copy of the ledger/key), or
// on-box — either way the S3 anchors are immutable, so root can't fake what it returns.
// Requires SetShipper. maxSkew tolerates normal emit→ship lag + clock skew.
func (l *Ledger) VerifyRemote(maxSkew time.Duration) (RemoteVerifyResult, error) {
	if l.shipper == nil {
		return RemoteVerifyResult{}, fmt.Errorf("no WORM shipper configured (okular.worm)")
	}
	l.mu.Lock()
	localHead := l.anchorSeq // local anchor chain head, for trailing-ship-stop detection
	l.mu.Unlock()
	vers, err := l.shipper.ListVersions()
	if err != nil {
		return RemoteVerifyResult{}, err
	}
	// Group versions by key: the (single) locked anchor version + whether a delete-marker
	// hides it. Enumerating VERSIONS (not just current objects) is what catches a root who
	// delete-markers a trailing anchor AND rewrites local .anchors to match — the locked
	// version still exists off-box, so we recover it and flag the delete-marker as tamper.
	type rec struct {
		key, versionId string
		lm             time.Time
		deleted        bool
	}
	byKey := map[string]*rec{}
	var keys []string
	for _, v := range vers {
		r := byKey[v.Key]
		if r == nil {
			r = &rec{key: v.Key}
			byKey[v.Key] = r
			keys = append(keys, v.Key)
		}
		if v.IsDeleteMarker {
			r.deleted = true
		} else {
			r.versionId = v.VersionId
			r.lm = v.LastModified
		}
	}
	sort.Strings(keys) // zero-padded seq keys -> lexicographic == numeric

	var res RemoteVerifyResult
	prev := anchorGenesis
	var expectSeq int64 = 1
	for _, k := range keys {
		o := byKey[k]
		if o.versionId == "" {
			// only a delete-marker, no recoverable locked version (Object-Lock should
			// prevent destruction, but never treat a vanished anchor as "fine").
			res.Issues = append(res.Issues, fmt.Sprintf("anchor object %s has NO recoverable version (only a delete-marker) — destroyed?", k))
			continue
		}
		got, err := l.shipper.GetVersion(o.key, o.versionId)
		if err != nil {
			res.Issues = append(res.Issues, fmt.Sprintf("get %s@%s: %v", o.key, o.versionId, err))
			continue
		}
		var a Anchor
		if json.Unmarshal(got.Body, &a) != nil {
			res.Issues = append(res.Issues, "unparseable anchor: "+o.key)
			continue
		}
		res.Anchors++
		if a.Seq > res.NewestSeq {
			res.NewestSeq = a.Seq
			res.NewestTime = o.lm
		}
		if o.deleted {
			res.Issues = append(res.Issues, fmt.Sprintf("anchor #%d HIDDEN by a delete-marker (tamper) — recovered from the locked version", a.Seq))
		}

		if a.Seq != expectSeq {
			res.Issues = append(res.Issues, fmt.Sprintf("GAP: expected anchor seq %d, got %d (%s) — a ship was blocked or an object hidden/deleted", expectSeq, a.Seq, o.key))
		}
		want := anchorContentHash(a.PrevAnchorHash, a.Seq, a.TS, a.HeadSeq, a.HeadHash)
		if a.PrevAnchorHash != prev || a.Hash != want {
			res.Issues = append(res.Issues, fmt.Sprintf("anchor #%d chain/hash mismatch", a.Seq))
		}
		sig, _ := hex.DecodeString(a.Signature)
		hb, _ := hex.DecodeString(a.Hash)
		if !ed25519.Verify(l.pub, hb, sig) {
			res.Issues = append(res.Issues, fmt.Sprintf("anchor #%d bad signature", a.Seq))
		}
		// back-dating: the object should be escrowed at ~its claimed ts (emit→ship is
		// immediate). A large positive Δ (escrowed long AFTER the claimed time) = forged.
		// If the escrow timestamp is missing/unparseable we CANNOT verify -> fail closed
		// (inability to check must never read as "no back-dating").
		if o.lm.IsZero() {
			res.Issues = append(res.Issues, fmt.Sprintf("anchor #%d: missing/unparseable escrow timestamp — cannot verify back-dating", a.Seq))
		} else {
			claimed := time.Unix(0, a.TS)
			if d := o.lm.Sub(claimed); d > maxSkew {
				res.Issues = append(res.Issues, fmt.Sprintf("anchor #%d BACK-DATED: claims ts %s, escrowed %s (Δ %s > %s)",
					a.Seq, claimed.UTC().Format(time.RFC3339), o.lm.UTC().Format(time.RFC3339), d.Round(time.Second), maxSkew))
			}
		}
		// ledger rewrite OR truncation: the local entry at the escrowed head_seq must still
		// carry the escrowed head_hash. A DELETED row (ErrNoRows) is truncation, not absence
		// of a problem; any other DB error fails CLOSED (never silently "all clear").
		if l.db != nil {
			var h string
			switch e := l.db.QueryRow("SELECT hash FROM okular_ledger WHERE seq = ?", a.HeadSeq).Scan(&h); {
			case e == nil:
				if h != a.HeadHash {
					res.Issues = append(res.Issues, fmt.Sprintf("LEDGER REWRITTEN below escrowed anchor #%d (head seq %d): local hash != escrowed hash", a.Seq, a.HeadSeq))
				}
			case errors.Is(e, sql.ErrNoRows):
				res.Issues = append(res.Issues, fmt.Sprintf("LEDGER TRUNCATED/MISSING below escrowed anchor #%d (head seq %d not present locally)", a.Seq, a.HeadSeq))
			default:
				res.Issues = append(res.Issues, fmt.Sprintf("cannot read local ledger seq %d: %v (fail-closed)", a.HeadSeq, e))
			}
		}
		prev = a.Hash
		expectSeq = a.Seq + 1
	}
	// Trailing ship-stop / hidden tail: the interior gap check above can't see a MISSING
	// TAIL. If the local ledger knows about more anchors than the escrow holds, shipping
	// was stopped / egress blocked / trailing objects hidden — at the attacker's exact
	// target window (newest events). localHead is the local anchor chain head.
	if localHead > res.NewestSeq {
		res.Issues = append(res.Issues, fmt.Sprintf("TRAILING SHIP-STOP: local anchor head is #%d but escrow's newest is #%d — %d trailing anchor(s) not escrowed (ship stopped / egress blocked / tail hidden)",
			localHead, res.NewestSeq, localHead-res.NewestSeq))
	}
	// Control-event integrity. The escrowed anchors above prove the local ledger wasn't
	// rewritten/truncated below an escrowed head, so the control-event stream is trustworthy
	// to replay here. Apply the disarm-pairing rule: a DISARMED with no preceding
	// DISARM-AUTHORIZED is a silent off-switch. A read error fails CLOSED.
	if cok, cissues, _, cerr := l.VerifyControlEvents(); cerr != nil {
		res.Issues = append(res.Issues, fmt.Sprintf("control-event check failed: %v (fail-closed)", cerr))
	} else if !cok {
		res.Issues = append(res.Issues, cissues...)
	}
	res.OK = res.Anchors > 0 && len(res.Issues) == 0
	return res, nil
}
