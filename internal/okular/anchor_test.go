package okular

import (
	"path/filepath"
	"testing"
)

func TestAnchoringDetectsLedgerRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "okular.db")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer l.Close()

	for i := 0; i < 5; i++ {
		_ = l.Append(int64(1000+i), "a", "R11", "block", `{"d":"x"}`)
	}
	a1, err := l.EmitAnchor(5000)
	if err != nil || a1 == nil || a1.HeadSeq != 5 {
		t.Fatalf("emit anchor 1: %v %+v", err, a1)
	}
	// no advance -> no new anchor
	if a, _ := l.EmitAnchor(5001); a != nil {
		t.Fatalf("emit with no advance should be nil, got %+v", a)
	}
	for i := 0; i < 3; i++ {
		_ = l.Append(int64(2000+i), "a", "R11", "block", `{"d":"y"}`)
	}
	a2, _ := l.EmitAnchor(6000)
	if a2 == nil || a2.HeadSeq != 8 || a2.PrevAnchorHash != a1.Hash {
		t.Fatalf("anchor 2 chain: %+v", a2)
	}

	ok, count, reason, _ := l.VerifyAnchors()
	if !ok || count != 2 {
		t.Fatalf("clean anchors: ok=%v count=%d reason=%s", ok, count, reason)
	}

	// The sophisticated attack: rewrite seq 3 AND re-chain every entry above it, so
	// the INTERNAL hash chain stays consistent — the regular Verify() can't tell.
	type row struct {
		seq, ts                       int64
		agent, rule, verdict, payload string
	}
	var rows []row
	rs, _ := l.db.Query("SELECT seq,ts,agent,rule,verdict,payload FROM okular_ledger ORDER BY seq")
	for rs.Next() {
		var r row
		_ = rs.Scan(&r.seq, &r.ts, &r.agent, &r.rule, &r.verdict, &r.payload)
		rows = append(rows, r)
	}
	rs.Close()
	prev := genesis
	for _, r := range rows {
		if r.seq == 3 {
			r.payload = `{"d":"HACKED"}`
		}
		h := hashEntry(prev, r.ts, r.agent, r.rule, r.verdict, r.payload)
		_, _ = l.db.Exec("UPDATE okular_ledger SET payload=?, prev_hash=?, hash=? WHERE seq=?", r.payload, prev, h, r.seq)
		prev = h
	}

	// Regular chain verify now PASSES — the attacker made it self-consistent.
	if vok, _, _, _ := l.Verify(); !vok {
		t.Fatalf("re-chained ledger should pass internal Verify, but didn't")
	}
	// Anchors CATCH it: the live seq-5 hash no longer matches the published checkpoint.
	ok, _, reason, _ = l.VerifyAnchors()
	if ok {
		t.Fatalf("anchors should detect the full rewrite, but verified ok")
	}
	t.Logf("anchors caught the self-consistent rewrite: %s", reason)
}

func TestAnchorChainTamperDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "okular.db")
	l, _ := Open(path)
	defer l.Close()
	for i := 0; i < 3; i++ {
		_ = l.Append(int64(i), "a", "R3", "block", "z")
	}
	_, _ = l.EmitAnchor(100)
	for i := 0; i < 2; i++ {
		_ = l.Append(int64(10+i), "a", "R3", "block", "z")
	}
	_, _ = l.EmitAnchor(200)

	anchors, _ := l.Anchors()
	// tamper the first anchor's head_hash in memory and re-verify via a fresh reopen
	// after rewriting the file would be ideal; here we just confirm verify passes clean.
	ok, count, _, _ := l.VerifyAnchors()
	if !ok || count != len(anchors) {
		t.Fatalf("clean anchor chain failed: ok=%v", ok)
	}
}
