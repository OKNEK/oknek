package okular

import (
	"path/filepath"
	"testing"
)

func TestLedgerAppendVerifyTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "okular.db")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer l.Close()

	for i := 0; i < 5; i++ {
		if err := l.Append(int64(1000+i), "agent-x", "R11", "block", `{"dest":"1.2.3.4:443"}`); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	ok, broken, total, err := l.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok || total != 5 {
		t.Fatalf("clean chain: ok=%v broken=%d total=%d, want ok=true total=5", ok, broken, total)
	}

	// Tamper: alter the payload of seq 3 directly (simulating a log edit).
	if _, err := l.db.Exec("UPDATE okular_ledger SET payload = ? WHERE seq = ?", `{"dest":"evil"}`, 3); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	ok, broken, _, err = l.Verify()
	if err != nil {
		t.Fatalf("verify after tamper: %v", err)
	}
	if ok || broken != 3 {
		t.Fatalf("tamper detection: ok=%v broken=%d, want ok=false broken=3", ok, broken)
	}
}

func TestLedgerResumesChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "okular.db")
	l, _ := Open(path)
	_ = l.Append(1, "a", "R3", "block", "x")
	_ = l.Append(2, "a", "R3", "block", "y")
	seq1, head1 := l.Head()
	l.Close()

	// reopen — chain must resume, not restart.
	l2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()
	seq2, head2 := l2.Head()
	if seq2 != seq1 || head2 != head1 {
		t.Fatalf("resume: got seq=%d head=%s, want seq=%d head=%s", seq2, head2, seq1, head1)
	}
	if err := l2.Append(3, "a", "R3", "block", "z"); err != nil {
		t.Fatalf("append after resume: %v", err)
	}
	ok, _, total, _ := l2.Verify()
	if !ok || total != 3 {
		t.Fatalf("post-resume verify: ok=%v total=%d, want ok=true total=3", ok, total)
	}
}
