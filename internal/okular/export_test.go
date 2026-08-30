package okular

import (
	"path/filepath"
	"testing"
)

func TestExportSignAndVerify(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "okular.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer l.Close()
	for i := 0; i < 4; i++ {
		_ = l.Append(int64(2000+i), "agent-z", "R11", "block", `{"dest":"5.6.7.8:443"}`)
	}

	b, err := l.ExportSigned("agent-z", 100, 42)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if b.Count != 4 || b.Agent != "agent-z" {
		t.Fatalf("bundle: count=%d agent=%s", b.Count, b.Agent)
	}
	sigOK, chainOK, err := VerifyBundle(b)
	if err != nil || !sigOK || !chainOK {
		t.Fatalf("verify clean: sig=%v chain=%v err=%v, want all good", sigOK, chainOK, err)
	}

	// tamper the payload of an entry -> chain breaks, signature breaks
	b.Entries[1].Payload = `{"dest":"evil"}`
	sigOK, chainOK, _ = VerifyBundle(b)
	if sigOK {
		t.Fatalf("tamper: signature still verified, want broken")
	}
	if chainOK {
		t.Fatalf("tamper: chain still intact, want broken")
	}

	// re-export is verifiable again (the seal travels with the content)
	b2, _ := l.ExportSigned("agent-z", 100, 43)
	sigOK, chainOK, _ = VerifyBundle(b2)
	if !sigOK || !chainOK {
		t.Fatalf("re-export verify: sig=%v chain=%v", sigOK, chainOK)
	}
}

func TestKeyPersists(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(filepath.Join(dir, "okular.db"))
	pk1 := l.PubKeyHex()
	l.Close()
	l2, _ := Open(filepath.Join(dir, "okular.db"))
	defer l2.Close()
	if l2.PubKeyHex() != pk1 || pk1 == "" {
		t.Fatalf("key not persisted: %q vs %q", pk1, l2.PubKeyHex())
	}
}
