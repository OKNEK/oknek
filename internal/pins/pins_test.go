package pins

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oknek/oknek/internal/store"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveTildeRelativeAndSubtree(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	write(t, filepath.Join(home, ".claude/settings.json"), "{}")
	write(t, filepath.Join(home, ".claude.json"), "{}")
	write(t, filepath.Join(cwd, ".claude/skills/a/SKILL.md"), "a")
	write(t, filepath.Join(cwd, ".claude/skills/a/run.sh"), "b")
	write(t, filepath.Join(cwd, ".claude/skills/b.md"), "c")
	write(t, filepath.Join(cwd, ".mcp.json"), "{}")
	_ = os.MkdirAll(filepath.Join(cwd, ".claude/hooks"), 0o755) // empty dir, no files

	got, err := Resolve([]string{"~/.claude/settings.json", "~/.claude.json", ".claude/skills/**", ".claude/hooks/**", ".mcp.json", ".cursor/mcp.json"}, home, []string{cwd})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(cwd, ".claude/skills/a/SKILL.md"),
		filepath.Join(cwd, ".claude/skills/a/run.sh"),
		filepath.Join(cwd, ".claude/skills/b.md"),
		filepath.Join(cwd, ".mcp.json"),
		filepath.Join(home, ".claude.json"),
		filepath.Join(home, ".claude/settings.json"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %d files %v, want %d", len(got), got, len(want))
	}
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			t.Errorf("missing %s", w)
		}
	}
}

func TestResolveDedupsAcrossCwds(t *testing.T) {
	cwd := t.TempDir()
	write(t, filepath.Join(cwd, ".mcp.json"), "{}")
	got, err := Resolve([]string{".mcp.json"}, "/nonexistent", []string{cwd, cwd})
	if err != nil || len(got) != 1 {
		t.Fatalf("dedup: %v %v", err, got)
	}
}

func TestHashFileStableAndInode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	write(t, p, "hello")
	s1, size, dev, ino, err := HashFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if size != 5 || ino == 0 {
		t.Fatalf("size=%d ino=%d dev=%d", size, ino, dev)
	}
	s2, _, _, _, _ := HashFile(p)
	if s1 != s2 || s1 != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("sha: %s", s1)
	}
	if _, _, _, _, err := HashFile(filepath.Dir(p)); err == nil {
		t.Fatal("directory must not hash")
	}
}

func TestKernelDev(t *testing.T) {
	// glibc encoding of major 8, minor 1 (sda1): (8<<8)|1 = 2049 -> kernel MKDEV (8<<20)|1
	if got := kernelDev(2049); got != (8<<20)|1 {
		t.Fatalf("kernelDev(2049)=%d", got)
	}
}

func TestSweepClassifies(t *testing.T) {
	dir := t.TempDir()
	same := filepath.Join(dir, "same")
	tamp := filepath.Join(dir, "tampered")
	gone := filepath.Join(dir, "gone")
	moved := filepath.Join(dir, "moved")
	for _, p := range []string{same, tamp, gone, moved} {
		write(t, p, "orig")
	}
	var pinsList []store.Pin
	for _, p := range []string{same, tamp, gone, moved} {
		sha, size, dev, ino, err := HashFile(p)
		if err != nil {
			t.Fatal(err)
		}
		pinsList = append(pinsList, store.Pin{Path: p, Dev: dev, Ino: ino, SHA256: sha, Size: size})
	}
	write(t, tamp, "evil")                                 // content change, same inode
	_ = os.Remove(gone)                                    // missing
	write(t, moved+".tmp", "orig")                         // atomic save: same bytes, new inode
	if err := os.Rename(moved+".tmp", moved); err != nil { //
		t.Fatal(err)
	}
	ch := Sweep(pinsList)
	kinds := map[string]string{}
	for _, c := range ch {
		kinds[c.Path] = c.Kind
	}
	if kinds[same] != "" || kinds[tamp] != "tampered" || kinds[gone] != "missing" || kinds[moved] != "moved" {
		t.Fatalf("kinds: %+v", kinds)
	}
	for _, c := range ch {
		if c.Kind == "tampered" && (c.NewSHA == "" || c.Ino == 0) {
			t.Fatalf("tampered change lacks new sha/inode: %+v", c)
		}
	}
}
