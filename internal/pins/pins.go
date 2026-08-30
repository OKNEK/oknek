// Package pins is R22's userspace half: resolve the agent supply-chain artifacts
// (skills, hooks, settings, MCP manifests) to concrete files, hash them, and re-check
// them on a sweep. The kernel half (oknek_pinned_inodes / oknek_quarantine_inodes)
// denies in-place writes to a pin and any open/exec of an artifact this package
// found tampered. Pure functions: no BPF, no store — testable anywhere.
package pins

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/oknek/oknek/internal/store"
)

// Resolve expands globs to regular files. "~/x" → home/x; a relative pattern is
// joined onto every cwd; a trailing "/**" means every file below that directory
// (the only "**" form supported — it is what agent artifact trees need). Missing
// paths are skipped, never errors. Result is sorted and de-duplicated.
func Resolve(globs []string, home string, cwds []string) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	add := func(p string) {
		if _, ok := seen[p]; ok {
			return
		}
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	for _, g := range globs {
		var roots []string
		switch {
		case strings.HasPrefix(g, "~/"):
			roots = []string{filepath.Join(home, g[2:])}
		case filepath.IsAbs(g):
			roots = []string{g}
		default:
			for _, c := range cwds {
				roots = append(roots, filepath.Join(c, g))
			}
		}
		for _, r := range roots {
			if strings.HasSuffix(r, "/**") {
				dir := strings.TrimSuffix(r, "/**")
				_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
					if err != nil {
						return nil // unreadable subtree: skip, keep going
					}
					if d.Type().IsRegular() {
						add(p)
					}
					return nil
				})
				continue
			}
			matches, err := filepath.Glob(r)
			if err != nil {
				return nil, err
			}
			for _, m := range matches {
				add(m)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// HashFile returns the SHA-256, size and kernel-form (dev, ino) of a regular file.
// dev is (major<<20)|minor — the form inode->i_sb->s_dev has when the BPF hook
// reads it, NOT glibc's st_dev encoding.
func HashFile(path string) (sha string, size int64, dev uint32, ino uint64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, 0, 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", 0, 0, 0, err
	}
	if !st.Mode().IsRegular() {
		return "", 0, 0, 0, errors.New("pins: not a regular file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", 0, 0, 0, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return "", 0, 0, 0, errors.New("pins: no stat_t")
	}
	dev = kernelDev(uint64(sys.Dev))
	return hex.EncodeToString(h.Sum(nil)), st.Size(), dev, uint64(sys.Ino), nil
}

// kernelDev re-encodes a userspace dev_t into the kernel's MKDEV(major, minor) form.
func kernelDev(d uint64) uint32 {
	major := uint32((d >> 8) & 0xfff)
	minor := uint32((d & 0xff) | ((d >> 12) & 0xfff00))
	return (major << 20) | minor
}

// Change is one sweep finding.
//
//	tampered — content hash differs from the pin (quarantine it)
//	missing  — file is gone (alert only)
//	moved    — same content, new inode (editor atomic save; re-point the pin silently)
type Change struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	OldSHA string `json:"old_sha,omitempty"`
	NewSHA string `json:"new_sha,omitempty"`
	Dev    uint32 `json:"dev,omitempty"`
	Ino    uint64 `json:"ino,omitempty"`
	Size   int64  `json:"size,omitempty"`
}

// Sweep re-hashes every pin and classifies what changed. Pins that are already
// quarantined are still re-checked so a restore-to-original can be surfaced as
// "moved"/unchanged by the caller (it re-pins on accept regardless).
func Sweep(pinned []store.Pin) []Change {
	var out []Change
	for _, p := range pinned {
		sha, size, dev, ino, err := HashFile(p.Path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				out = append(out, Change{Path: p.Path, Kind: "missing", OldSHA: p.SHA256})
			}
			continue
		}
		switch {
		case sha != p.SHA256:
			out = append(out, Change{Path: p.Path, Kind: "tampered", OldSHA: p.SHA256, NewSHA: sha, Dev: dev, Ino: ino, Size: size})
		case dev != p.Dev || ino != p.Ino:
			out = append(out, Change{Path: p.Path, Kind: "moved", OldSHA: p.SHA256, NewSHA: sha, Dev: dev, Ino: ino, Size: size})
		}
	}
	return out
}
