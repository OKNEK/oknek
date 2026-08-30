//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// selfID mirrors `struct oknek_selfid` in oknek_lsm.c (16 bytes: ino u64, dev u32,
// enforce u32). cilium/ebpf marshals it into the single-entry oknek_self_id ARRAY.
type selfID struct {
	Ino     uint64
	Dev     uint32
	Enforce uint32
}

// ArmSelfGuard writes the bpffs pin dir's own (dev, ino) into the BPF map, arming
// R20: from this point the inode_unlink/inode_rename hooks deny any attempt to rm
// or mv oknek's own pins — so a root insider can't detach enforcement by deleting
// the pin. enforce=false arms it in OBSERVE (log the DISABLE attempt, allow it);
// enforce=true blocks. Until this is called, self_id is {0,0,0} and the guard is
// fail-OPEN (zero behavior change) — anti-unpin is strictly opt-in.
//
// CRITICAL: the kernel's inode->i_sb->s_dev is MKDEV(major,minor) = (major<<20)|minor,
// NOT glibc's split st_dev encoding. We decode st.Dev to major/minor (glibc) and
// re-encode with the KERNEL formula so the value matches BPF_CORE_READ(s_dev). Get
// this wrong and the (dev,ino) compare silently never matches -> guard is a no-op.
func (l *Loader) ArmSelfGuard(enforce bool) error {
	if l.selfID == nil {
		return errors.New("oknek_self_id map not loaded")
	}
	pinDir := PinDir()
	var st syscall.Stat_t
	if err := syscall.Stat(pinDir, &st); err != nil {
		return fmt.Errorf("stat pin dir %s: %w", pinDir, err)
	}
	kdev := KernelDev(uint64(st.Dev))
	v := selfID{Ino: st.Ino, Dev: kdev}
	if enforce {
		v.Enforce = 1
	}
	var key uint32 = 0
	if err := l.selfID.Put(key, v); err != nil {
		return fmt.Errorf("write self_id: %w", err)
	}
	// When enforcing, FREEZE the self_id map: otherwise a CAP_BPF root can
	// `bpftool map update` enforce=0 from userspace and disable the guard in one
	// command (verified open in-band vector). Freeze makes the map immutable from
	// userspace (the BPF prog still reads it). Best-effort (not all kernels).
	// Irreversible for the map's lifetime: removing an armed enforce guard then
	// requires a reboot — the deliberate cost of "root can't flip it off". Only on
	// enforce; observe stays adjustable (flipping observe->enforce is not an attack).
	if enforce {
		if err := l.selfID.Freeze(); err != nil {
			fmt.Fprintf(os.Stderr, "self_guard: self_id freeze failed (map-write disable vector stays open): %v\n", err)
		}
	}
	return nil
}

// KernelDev converts a glibc st_dev into the kernel's internal dev_t encoding
// (major<<20 | minor) that BPF reads from inode->i_sb->s_dev.
func KernelDev(stDev uint64) uint32 {
	return uint32((unix.Major(stDev) << 20) | unix.Minor(stDev))
}

// SelfGuardArmed reports the current armed state (initialised?, enforcing?) by
// reading back the self_id map — used by the doctor preflight and the heartbeat.
func (l *Loader) SelfGuardArmed() (initialised, enforcing bool) {
	if l.selfID == nil {
		return false, false
	}
	var v selfID
	var key uint32 = 0
	if err := l.selfID.Lookup(key, &v); err != nil {
		return false, false
	}
	initialised = v.Ino != 0 || v.Dev != 0
	enforcing = v.Enforce != 0
	return initialised, enforcing
}

// selfPinLinks is the full set of pinned LSM/tracepoint links keyed by pin name —
// the single source of truth shared by the initial pin loop's intent and the
// watchdog's heal.
func (l *Loader) selfPinLinks() map[string]link.Link {
	return map[string]link.Link{
		"file_open": l.lnk, "socket_connect": l.lnk2, "sendmsg": l.lnk5,
		"ptrace": l.lnk6, "exec": l.lnk7, "bind": l.lnk8, "bpf": l.lnk9,
		"kmod": l.lnk10, "mount": l.lnk11, "inode_unlink": l.lnk12,
		"inode_rename": l.lnk13, "sb_umount": l.lnk14, "fork": l.lnk3, "exit": l.lnk4,
	}
}

// CountPins returns how many of oknek's links are currently pinned on bpffs. The
// doctor preflight and heartbeat use this; a drop is the signal the watchdog heals.
func (l *Loader) CountPins() int {
	pinDir := PinDir()
	n := 0
	for name, lk := range l.selfPinLinks() {
		if lk == nil {
			continue
		}
		if _, err := os.Stat(pinDir + "/" + name); err == nil {
			n++
		}
	}
	return n
}

// HealPins is the watchdog's in-process self-heal: if a pin file was removed while
// the daemon is alive (e.g. root rm'd it and R20 was in observe, or before R20 was
// armed), re-pin the still-live link object. Returns how many pins it restored.
// (Daemon *death* is covered by systemd Restart=always, which re-runs Start and
// re-attaches everything fresh.)
func (l *Loader) HealPins() (healed int) {
	pinDir := PinDir()
	for name, lk := range l.selfPinLinks() {
		if lk == nil {
			continue
		}
		pp := pinDir + "/" + name
		if _, err := os.Stat(pp); err == nil {
			continue // still pinned
		}
		// The pin file is gone, but the link's internal pinnedPath may still equal pp, so
		// a bare Pin(pp) short-circuits (cilium: currentPath==newPath -> no-op) and never
		// re-creates it — yet returns nil, which previously logged a phantom "re-pinned".
		// Unpin first to clear the stale path (Remove of the already-gone file is nil), then
		// Pin actually issues BPF_OBJ_PIN. Propagate the real error.
		_ = lk.Unpin()
		if err := lk.Pin(pp); err != nil {
			fmt.Fprintf(os.Stderr, "self_guard: HealPins re-pin %s failed: %v\n", name, err)
			continue
		}
		healed++
	}
	return healed
}
