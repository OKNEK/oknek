//go:build linux

// Package ebpf loads + attaches oknek's BPF-LSM credential-read enforcer and
// streams its block events back to the daemon. Kernel-grade: catches reads even
// from statically-linked agents that bypass the LD_PRELOAD shim.
//
// The compiled BPF object (oknek_lsm.o) is embedded; it is built on a Linux box
// with clang (Apple clang can't target BPF) via `make shim-ebpf`. cilium/ebpf
// CO-RE-relocates it against the running kernel's BTF at load time.
package ebpf

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed oknek_lsm.o
var bpfObj []byte

const agentLen = 64

// event mirrors `struct oknek_event` in oknek_lsm.c (little-endian / x86-64).
type event struct {
	TsNs     uint64
	PID      uint32
	PPID     uint32
	Rule     uint8
	Verdict  uint8
	Category uint8
	Pad      uint8
	Comm     [16]byte
	AgentID  [agentLen]byte
	Dir      [64]byte
	Name     [64]byte
	Daddr    [16]byte
	Dport    uint16
	Family   uint8
}

// Loader holds the attached BPF-LSM programs, their maps, and the ringbuf reader.
type Loader struct {
	coll        *ebpf.Collection
	lnk         link.Link // lsm/file_open (R3)
	lnk2        link.Link // lsm/socket_connect (R11)
	lnk3        link.Link // raw_tp/sched_process_fork (watch propagation)
	lnk4        link.Link // raw_tp/sched_process_exit (watch cleanup)
	lnk5        link.Link // lsm/socket_sendmsg (R11 connectionless egress)
	lnk6        link.Link // lsm/ptrace_access_check (R13 memory-read guard)
	lnk7        link.Link // lsm/bprm_check_security (R15 privesc/exec guard)
	lnk8        link.Link // lsm/socket_bind (R16 inbound-backdoor guard)
	lnk9        link.Link // lsm/bpf (R17 kernel-tamper / anti-rootkit guard)
	lnk10       link.Link // lsm/kernel_read_file (R18 kernel-module-load guard)
	lnk11       link.Link // lsm/sb_mount (R19 mount guard)
	lnk12       link.Link // lsm/inode_unlink (R20 anti-unpin: deny rm of own pins)
	lnk13       link.Link // lsm/inode_rename (R20 anti-unpin: deny mv of own pins)
	lnk14       link.Link // lsm/sb_umount (R20 anti-unpin: deny umount of own bpffs)
	reader      *ringbuf.Reader
	pids        *ebpf.Map
	egress      *ebpf.Map    // R11 single-entry egress policy
	inodes      *ebpf.Map    // R3 protected-inode set (hardlink/rename-proof)
	selfID      *ebpf.Map    // R20 anti-unpin: pin dir's own (dev, ino) + enforce flag
	policy      *ebpf.Map    // Okredo: tgid -> policy id
	egressAllow *ebpf.Map    // Okredo: {policy,port,ip} -> per-agent egress allowlist
	egressCIDR  *ebpf.Map    // Okredo: per-policy byte-aligned CIDR grants (array)
	cidrN       uint32       // next free CIDR slot
	pinned      *ebpf.Map    // R22: pinned artifact inodes (watched write -> EPERM)
	quarantine  *ebpf.Map    // R22: tampered artifact inodes (watched open/exec -> EPERM)
	canary      *ebpf.Map    // R23: decoy credential inodes (watched open -> alert/block)
	taint       *ebpf.Map    // R21: agent identity -> taint bits (U=1 P=2 X=4)
	r2mode      *ebpf.Map    // R21: policy id -> mode (0 off 1 observe 2 enforce)
	untrustedIn *ebpf.Map    // R21: untrusted file inodes
	untrustedDr *ebpf.Map    // R21: untrusted dir inodes (direct children)
	privateIn   *ebpf.Map    // R21: private file inodes
	privateDr   *ebpf.Map    // R21: private dir inodes
	execObs     ExecObserver // R24: exec-observed callback (nil = ignore)
}

// Available reports whether the kernel has the bpf LSM active (required to block).
func Available() bool {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	for _, name := range strings.Split(strings.TrimSpace(string(b)), ",") {
		if name == "bpf" {
			return true
		}
	}
	return false
}

// Start loads + attaches the BPF-LSM enforcer and spawns a goroutine that drains
// block events into `insert` (same signature as store.InsertEvent). It calls
// attach("ebpf", agent) so `oknek status` reports hook_mode=ebpf and counts agents.
func Start(
	ctx context.Context,
	insert func(id string, ts int64, agentID, ruleID, verdict, payload string) error,
	attach func(mode, agent string),
	observe ConnectObserver,
) (*Loader, error) {
	if !Available() {
		return nil, errors.New("bpf not in active LSM list (boot with lsm=...,bpf)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObj))
	if err != nil {
		return nil, fmt.Errorf("parse bpf object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load collection: %w", err)
	}
	prog := coll.Programs["oknek_file_open"]
	if prog == nil {
		coll.Close()
		return nil, errors.New("program oknek_file_open not found in object")
	}
	lnk, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach lsm/file_open: %w", err)
	}
	cprog := coll.Programs["oknek_socket_connect"]
	if cprog == nil {
		lnk.Close()
		coll.Close()
		return nil, errors.New("program oknek_socket_connect not found in object")
	}
	lnk2, err := link.AttachLSM(link.LSMOptions{Program: cprog})
	if err != nil {
		lnk.Close()
		coll.Close()
		return nil, fmt.Errorf("attach lsm/socket_connect: %w", err)
	}
	// R11 connectionless egress: gate UDP/QUIC sendmsg too. Best-effort.
	var lnk5 link.Link
	if p := coll.Programs["oknek_socket_sendmsg"]; p != nil {
		lnk5, _ = link.AttachLSM(link.LSMOptions{Program: p})
	}
	// R13 memory-read guard: gate cross-process memory reads (ptrace /
	// process_vm_readv / /proc/pid/{mem,environ}). Best-effort.
	var lnk6 link.Link
	if p := coll.Programs["oknek_ptrace"]; p != nil {
		lnk6, _ = link.AttachLSM(link.LSMOptions{Program: p})
	}
	// R15 privesc/exec guard: block a watched agent exec'ing sudo/su/pkexec/...
	// Best-effort.
	var lnk7 link.Link
	if p := coll.Programs["oknek_exec"]; p != nil {
		lnk7, _ = link.AttachLSM(link.LSMOptions{Program: p})
	}
	// R16 inbound-backdoor guard: block a watched agent binding a non-loopback
	// listener. Best-effort.
	var lnk8 link.Link
	if p := coll.Programs["oknek_bind"]; p != nil {
		lnk8, _ = link.AttachLSM(link.LSMOptions{Program: p})
	}
	// R17 kernel-tamper guard: block a watched agent calling bpf(). Best-effort.
	var lnk9 link.Link
	if p := coll.Programs["oknek_bpf"]; p != nil {
		lnk9, _ = link.AttachLSM(link.LSMOptions{Program: p})
	}
	// R18 kernel-module-load guard + R19 mount guard (anti-rootkit / anti-escape).
	// Best-effort.
	var lnk10, lnk11 link.Link
	if p := coll.Programs["oknek_kmod"]; p != nil {
		lnk10, _ = link.AttachLSM(link.LSMOptions{Program: p})
	}
	if p := coll.Programs["oknek_mount"]; p != nil {
		lnk11, _ = link.AttachLSM(link.LSMOptions{Program: p})
	}
	// R20 anti-unpin (self-pin-guard): deny rm/rename of oknek's own bpffs pins.
	// Attached fail-open (the guard does nothing until the daemon calls WriteSelfID
	// to arm it), so it's zero-behavior-change until self_guard is enabled. Unlike
	// the other rules this guards oknek's off-switch against ANYONE, incl. root.
	// Best-effort. NB: these fire host-wide on unlink/rename — they MUST stay
	// strictly scoped to the pin dir's (dev,ino) or they brick normal file ops.
	var lnk12, lnk13, lnk14 link.Link
	if p := coll.Programs["oknek_inode_unlink"]; p != nil {
		lnk12, _ = link.AttachLSM(link.LSMOptions{Program: p})
	}
	if p := coll.Programs["oknek_inode_rename"]; p != nil {
		lnk13, _ = link.AttachLSM(link.LSMOptions{Program: p})
	}
	if p := coll.Programs["oknek_sb_umount"]; p != nil {
		lnk14, _ = link.AttachLSM(link.LSMOptions{Program: p})
	}
	// Fork-propagation (the keystone): mark children of watched agents at fork so
	// watched-ness survives re-parenting (double-fork to init) + the bounded
	// ancestry walk. Best-effort — LSM enforcement still works via the ancestry
	// fallback if these tracepoints don't attach on this kernel.
	var lnk3, lnk4 link.Link
	if p := coll.Programs["oknek_fork"]; p != nil {
		lnk3, _ = link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sched_process_fork", Program: p})
	}
	if p := coll.Programs["oknek_exit"]; p != nil {
		lnk4, _ = link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sched_process_exit", Program: p})
	}
	rd, err := ringbuf.NewReader(coll.Maps["oknek_events"])
	if err != nil {
		if lnk14 != nil {
			lnk14.Close()
		}
		if lnk13 != nil {
			lnk13.Close()
		}
		if lnk12 != nil {
			lnk12.Close()
		}
		if lnk11 != nil {
			lnk11.Close()
		}
		if lnk10 != nil {
			lnk10.Close()
		}
		if lnk9 != nil {
			lnk9.Close()
		}
		if lnk8 != nil {
			lnk8.Close()
		}
		if lnk7 != nil {
			lnk7.Close()
		}
		if lnk6 != nil {
			lnk6.Close()
		}
		if lnk5 != nil {
			lnk5.Close()
		}
		if lnk4 != nil {
			lnk4.Close()
		}
		if lnk3 != nil {
			lnk3.Close()
		}
		lnk2.Close()
		lnk.Close()
		coll.Close()
		return nil, fmt.Errorf("open ringbuf: %w", err)
	}
	l := &Loader{
		coll:        coll,
		lnk:         lnk,
		lnk2:        lnk2,
		lnk3:        lnk3,
		lnk4:        lnk4,
		lnk5:        lnk5,
		lnk6:        lnk6,
		lnk7:        lnk7,
		lnk8:        lnk8,
		lnk9:        lnk9,
		lnk10:       lnk10,
		lnk11:       lnk11,
		lnk12:       lnk12,
		lnk13:       lnk13,
		lnk14:       lnk14,
		reader:      rd,
		pids:        coll.Maps["oknek_agent_pids"],
		egress:      coll.Maps["oknek_egress"],
		inodes:      coll.Maps["oknek_protected_inodes"],
		selfID:      coll.Maps["oknek_self_id"],
		policy:      coll.Maps["oknek_agent_policy"],
		egressAllow: coll.Maps["oknek_egress_allow"],
		egressCIDR:  coll.Maps["oknek_egress_cidr"],
		pinned:      coll.Maps["oknek_pinned_inodes"],
		quarantine:  coll.Maps["oknek_quarantine_inodes"],
		canary:      coll.Maps["oknek_canary_inodes"],
		taint:       coll.Maps["oknek_taint"],
		r2mode:      coll.Maps["oknek_r2_mode"],
		untrustedIn: coll.Maps["oknek_untrusted_inodes"],
		untrustedDr: coll.Maps["oknek_untrusted_dirs"],
		privateIn:   coll.Maps["oknek_private_inodes"],
		privateDr:   coll.Maps["oknek_private_dirs"],
	}

	// Pin the LSM links to bpffs so enforcement SURVIVES a daemon kill — a root
	// agent can't disable us just by SIGKILLing oknekd. Best-effort: skipped where
	// bpffs is unavailable; stale pins from a prior run are cleared first. The dir is
	// overridable (OKNEK_BPF_PIN_DIR) so a test daemon never clobbers a prod instance's pins.
	pinDir := PinDir()
	_ = os.MkdirAll(pinDir, 0o700)
	for name, lk := range map[string]link.Link{"file_open": lnk, "socket_connect": lnk2, "sendmsg": lnk5, "ptrace": lnk6, "exec": lnk7, "bind": lnk8, "bpf": lnk9, "kmod": lnk10, "mount": lnk11, "inode_unlink": lnk12, "inode_rename": lnk13, "sb_umount": lnk14, "fork": lnk3, "exit": lnk4} {
		if lk == nil {
			continue
		}
		pp := pinDir + "/" + name
		// Don't swallow these: under R20 enforce a RESTART can't remove the old pins (the
		// still-live frozen guard denies it, EPERM) so Pin then fails EEXIST and the new
		// link attaches UNPINNED while the old one persists = silent double-attach. Log it
		// loudly — applying self_guard config changes under enforce requires a reboot.
		if err := os.Remove(pp); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "ebpf: pin %s: stale pin not removable (%v) — restart under R20 enforce? reboot to cleanly re-pin\n", name, err)
		}
		if err := lk.Pin(pp); err != nil {
			fmt.Fprintf(os.Stderr, "ebpf: pin %s failed (link attached but UNPINNED): %v\n", name, err)
		}
	}

	attach("ebpf", "") // flip hook_mode to ebpf

	go func() { <-ctx.Done(); rd.Close() }()
	go l.drain(insert, attach, observe)
	return l, nil
}

// RegisterPID marks a process (and its same-PID exec target) as a watched agent
// so the kernel hook enforces on it. Called from hook.attach.
func (l *Loader) RegisterPID(pid uint32, agent string) error {
	if l == nil {
		return nil
	}
	var v [agentLen]byte
	copy(v[:], agent)
	return l.pids.Put(pid, v)
}

// UnregisterPID stops enforcing on a PID.
func (l *Loader) UnregisterPID(pid uint32) error {
	if l == nil {
		return nil
	}
	return l.pids.Delete(pid)
}

// Close detaches the program and frees maps.
func (l *Loader) Close() error {
	if l == nil {
		return nil
	}
	if l.reader != nil {
		l.reader.Close()
	}
	if l.lnk14 != nil {
		l.lnk14.Close()
	}
	if l.lnk13 != nil {
		l.lnk13.Close()
	}
	if l.lnk12 != nil {
		l.lnk12.Close()
	}
	if l.lnk11 != nil {
		l.lnk11.Close()
	}
	if l.lnk10 != nil {
		l.lnk10.Close()
	}
	if l.lnk9 != nil {
		l.lnk9.Close()
	}
	if l.lnk8 != nil {
		l.lnk8.Close()
	}
	if l.lnk7 != nil {
		l.lnk7.Close()
	}
	if l.lnk6 != nil {
		l.lnk6.Close()
	}
	if l.lnk5 != nil {
		l.lnk5.Close()
	}
	if l.lnk4 != nil {
		l.lnk4.Close()
	}
	if l.lnk3 != nil {
		l.lnk3.Close()
	}
	if l.lnk2 != nil {
		l.lnk2.Close()
	}
	if l.lnk != nil {
		l.lnk.Close()
	}
	if l.coll != nil {
		l.coll.Close()
	}
	return nil
}

// SetEgressPolicy installs the gateway-jail policy into the BPF map. With it set
// and enforce=true, watched agents (and their process tree) may only reach the
// gateway, DNS (if allowDNS), and loopback; all other egress is blocked.
func (l *Loader) SetEgressPolicy(gw net.IP, gwPort int, allowDNS, enforce bool, resolvers []net.IP) error {
	if l == nil {
		return nil
	}
	var key uint32 = 0
	p := buildEgressPolicy(gw, gwPort, allowDNS, enforce, resolvers)
	if err := l.egress.Put(key, p); err != nil {
		return err
	}
	// Freeze the policy map so a root/CAP_BPF agent can't flip enforce=0 or rewrite
	// the gateway from userspace. Best-effort (not all kernels support freeze).
	if err := l.egress.Freeze(); err != nil {
		fmt.Fprintf(os.Stderr, "egress_jail: map freeze failed: %v\n", err)
	}
	return nil
}

type inodeKey struct {
	Ino uint64
	Dev uint32
	_   uint32
}

// AddProtectedInode marks a file (by device + inode) as credential-protected, so
// R3 blocks it even when opened via a hardlink, rename, or bind-mount (same inode).
func (l *Loader) AddProtectedInode(dev uint32, ino uint64) error {
	if l == nil {
		return nil
	}
	if l.inodes == nil {
		return nil
	}
	var v uint8 = 1
	return l.inodes.Put(inodeKey{Ino: ino, Dev: dev}, v)
}

// allowKey mirrors `struct oknek_allow_key` in the BPF object (8 bytes, no padding).
type allowKey struct {
	Policy uint16
	Port   uint16
	IP     [4]byte
}

// SetAgentPolicy binds a watched agent (by global pid) to an Okredo policy id, so
// the kernel applies that identity's per-agent egress allowlist.
func (l *Loader) SetAgentPolicy(pid uint32, policyID uint16) error {
	if l == nil {
		return nil
	}
	if l.policy == nil || policyID == 0 {
		return nil
	}
	return l.policy.Put(pid, policyID)
}

// AddEgressAllow authorizes a policy/identity to reach a specific dest IPv4:port,
// additive to the base egress jail.
func (l *Loader) AddEgressAllow(policyID uint16, ip net.IP, port uint16) error {
	if l == nil {
		return nil
	}
	if l.egressAllow == nil {
		return nil
	}
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("okredo: %s is not IPv4", ip)
	}
	var k allowKey
	k.Policy = policyID
	k.Port = port
	copy(k.IP[:], v4)
	var one uint8 = 1
	return l.egressAllow.Put(k, one)
}

// cidrEntry mirrors `struct oknek_cidr` in the BPF object (12 bytes).
type cidrEntry struct {
	Policy uint16
	Port   uint16
	Net    [4]byte
	NBytes uint8
	_      [3]byte
}

// ReapDeadPolicies removes oknek_agent_policy entries whose process no longer
// exists. This bounds the map (the exit hook can't safely clean it — a Go agent's
// exec triggers a spurious leader-exit that would wipe a live policy), and a present
// /proc/<pid> is the unambiguous "still alive" signal.
func (l *Loader) ReapDeadPolicies() int {
	if l == nil {
		return 0
	}
	if l.policy == nil {
		return 0
	}
	var key uint32
	var val uint16
	var dead []uint32
	it := l.policy.Iterate()
	for it.Next(&key, &val) {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", key)); err != nil {
			dead = append(dead, key)
		}
	}
	for _, k := range dead {
		_ = l.policy.Delete(k)
	}
	return len(dead)
}

// AddEgressCIDR authorizes a policy/identity to reach a byte-aligned IPv4 range
// (nbytes = significant octets: 1=/8, 2=/16, 3=/24, 4=/32). port 0 = any port.
func (l *Loader) AddEgressCIDR(policyID uint16, ip net.IP, nbytes uint8, port uint16) error {
	if l == nil {
		return nil
	}
	if l.egressCIDR == nil {
		return nil
	}
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("okredo cidr: %s is not IPv4", ip)
	}
	if l.cidrN >= 32 {
		return fmt.Errorf("okredo: too many CIDR grants (max 32)")
	}
	var c cidrEntry
	c.Policy = policyID
	c.Port = port
	copy(c.Net[:], v4)
	c.NBytes = nbytes
	idx := l.cidrN
	l.cidrN++
	return l.egressCIDR.Put(idx, c)
}

var categoryName = map[uint8]string{0: "exact", 1: "suffix", 2: "substring", 3: "basename"}

func (l *Loader) drain(
	insert func(id string, ts int64, agentID, ruleID, verdict, payload string) error,
	attach func(mode, agent string),
	observe ConnectObserver,
) {
	for {
		rec, err := l.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		var e event
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}
		ts := time.Now().UnixNano()
		agentID := cstr(e.AgentID[:])
		if agentID != "" {
			attach("ebpf", agentID)
		}
		if e.Rule == 13 {
			evidence := map[string]interface{}{
				"target_pid":       e.PPID,
				"process":          cstr(e.Comm[:]),
				"agent_identifier": agentID,
				"pid":              e.PID,
				"enforcement":      "ebpf",
				"rule":             "mem-read-guard",
			}
			payload, _ := json.Marshal(evidence)
			id := fmt.Sprintf("e_%d_%d_R13", ts, e.PID)
			_ = insert(id, ts, agentID, "R13", "block", string(payload))
			continue
		}
		if e.Rule == 14 {
			evidence := map[string]interface{}{
				"path":             "/" + cstr(e.Dir[:]) + "/" + cstr(e.Name[:]),
				"dir":              cstr(e.Dir[:]),
				"name":             cstr(e.Name[:]),
				"process":          cstr(e.Comm[:]),
				"agent_identifier": agentID,
				"pid":              e.PID,
				"enforcement":      "ebpf",
				"rule":             "persistence-guard",
			}
			payload, _ := json.Marshal(evidence)
			id := fmt.Sprintf("e_%d_%d_R14", ts, e.PID)
			_ = insert(id, ts, agentID, "R14", "block", string(payload))
			continue
		}
		if e.Rule == 15 {
			evidence := map[string]interface{}{
				"binary":           cstr(e.Name[:]),
				"process":          cstr(e.Comm[:]),
				"agent_identifier": agentID,
				"pid":              e.PID,
				"enforcement":      "ebpf",
				"rule":             "privesc-guard",
			}
			payload, _ := json.Marshal(evidence)
			id := fmt.Sprintf("e_%d_%d_R15", ts, e.PID)
			_ = insert(id, ts, agentID, "R15", "block", string(payload))
			continue
		}
		if e.Rule == 16 {
			ip := net.IP(e.Daddr[:])
			if e.Family == 2 { // AF_INET
				ip = net.IP(e.Daddr[:4])
			}
			evidence := map[string]interface{}{
				"bind":             fmt.Sprintf("%s:%d", ip.String(), e.Dport),
				"bind_ip":          ip.String(),
				"bind_port":        e.Dport,
				"process":          cstr(e.Comm[:]),
				"agent_identifier": agentID,
				"pid":              e.PID,
				"enforcement":      "ebpf",
				"rule":             "inbound-backdoor-guard",
			}
			payload, _ := json.Marshal(evidence)
			id := fmt.Sprintf("e_%d_%d_R16", ts, e.PID)
			_ = insert(id, ts, agentID, "R16", "block", string(payload))
			continue
		}
		if e.Rule == 17 {
			evidence := map[string]interface{}{
				"process":          cstr(e.Comm[:]),
				"agent_identifier": agentID,
				"pid":              e.PID,
				"enforcement":      "ebpf",
				"rule":             "kernel-tamper-guard",
				"detail":           "bpf() syscall blocked",
			}
			payload, _ := json.Marshal(evidence)
			id := fmt.Sprintf("e_%d_%d_R17", ts, e.PID)
			_ = insert(id, ts, agentID, "R17", "block", string(payload))
			continue
		}
		if e.Rule == 18 || e.Rule == 19 {
			rname := "kmod-load-guard"
			if e.Rule == 19 {
				rname = "mount-guard"
			}
			evidence := map[string]interface{}{
				"process":          cstr(e.Comm[:]),
				"agent_identifier": agentID,
				"pid":              e.PID,
				"enforcement":      "ebpf",
				"rule":             rname,
			}
			payload, _ := json.Marshal(evidence)
			rid := fmt.Sprintf("R%d", e.Rule)
			id := fmt.Sprintf("e_%d_%d_%s", ts, e.PID, rid)
			_ = insert(id, ts, agentID, rid, "block", string(payload))
			continue
		}
		if e.Rule == 20 {
			// anti-unpin: someone tried to rm/rename/umount oknek's own bpffs pins.
			// agent_id is empty (NOT scoped to a watched agent — this fires for
			// anyone, incl. a root insider); the process/pid is the attacker.
			detail := "attempt to remove/rename oknek's bpffs pin (DISABLE attempt)"
			if e.Category == 1 {
				detail = "attempt to umount oknek's bpffs (DISABLE attempt)"
			}
			evidence := map[string]interface{}{
				"process":     cstr(e.Comm[:]),
				"pid":         e.PID,
				"enforcement": "ebpf",
				"rule":        "anti-unpin-guard",
				"detail":      detail,
			}
			payload, _ := json.Marshal(evidence)
			id := fmt.Sprintf("e_%d_%d_R20", ts, e.PID)
			_ = insert(id, ts, agentID, "R20", vstr(e.Verdict), string(payload))
			continue
		}
		if e.Rule == 11 {
			ip := net.IP(e.Daddr[:])
			if e.Family == 2 { // AF_INET
				ip = net.IP(e.Daddr[:4])
			}
			evidence := map[string]interface{}{
				"dest":             fmt.Sprintf("%s:%d", ip.String(), e.Dport),
				"dest_ip":          ip.String(),
				"dest_port":        e.Dport,
				"process":          cstr(e.Comm[:]),
				"agent_identifier": agentID,
				"pid":              e.PID,
				"enforcement":      "ebpf",
				"rule":             "egress-jail",
			}
			payload, _ := json.Marshal(evidence)
			id := fmt.Sprintf("e_%d_%d_R11", ts, e.PID)
			_ = insert(id, ts, agentID, "R11", vstr(e.Verdict), string(payload))
			if observe != nil {
				observe(agentID, cstr(e.Comm[:]), int(e.PID), ip.String(), e.Dport, ts)
			}
			continue
		}
		if e.Rule == 30 {
			if l.execObs != nil {
				l.execObs(e.PID, e.PPID, agentID, cstr(e.Name[:]))
			}
			continue
		}
		if e.Rule == 21 {
			bits := e.Category
			phase := "acquired"
			verdict := "observe"
			if e.Pad == 1 {
				phase = "would_deny"
				if e.Verdict == 2 {
					phase = "denied"
					verdict = "block"
				}
			}
			trigger := "read /" + cstr(e.Dir[:]) + "/" + cstr(e.Name[:])
			if e.Family != 0 {
				ip := net.IP(e.Daddr[:])
				if e.Family == 2 {
					ip = net.IP(e.Daddr[:4])
				}
				trigger = fmt.Sprintf("connect %s:%d", ip.String(), e.Dport)
			}
			evidence := map[string]interface{}{
				"taint":            map[string]interface{}{"bits": bits, "u": bits&1 != 0, "p": bits&2 != 0, "x": bits&4 != 0},
				"phase":            phase,
				"trigger":          trigger,
				"process":          cstr(e.Comm[:]),
				"agent_identifier": agentID,
				"pid":              e.PID,
				"enforcement":      "ebpf",
				"rule":             "rule-of-two",
			}
			payload, _ := json.Marshal(evidence)
			_ = insert(fmt.Sprintf("e_%d_%d_R21", ts, e.PID), ts, agentID, "R21", verdict, string(payload))
			continue
		}
		if e.Rule == 22 {
			detail := map[uint8]string{1: "in-place write to a pinned artifact", 2: "open of a quarantined (tampered) artifact", 3: "exec of a quarantined (tampered) artifact"}[e.Category]
			evidence := map[string]interface{}{
				"path":             "/" + cstr(e.Dir[:]) + "/" + cstr(e.Name[:]),
				"dir":              cstr(e.Dir[:]),
				"name":             cstr(e.Name[:]),
				"process":          cstr(e.Comm[:]),
				"agent_identifier": agentID,
				"pid":              e.PID,
				"enforcement":      "ebpf",
				"rule":             "supply-chain-guard",
				"detail":           detail,
			}
			payload, _ := json.Marshal(evidence)
			_ = insert(fmt.Sprintf("e_%d_%d_R22", ts, e.PID), ts, agentID, "R22", vstr(e.Verdict), string(payload))
			continue
		}
		if e.Rule == 23 {
			mode := map[uint8]string{1: "alert", 2: "block"}[e.Category]
			verdict := "alert"
			if e.Verdict == 2 {
				verdict = "block"
			}
			evidence := map[string]interface{}{
				"path":             "/" + cstr(e.Dir[:]) + "/" + cstr(e.Name[:]),
				"dir":              cstr(e.Dir[:]),
				"name":             cstr(e.Name[:]),
				"process":          cstr(e.Comm[:]),
				"agent_identifier": agentID,
				"pid":              e.PID,
				"enforcement":      "ebpf",
				"rule":             "canary",
				"severity":         "critical",
				"mode":             mode,
			}
			payload, _ := json.Marshal(evidence)
			_ = insert(fmt.Sprintf("e_%d_%d_R23", ts, e.PID), ts, agentID, "R23", verdict, string(payload))
			// R21: a canary read is a private-data touch — set the P taint bit here (plan C).
			continue
		}
		evidence := map[string]interface{}{
			"path":             "/" + cstr(e.Dir[:]) + "/" + cstr(e.Name[:]),
			"dir":              cstr(e.Dir[:]),
			"name":             cstr(e.Name[:]),
			"matched_category": categoryName[e.Category],
			"process":          cstr(e.Comm[:]),
			"agent_identifier": agentID,
			"pid":              e.PID,
			"enforcement":      "ebpf",
		}
		payload, _ := json.Marshal(evidence)
		// same id scheme + verdict string as logMatches() so status counters tally.
		id := fmt.Sprintf("e_%d_%d_R3", ts, e.PID)
		_ = insert(id, ts, agentID, "R3", "block", string(payload))
	}
}

// vstr maps the BPF event verdict byte to the audit string: 1 = observe (op was
// ALLOWED in observe mode), else block. Prevents the WORM record overstating enforcement.
func vstr(v uint8) string {
	if v == 1 {
		return "observe"
	}
	return "block"
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// --- R22 / R23 inode maps -------------------------------------------------------

func (l *Loader) putInode(m *ebpf.Map, dev uint32, ino uint64, v uint8) error {
	if l == nil || m == nil {
		return nil
	}
	return m.Put(inodeKey{Ino: ino, Dev: dev}, v)
}

func (l *Loader) delInode(m *ebpf.Map, dev uint32, ino uint64) error {
	if l == nil || m == nil {
		return nil
	}
	if err := m.Delete(inodeKey{Ino: ino, Dev: dev}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// AddPinnedInode marks a supply-chain artifact: a watched agent may not open it for WRITE.
func (l *Loader) AddPinnedInode(dev uint32, ino uint64) error {
	if l == nil {
		return nil
	}
	return l.putInode(l.pinned, dev, ino, 1)
}

// RemovePinnedInode drops a pin (file re-pinned at a new inode, or forgotten).
func (l *Loader) RemovePinnedInode(dev uint32, ino uint64) error {
	if l == nil {
		return nil
	}
	return l.delInode(l.pinned, dev, ino)
}

// AddQuarantineInode marks a TAMPERED artifact: a watched agent may not open or exec it.
func (l *Loader) AddQuarantineInode(dev uint32, ino uint64) error {
	if l == nil {
		return nil
	}
	return l.putInode(l.quarantine, dev, ino, 1)
}

// RemoveQuarantineInode releases a quarantine (human re-pinned via `oknek pin --accept`).
func (l *Loader) RemoveQuarantineInode(dev uint32, ino uint64) error {
	if l == nil {
		return nil
	}
	return l.delInode(l.quarantine, dev, ino)
}

// AddCanaryInode marks a planted decoy: watched open -> alert (block=false) or EPERM (block=true).
func (l *Loader) AddCanaryInode(dev uint32, ino uint64, block bool) error {
	if l == nil {
		return nil
	}
	var v uint8 = 1
	if block {
		v = 2
	}
	return l.putInode(l.canary, dev, ino, v)
}

// RemoveCanaryInode forgets a decoy.
func (l *Loader) RemoveCanaryInode(dev uint32, ino uint64) error {
	if l == nil {
		return nil
	}
	return l.delInode(l.canary, dev, ino)
}

// --- R21 Rule of Two ------------------------------------------------------------

// R2 inode kinds for AddR2Inode.
const (
	R2UntrustedFile uint8 = iota
	R2UntrustedDir
	R2PrivateFile
	R2PrivateDir
)

type agentKey [agentLen]byte

// AddR2Inode classifies a file or directory (by dev+ino) as untrusted input or private data.
func (l *Loader) AddR2Inode(kind uint8, dev uint32, ino uint64) error {
	if l == nil {
		return nil
	}
	switch kind {
	case R2UntrustedFile:
		return l.putInode(l.untrustedIn, dev, ino, 1)
	case R2UntrustedDir:
		return l.putInode(l.untrustedDr, dev, ino, 1)
	case R2PrivateFile:
		return l.putInode(l.privateIn, dev, ino, 1)
	case R2PrivateDir:
		return l.putInode(l.privateDr, dev, ino, 1)
	}
	return fmt.Errorf("AddR2Inode: unknown kind %d", kind)
}

// SetR2Mode sets an Okredo policy's Rule-of-Two mode: 0 off, 1 observe, 2 enforce.
func (l *Loader) SetR2Mode(policy uint16, mode uint8) error {
	if l == nil || l.r2mode == nil || policy == 0 {
		return nil
	}
	return l.r2mode.Put(policy, mode)
}

// Taints returns every agent session's taint bits.
func (l *Loader) Taints() map[string]uint8 {
	out := map[string]uint8{}
	if l == nil || l.taint == nil {
		return out
	}
	var k agentKey
	var v uint8
	it := l.taint.Iterate()
	for it.Next(&k, &v) {
		out[cstr(k[:])] = v
	}
	return out
}

// ClearTaint resets an agent session (human checkpoint, or a fresh `oknek run`).
func (l *Loader) ClearTaint(agent string) error {
	if l == nil || l.taint == nil {
		return nil
	}
	var k agentKey
	copy(k[:], agent)
	if err := l.taint.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// SetR2NetworkTrusted: true = an external connect is X only; false = U+X (default).
func (l *Loader) SetR2NetworkTrusted(trusted bool) error {
	if l == nil || l.r2mode == nil {
		return nil
	}
	var v uint8
	if trusted {
		v = 1
	}
	return l.r2mode.Put(uint16(0xFFFF), v)
}

// Agents returns every registered agent identity -> its registered (root) pid.
func (l *Loader) Agents() map[string]uint32 {
	out := map[string]uint32{}
	if l == nil || l.pids == nil {
		return out
	}
	var k uint32
	var v [agentLen]byte
	it := l.pids.Iterate()
	for it.Next(&k, &v) {
		out[cstr(v[:])] = k
	}
	return out
}

// PolicyOf returns the Okredo policy id bound to pid (0 = base jail only).
func (l *Loader) PolicyOf(pid uint32) uint16 {
	if l == nil || l.policy == nil {
		return 0
	}
	var v uint16
	if err := l.policy.Lookup(pid, &v); err != nil {
		return 0
	}
	return v
}

// ExecObserver receives every exec by a watched process tree (informational).
type ExecObserver func(pid, ppid uint32, agent, name string)

// SetExecObserver installs the R24 exec callback (nil-safe).
func (l *Loader) SetExecObserver(fn ExecObserver) {
	if l == nil {
		return
	}
	l.execObs = fn
}
