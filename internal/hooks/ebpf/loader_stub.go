//go:build !linux

// Stub so the daemon still compiles on macOS (dev) and non-Linux cross targets.
// eBPF BPF-LSM enforcement is Linux-only; everywhere else this is a no-op and
// the daemon runs in LD_PRELOAD mode.
package ebpf

import (
	"context"
	"errors"
	"net"
)

// ErrUnsupported is returned by Start on non-Linux platforms.
var ErrUnsupported = errors.New("eBPF LSM enforcement is only supported on Linux")

// Loader is a no-op handle on non-Linux platforms.
type Loader struct{}

// Available always reports false off Linux.
func Available() bool { return false }

// Start is a no-op off Linux.
func Start(
	_ context.Context,
	_ func(id string, ts int64, agentID, ruleID, verdict, payload string) error,
	_ func(mode, agent string),
	_ ConnectObserver,
) (*Loader, error) {
	return nil, ErrUnsupported
}

// SetEgressPolicy is a no-op off Linux.
func (l *Loader) SetEgressPolicy(gw net.IP, gwPort int, allowDNS, enforce bool, resolvers []net.IP) error {
	return ErrUnsupported
}

// AddProtectedInode is a no-op off Linux.
func (l *Loader) AddProtectedInode(dev uint32, ino uint64) error { return nil }

// SetAgentPolicy is a no-op off Linux.
func (l *Loader) SetAgentPolicy(pid uint32, policyID uint16) error { return nil }

// AddEgressAllow is a no-op off Linux.
func (l *Loader) AddEgressAllow(policyID uint16, ip net.IP, port uint16) error { return nil }

// AddEgressCIDR is a no-op off Linux.
func (l *Loader) AddEgressCIDR(policyID uint16, ip net.IP, nbytes uint8, port uint16) error {
	return nil
}

// ReapDeadPolicies is a no-op off Linux.
func (l *Loader) ReapDeadPolicies() int { return 0 }

// ArmSelfGuard is a no-op off Linux (R20 anti-unpin needs BPF-LSM).
func (l *Loader) ArmSelfGuard(enforce bool) error { return ErrUnsupported }

// SelfGuardArmed reports unarmed off Linux.
func (l *Loader) SelfGuardArmed() (initialised, enforcing bool) { return false, false }

// CountPins reports zero off Linux.
func (l *Loader) CountPins() int { return 0 }

// HealPins is a no-op off Linux.
func (l *Loader) HealPins() int { return 0 }

// RegisterPID is a no-op off Linux.
func (l *Loader) RegisterPID(pid uint32, agent string) error { return ErrUnsupported }

// UnregisterPID is a no-op off Linux.
func (l *Loader) UnregisterPID(pid uint32) error { return ErrUnsupported }

// Close is a no-op off Linux.
func (l *Loader) Close() error { return nil }

// R22/R23 inode maps are no-ops off Linux.
func (l *Loader) AddPinnedInode(dev uint32, ino uint64) error             { return nil }
func (l *Loader) RemovePinnedInode(dev uint32, ino uint64) error          { return nil }
func (l *Loader) AddQuarantineInode(dev uint32, ino uint64) error         { return nil }
func (l *Loader) RemoveQuarantineInode(dev uint32, ino uint64) error      { return nil }
func (l *Loader) AddCanaryInode(dev uint32, ino uint64, block bool) error { return nil }
func (l *Loader) RemoveCanaryInode(dev uint32, ino uint64) error          { return nil }

// R21 Rule of Two is a no-op off Linux.
const (
	R2UntrustedFile uint8 = iota
	R2UntrustedDir
	R2PrivateFile
	R2PrivateDir
)

func (l *Loader) AddR2Inode(kind uint8, dev uint32, ino uint64) error { return nil }
func (l *Loader) SetR2Mode(policy uint16, mode uint8) error           { return nil }
func (l *Loader) Taints() map[string]uint8                            { return map[string]uint8{} }
func (l *Loader) ClearTaint(agent string) error                       { return nil }
func (l *Loader) SetR2NetworkTrusted(trusted bool) error              { return nil }
func (l *Loader) Agents() map[string]uint32                           { return map[string]uint32{} }
func (l *Loader) PolicyOf(pid uint32) uint16                          { return 0 }

// ExecObserver receives every exec by a watched process tree (informational).
type ExecObserver func(pid, ppid uint32, agent, name string)

func (l *Loader) SetExecObserver(fn ExecObserver) {}
