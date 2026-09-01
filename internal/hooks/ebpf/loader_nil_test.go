//go:build linux

package ebpf

import "testing"

// A nil *Loader is the normal state on a host without BPF-LSM: the daemon runs
// in LD_PRELOAD (DEGRADED) mode and cmd/oknekd hands the nil straight to the
// pin/canary services, whose field comment promises "nil-safe: every map op is
// a no-op without BPF". That promise used to be false — the guards lived inside
// putInode/delInode, but the callers evaluated l.pinned as an ARGUMENT first,
// so `oknek pin` and `oknek canary plant` panicked the daemon on exactly the
// hosts the README says are supported. Every exported method must tolerate a
// nil receiver.
func TestNilLoaderIsNoOp(t *testing.T) {
	var l *Loader // nil, as on a non-BPF-LSM host

	cases := []struct {
		name string
		call func() error
	}{
		{"RegisterPID", func() error { return l.RegisterPID(1234, "agent") }},
		{"UnregisterPID", func() error { return l.UnregisterPID(1234) }},
		{"AddProtectedInode", func() error { return l.AddProtectedInode(1, 2) }},
		{"SetAgentPolicy", func() error { return l.SetAgentPolicy(1234, 7) }},
		{"AddPinnedInode", func() error { return l.AddPinnedInode(1, 2) }},
		{"RemovePinnedInode", func() error { return l.RemovePinnedInode(1, 2) }},
		{"AddQuarantineInode", func() error { return l.AddQuarantineInode(1, 2) }},
		{"RemoveQuarantineInode", func() error { return l.RemoveQuarantineInode(1, 2) }},
		{"AddCanaryInode", func() error { return l.AddCanaryInode(1, 2, true) }},
		{"RemoveCanaryInode", func() error { return l.RemoveCanaryInode(1, 2) }},
		{"AddR2Inode", func() error { return l.AddR2Inode(R2PrivateFile, 1, 2) }},
		{"SetR2Mode", func() error { return l.SetR2Mode(1, 2) }},
		{"ClearTaint", func() error { return l.ClearTaint("agent") }},
		{"Close", func() error { return l.Close() }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.call(); err != nil {
				t.Fatalf("%s on nil loader = %v, want nil", c.name, err)
			}
		})
	}

	// Readers must return usable zero values, not panic.
	if got := l.Agents(); len(got) != 0 {
		t.Fatalf("Agents() on nil loader = %v, want empty", got)
	}
	if got := l.Taints(); len(got) != 0 {
		t.Fatalf("Taints() on nil loader = %v, want empty", got)
	}
	if got := l.PolicyOf(1234); got != 0 {
		t.Fatalf("PolicyOf() on nil loader = %d, want 0", got)
	}
	if got := l.ReapDeadPolicies(); got != 0 {
		t.Fatalf("ReapDeadPolicies() on nil loader = %d, want 0", got)
	}
	l.SetExecObserver(nil) // must not panic
}
