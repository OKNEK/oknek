//go:build linux

package ipc

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerPID returns the connecting peer's PID as seen in THIS process's PID
// namespace via SO_PEERCRED. For the daemon (which runs in the host/init PID
// namespace) that is the global PID — the same identity the BPF-LSM hooks see
// from bpf_get_current_pid_tgid(). This makes agent registration:
//   - namespace-correct: a containerized agent reports its container-local PID in
//     the request body, but the kernel translates the peer to the global PID here,
//     so enforcement actually matches (the Class-6 container gap).
//   - spoof-proof: the kernel fills the credential, not the agent, so an agent
//     can't register a bogus PID to dodge being watched.
func peerPID(conn net.Conn) (int, bool) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *unix.Ucred
	var cerr error
	if cerr2 := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); cerr2 != nil {
		return 0, false
	}
	if cerr != nil || cred == nil || cred.Pid <= 0 {
		return 0, false
	}
	return int(cred.Pid), true
}
