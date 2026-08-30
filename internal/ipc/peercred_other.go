//go:build !linux

package ipc

import "net"

// peerPID is unsupported off Linux (no SO_PEERCRED); callers fall back to the
// self-reported PID.
func peerPID(conn net.Conn) (int, bool) { return 0, false }
