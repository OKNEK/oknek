package ebpf

// ConnectObserver is invoked for each R11 off-gateway connect event the kernel
// drain decodes, so a higher layer (R12 exfilwatch) can detect beaconing /
// velocity. process+pid are the connecting process for alert evidence. Always
// nil-safe at the call site. Declared in an untagged file so both the linux
// loader and the non-linux stub share one definition.
type ConnectObserver func(agentID, process string, pid int, destIP string, destPort uint16, tsNano int64)
