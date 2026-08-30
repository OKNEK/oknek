package ebpf

import "os"

// PinDir is the bpffs directory the LSM links are pinned under. Overridable via
// OKNEK_BPF_PIN_DIR so a test daemon never clobbers a prod instance's pins (both
// default to /sys/fs/bpf/oknek). Shared by the loader (where it pins) and the
// daemon's doctor preflight (where it counts the pins).
func PinDir() string {
	if d := os.Getenv("OKNEK_BPF_PIN_DIR"); d != "" {
		return d
	}
	return "/sys/fs/bpf/oknek"
}
