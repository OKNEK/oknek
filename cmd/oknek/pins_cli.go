package main

import (
	"fmt"
	"os"
	"strings"
)

type pinRow struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	PinnedAt    int64  `json:"pinned_at"`
	TamperedAt  int64  `json:"tampered_at"`
	Quarantined bool   `json:"quarantined"`
}

type canaryRow struct {
	Path      string `json:"path"`
	PlantedAt int64  `json:"planted_at"`
}

type pinStatus struct {
	PinsEnabled   bool        `json:"pins_enabled"`
	PinsEnforce   bool        `json:"pins_enforce"`
	Kernel        bool        `json:"kernel"`
	Pinned        int         `json:"pinned"`
	Tampered      int         `json:"tampered"`
	Quarantined   int         `json:"quarantined"`
	Pins          []pinRow    `json:"pins"`
	R22Events     int         `json:"r22_events"`
	CanaryEnabled bool        `json:"canary_enabled"`
	CanaryMode    string      `json:"canary_mode"`
	Canaries      []canaryRow `json:"canaries"`
	CanaryHits    int         `json:"canary_hits"`
}

// oknek pin                     pin the configured artifacts (globs relative to cwd + ~)
// oknek pin status              list pins, tamper/quarantine state
// oknek pin --accept <p>... [--note "…"]   re-pin after human review (lifts quarantine)
func runPin(configPath string, rest []string) {
	c, _ := client(configPath)
	if len(rest) > 0 && rest[0] == "status" {
		printPinStatus(c)
		return
	}
	if len(rest) > 0 && rest[0] == "--accept" {
		var paths []string
		note := "accepted via oknek pin --accept"
		for i := 1; i < len(rest); i++ {
			if rest[i] == "--note" && i+1 < len(rest) {
				note = rest[i+1]
				i++
				continue
			}
			paths = append(paths, absPath(rest[i]))
		}
		if len(paths) == 0 {
			fmt.Fprintln(os.Stderr, "usage: oknek pin --accept <path>... [--note \"why\"]")
			os.Exit(2)
		}
		var out struct {
			Accepted int      `json:"accepted"`
			Pins     []pinRow `json:"pins"`
		}
		if err := c.Call("pin.accept", map[string]interface{}{"paths": paths, "note": note}, &out); err != nil {
			fmt.Fprintf(os.Stderr, "oknek: pin --accept: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("oknek pin · %d artifact(s) ACCEPTED + re-pinned (quarantine lifted, sealed to Okular)\n", out.Accepted)
		for _, p := range out.Pins {
			fmt.Printf("  ✓ %s  %s\n", p.Path, short12(p.SHA256))
		}
		return
	}
	if len(rest) > 0 && rest[0] != "set" {
		fmt.Fprintln(os.Stderr, "usage: oknek pin [set|status|--accept <path>... [--note \"why\"]]")
		os.Exit(2)
	}
	cwd, _ := os.Getwd()
	var out struct {
		Pinned int      `json:"pinned"`
		Pins   []pinRow `json:"pins"`
	}
	if err := c.Call("pin.set", map[string]interface{}{"cwds": []string{cwd}}, &out); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: pin (daemon unreachable or pins disabled?): %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("oknek pin · %d supply-chain artifact(s) pinned (R22) · sealed to Okular\n", out.Pinned)
	for _, p := range out.Pins {
		fmt.Printf("  ✓ %s  %s  %dB\n", p.Path, short12(p.SHA256), p.Size)
	}
	if out.Pinned == 0 {
		fmt.Println("  (no artifacts matched pins.paths from", cwd, "or ~ — nothing to protect yet)")
	}
}

func printPinStatus(c rpcCaller) {
	var s pinStatus
	if err := c.Call("pin.status", nil, &s); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: pin status: %v\n", err)
		os.Exit(1)
	}
	enf := "observe"
	if s.PinsEnforce && s.Kernel {
		enf = "KERNEL-ENFORCED"
	}
	fmt.Printf("oknek pin status · R22 supply-chain guard · %s\n", enf)
	fmt.Printf("  pinned %d · tampered %d · quarantined %d · R22 events %d\n", s.Pinned, s.Tampered, s.Quarantined, s.R22Events)
	for _, p := range s.Pins {
		mark := "✓ pinned     "
		if p.Quarantined {
			mark = "✗ QUARANTINED"
		} else if p.TamperedAt > 0 {
			mark = "! tampered   "
		}
		fmt.Printf("  %s %s  %s\n", mark, p.Path, short12(p.SHA256))
	}
	fmt.Printf("  canaries %d (mode %s) · hits %d\n", len(s.Canaries), s.CanaryMode, s.CanaryHits)
	for _, k := range s.Canaries {
		fmt.Printf("  ◌ canary     %s\n", k.Path)
	}
}

// oknek canary plant [path...]   plant decoys (default: canary.plant); never overwrites a real file
// oknek canary status
// oknek canary remove            remove decoys whose bytes are still ours
func runCanary(configPath string, rest []string) {
	c, _ := client(configPath)
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "usage: oknek canary plant [path...] | status | remove")
		os.Exit(2)
	}
	switch rest[0] {
	case "plant":
		var paths []string
		for _, p := range rest[1:] {
			if strings.HasPrefix(p, "~/") {
				paths = append(paths, p)
			} else {
				paths = append(paths, absPath(p))
			}
		}
		var out struct {
			Planted []string `json:"planted"`
			Skipped []string `json:"skipped"`
			Mode    string   `json:"mode"`
		}
		if err := c.Call("canary.plant", map[string]interface{}{"paths": paths}, &out); err != nil {
			fmt.Fprintf(os.Stderr, "oknek: canary plant: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("oknek canary · %d decoy(s) planted · mode %s · sealed to Okular\n", len(out.Planted), out.Mode)
		for _, p := range out.Planted {
			fmt.Printf("  ◌ %s\n", p)
		}
		for _, p := range out.Skipped {
			fmt.Printf("  – %s  (real file present — NOT touched)\n", p)
		}
	case "status":
		printPinStatus(c)
	case "remove":
		var out struct {
			Removed []string `json:"removed"`
			Kept    []string `json:"kept"`
		}
		if err := c.Call("canary.remove", nil, &out); err != nil {
			fmt.Fprintf(os.Stderr, "oknek: canary remove: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("oknek canary · %d decoy(s) removed\n", len(out.Removed))
		for _, p := range out.Kept {
			fmt.Printf("  ! %s  content changed since planting — left in place\n", p)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: oknek canary plant [path...] | status | remove")
		os.Exit(2)
	}
}

type rpcCaller interface {
	Call(method string, params interface{}, out interface{}) error
}

func absPath(p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	cwd, _ := os.Getwd()
	return cwd + "/" + strings.TrimPrefix(p, "./")
}

func short12(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
