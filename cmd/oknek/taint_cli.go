package main

import (
	"fmt"
	"os"
)

// oknek taint                      show each agent session's Rule-of-Two taint
// oknek taint clear <agent> [--note "why"]   human checkpoint: reset a session (sealed)
func runTaint(configPath string, rest []string) {
	c, _ := client(configPath)
	if len(rest) > 0 && rest[0] == "clear" {
		if len(rest) < 2 {
			fmt.Fprintln(os.Stderr, "usage: oknek taint clear <agent> [--note \"why\"]")
			os.Exit(2)
		}
		agent := rest[1]
		note := "cleared via oknek taint clear"
		for i := 2; i+1 < len(rest); i++ {
			if rest[i] == "--note" {
				note = rest[i+1]
			}
		}
		var out struct {
			OK    bool   `json:"ok"`
			Agent string `json:"agent"`
		}
		if err := c.Call("taint.clear", map[string]interface{}{"agent": agent, "note": note}, &out); err != nil {
			fmt.Fprintf(os.Stderr, "oknek: taint clear: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("oknek taint · session %q CLEARED (human checkpoint, sealed to Okular)\n", out.Agent)
		return
	}
	var s struct {
		Kernel    bool `json:"kernel"`
		Enforce   int  `json:"enforce"`
		Observe   int  `json:"observe"`
		R21Events int  `json:"r21_events"`
		Sessions  []struct {
			Agent   string `json:"agent"`
			U, P, X bool
		} `json:"sessions"`
	}
	if err := c.Call("taint.show", nil, &s); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: taint: %v\n", err)
		os.Exit(1)
	}
	state := "INACTIVE (needs kernel BPF-LSM)"
	if s.Kernel {
		state = fmt.Sprintf("KERNEL-ENFORCED · %d profile(s) enforce · %d observe", s.Enforce, s.Observe)
	}
	fmt.Printf("oknek taint · R21 Rule of Two · %s · %d event(s)\n", state, s.R21Events)
	fmt.Println("   an agent session may hold at most two of  U untrusted input · P private data · X external comms")
	if len(s.Sessions) == 0 {
		fmt.Println("   no tainted sessions")
		return
	}
	flag := func(b bool, ch string) string {
		if b {
			return ch
		}
		return "·"
	}
	for _, r := range s.Sessions {
		n := 0
		for _, b := range []bool{r.U, r.P, r.X} {
			if b {
				n++
			}
		}
		note := ""
		if n == 2 {
			note = "  ← one more property = DENIED"
		}
		fmt.Printf("   %-20s [%s %s %s]%s\n", r.Agent, flag(r.U, "U"), flag(r.P, "P"), flag(r.X, "X"), note)
	}
	fmt.Println("   reset a session after review: oknek taint clear <agent> --note \"…\"")
}
