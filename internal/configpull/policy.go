package configpull

import (
	"fmt"
	"regexp"
	"strings"
)

// THE GUARDRAIL (daemon side). A diff may only touch the four tunable surfaces
// below; anything else — self-guard (R20), kernel enforcement, disarm, unknown ops
// — is rejected by construction. Kept in lockstep with oknek-web/_lib/policy.js and
// oknek-dean/src/policy.js.
var (
	reName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	reDest = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*(:\d{1,5})?$`)
	rePath = regexp.MustCompile(`^[~/][\x20-\x7e]{0,255}$`)
)

// Validate returns nil iff the diff is one of the allowed tuning ops with well-formed
// fields. Never returns nil for anything touching oknek's own guards.
func Validate(d Diff) error {
	name := func(field, v string) error {
		if v == "" || strings.Contains(v, "..") || !reName.MatchString(v) {
			return fmt.Errorf("invalid %s", field)
		}
		return nil
	}
	dest := func(v string) error {
		if v == "" || strings.Contains(v, "..") || !reDest.MatchString(v) {
			return fmt.Errorf("invalid dest")
		}
		return nil
	}
	path := func(v string) error {
		if v == "" || strings.Contains(v, "..") || !rePath.MatchString(v) {
			return fmt.Errorf("invalid path")
		}
		return nil
	}

	switch d.Op {
	case "egress_allow_add", "egress_allow_remove":
		if err := name("agent", d.Agent); err != nil {
			return err
		}
		return dest(d.Dest)
	case "r1_chain_limit":
		if d.Limit < 1 || d.Limit > 64 {
			return fmt.Errorf("limit must be 1–64")
		}
		if d.Host != "" {
			return name("host", d.Host)
		}
		return nil
	case "host_mode":
		if err := name("host", d.Host); err != nil {
			return err
		}
		if d.Mode != "enforce" && d.Mode != "observe" {
			return fmt.Errorf("invalid mode")
		}
		return nil
	case "r3_exception_add", "r3_exception_remove":
		if err := name("agent", d.Agent); err != nil {
			return err
		}
		return path(d.Path)
	default:
		return fmt.Errorf("op not in allowlist: %q", d.Op)
	}
}

// Describe renders a short human line for the Okular policy event / ack receipt.
func Describe(d Diff) string {
	switch d.Op {
	case "egress_allow_add":
		return fmt.Sprintf("allow %s → %s (R11 egress)", d.Agent, d.Dest)
	case "egress_allow_remove":
		return fmt.Sprintf("remove %s from %s egress allowlist (R11)", d.Dest, d.Agent)
	case "r1_chain_limit":
		if d.Host != "" {
			return fmt.Sprintf("R1 chain limit → %d on %s", d.Limit, d.Host)
		}
		return fmt.Sprintf("R1 chain limit → %d (default)", d.Limit)
	case "host_mode":
		return fmt.Sprintf("%s → %s mode", d.Host, d.Mode)
	case "r3_exception_add":
		return fmt.Sprintf("R3 exception: %s may read %s", d.Agent, d.Path)
	case "r3_exception_remove":
		return fmt.Sprintf("remove R3 exception for %s: %s", d.Agent, d.Path)
	default:
		return "config change"
	}
}
