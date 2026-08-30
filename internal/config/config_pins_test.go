package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPinsAndCanaryDefaults(t *testing.T) {
	c := Default()
	if c.Pins.SweepSeconds != 30 {
		t.Fatalf("sweep default: %d", c.Pins.SweepSeconds)
	}
	if c.Canary.Mode != "alert" {
		t.Fatalf("canary mode default: %q", c.Canary.Mode)
	}
	if c.Pins.Enabled || len(c.Pins.Paths) != 0 {
		t.Fatalf("pins must be opt-in and empty by default: %+v", c.Pins)
	}
}

func TestPinsAndCanaryParse(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "oknek.yaml")
	y := "pins:\n  enabled: true\n  enforce: true\n  paths: [\"~/.claude/settings.json\", \".claude/skills/**\"]\ncanary:\n  enabled: true\n  mode: block\n  plant: [\"~/.aws/credentials\"]\n"
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Pins.Enabled || !c.Pins.Enforce || len(c.Pins.Paths) != 2 || c.Pins.SweepSeconds != 30 {
		t.Fatalf("pins parse: %+v", c.Pins)
	}
	if !c.Canary.Enabled || c.Canary.Mode != "block" || len(c.Canary.Plant) != 1 {
		t.Fatalf("canary parse: %+v", c.Canary)
	}
}

// Enabled with no paths = the default artifact set, so a one-line `pins: {enabled: true}` is useful.
func TestPinsEnabledEmptyPathsGetsDefaults(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "oknek.yaml")
	if err := os.WriteFile(p, []byte("pins:\n  enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Pins.Paths) != len(DefaultPinPaths) {
		t.Fatalf("want %d default paths, got %v", len(DefaultPinPaths), c.Pins.Paths)
	}
}

func TestRuleOfTwoParse(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "oknek.yaml")
	y := "rule_of_two:\n  untrusted_dirs: [/workspace, ~/Downloads]\n  private_files: [/srv/customer.db]\nokredo:\n  enabled: true\n  profiles:\n    cc:\n      allow_egress: [\"1.1.1.1:443\"]\n      rule_of_two: enforce\n    plain:\n      allow_egress: []\n"
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.RuleOfTwo.UntrustedDirs) != 2 || len(c.RuleOfTwo.PrivateFiles) != 1 {
		t.Fatalf("lists: %+v", c.RuleOfTwo)
	}
	if c.Okredo.Profiles["cc"].RuleOfTwo != "enforce" || c.Okredo.Profiles["plain"].RuleOfTwo != "" {
		t.Fatalf("profile modes: %+v", c.Okredo.Profiles)
	}
}
