package policy

import "testing"

const goodYAML = `
apiVersion: oknek/v1
kind: AgentPolicy
metadata:
  name: coding-agent
  version: 3
selector:
  agentId: devin-worker
mode: enforce
default: deny
allow:
  exec:
    - /usr/bin/python3
    - /usr/bin/git
  files:
    read: ["/home/agent/workspace/**", "/etc/ssl/certs/**"]
    write: ["/home/agent/workspace/**"]
    deny: ["/home/agent/workspace/.env", "~/.aws/**"]
  network:
    egress:
      - cidr: 10.0.0.0/8
      - port: 443
      - resolver: 10.0.0.53
    deny:
      - cidr: 169.254.169.254/32
  caps:
    deny: [ptrace, bpf, kmod, mount, raw_socket]
audit: full
`

func TestParseValid(t *testing.T) {
	p, err := Parse([]byte(goodYAML))
	if err != nil {
		t.Fatal(err)
	}
	if p.Metadata.Name != "coding-agent" || p.Mode != "enforce" || p.Default != "deny" {
		t.Fatalf("parse mismatch: %+v", p.Metadata)
	}
	if len(p.Allow.Exec) != 2 || len(p.Allow.Network.Egress) != 3 || len(p.Allow.Caps.Deny) != 5 {
		t.Fatalf("nested parse wrong: exec=%d egress=%d caps=%d", len(p.Allow.Exec), len(p.Allow.Network.Egress), len(p.Allow.Caps.Deny))
	}
}

func TestLintCleanPolicy(t *testing.T) {
	p, _ := Parse([]byte(goodYAML))
	r := Lint(p)
	if !r.OK() {
		t.Fatalf("clean policy should lint OK, errors=%v", r.Errors)
	}
}

// THE brick-the-box guard: enforce + default-deny with NO selector would apply host-wide.
func TestLintRejectsHostWideDenyAll(t *testing.T) {
	p, _ := Parse([]byte(goodYAML))
	p.Selector = Selector{} // no selector at all
	r := Lint(p)
	if r.OK() || !hasErr(r, "selector") {
		t.Fatalf("enforce+deny with no selector must ERROR (brick risk), got %+v", r)
	}
}

// envLabel alone is spoofable — a warning, not a hard error, but it must be flagged.
func TestLintWarnsEnvLabelOnlySelector(t *testing.T) {
	p, _ := Parse([]byte(goodYAML))
	p.Selector = Selector{EnvLabel: "agent=devin"}
	r := Lint(p)
	if !hasWarn(r, "spoof") {
		t.Fatalf("envLabel-only selector under enforce should warn (spoofable), got %+v", r)
	}
}

func TestLintRejectsBadMode(t *testing.T) {
	p, _ := Parse([]byte(goodYAML))
	p.Mode = "whatever"
	if r := Lint(p); r.OK() || !hasErr(r, "mode") {
		t.Fatalf("bad mode must error, got %+v", r)
	}
}

func TestLintWarnsDefaultNotDeny(t *testing.T) {
	p, _ := Parse([]byte(goodYAML))
	p.Default = "allow"
	if r := Lint(p); !hasWarn(r, "default") {
		t.Fatalf("default:allow should warn (deny is the spine), got %+v", r)
	}
}

// Egress allowlist under default-deny with no resolver breaks DNS — flag it.
func TestLintWarnsEgressLockedNoResolver(t *testing.T) {
	p, _ := Parse([]byte(goodYAML))
	p.Allow.Network.Egress = []EgressRule{{CIDR: "10.0.0.0/8"}, {Port: 443}} // no resolver
	r := Lint(p)
	if !hasWarn(r, "resolver") {
		t.Fatalf("egress locked without a resolver should warn, got %+v", r)
	}
}

func TestCompileCodingTemplate(t *testing.T) {
	p, _ := Parse([]byte(Templates()["coding-agent"]))
	c, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Exec) != 4 || len(c.Resolvers) != 1 || c.CapsDeny == 0 {
		t.Fatalf("compile wrong: exec=%d resolvers=%d caps=%d", len(c.Exec), len(c.Resolvers), c.CapsDeny)
	}
	if c.Enforce { // template is observe
		t.Fatal("observe template should compile Enforce=false")
	}
}

func TestCompileCapsBitmask(t *testing.T) {
	p, _ := Parse([]byte(goodYAML))
	p.Allow.Caps.Deny = []string{"ptrace", "bpf"}
	c, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.CapsDeny != (capBits["ptrace"] | capBits["bpf"]) {
		t.Fatalf("caps bitmask = %d, want %d", c.CapsDeny, capBits["ptrace"]|capBits["bpf"])
	}
}

func TestCompileRejectsBadCIDR(t *testing.T) {
	p, _ := Parse([]byte(goodYAML))
	p.Allow.Network.Egress = []EgressRule{{CIDR: "not-a-cidr"}}
	if _, err := Compile(p); err == nil {
		t.Fatal("invalid cidr must error")
	}
}

func TestCompileRejectsUnknownCap(t *testing.T) {
	p, _ := Parse([]byte(goodYAML))
	p.Allow.Caps.Deny = []string{"frobnicate"}
	if _, err := Compile(p); err == nil {
		t.Fatal("unknown capability must error")
	}
}

func TestCompileRejectsRelativeExec(t *testing.T) {
	p, _ := Parse([]byte(goodYAML))
	p.Allow.Exec = []string{"python3"} // not absolute
	if _, err := Compile(p); err == nil {
		t.Fatal("relative exec path must error")
	}
}

func TestCompileAllTemplates(t *testing.T) {
	for name, y := range Templates() {
		p, _ := Parse([]byte(y))
		if _, err := Compile(p); err != nil {
			t.Fatalf("template %s compile: %v", name, err)
		}
	}
}

// Every built-in template must parse and lint with NO errors (warnings allowed).
func TestTemplatesLintClean(t *testing.T) {
	for name, y := range Templates() {
		p, err := Parse([]byte(y))
		if err != nil {
			t.Fatalf("template %s parse: %v", name, err)
		}
		if r := Lint(p); !r.OK() {
			t.Fatalf("template %s has lint ERRORS: %v", name, r.Errors)
		}
		if p.Metadata.Name != name {
			t.Fatalf("template key %q != metadata.name %q", name, p.Metadata.Name)
		}
	}
}

func hasErr(r LintResult, s string) bool  { return contains(r.Errors, s) }
func hasWarn(r LintResult, s string) bool { return contains(r.Warnings, s) }
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if containsStr(x, s) {
			return true
		}
	}
	return false
}
func containsStr(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
