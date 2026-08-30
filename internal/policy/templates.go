package policy

// Templates returns the built-in starter policies. All ship in `mode: observe` (default-deny,
// but logging-only) so an operator reviews the would-block report before flipping to enforce.
// Customize the selector + paths/CIDRs for your environment, lint, then apply.
func Templates() map[string]string {
	return map[string]string{
		"coding-agent":  codingAgent,
		"browser-agent": browserAgent,
		"cx-agent":      cxAgent,
	}
}

const codingAgent = `apiVersion: oknek/v1
kind: AgentPolicy
metadata:
  name: coding-agent
  version: 1
selector:
  agentId: example-coding-agent   # replace: your Okredo agent id / cgroup / container image
mode: observe                     # review would-blocks, then flip to enforce
default: deny
allow:
  exec: [/usr/bin/python3, /usr/bin/node, /usr/bin/git, /bin/sh]
  files:
    read: ["/home/agent/workspace/**", "/etc/ssl/certs/**"]
    write: ["/home/agent/workspace/**", "/tmp/agent/**"]
    deny: ["/home/agent/workspace/.env", "~/.aws/**", "~/.ssh/**"]
  network:
    egress:
      - cidr: 10.0.0.0/8
      - port: 443
      - resolver: 10.0.0.53
    deny:
      - cidr: 169.254.169.254/32   # cloud metadata
  caps:
    deny: [ptrace, bpf, kmod, mount, raw_socket]
audit: full
`

const browserAgent = `apiVersion: oknek/v1
kind: AgentPolicy
metadata:
  name: browser-agent
  version: 1
selector:
  agentId: example-browser-agent
mode: observe
default: deny
allow:
  exec: [/usr/bin/chromium, /usr/bin/chromedriver]
  files:
    read: ["/home/agent/.config/chromium/**", "/etc/ssl/certs/**"]
    write: ["/home/agent/.config/chromium/**", "/tmp/agent/**"]
    deny: ["~/.aws/**", "~/.ssh/**", "/home/agent/.env"]
  network:
    egress:
      - port: 443
      - resolver: 10.0.0.53
    deny:
      - cidr: 10.0.0.0/8           # block internal pivots (SSRF)
      - cidr: 169.254.169.254/32   # block cloud metadata
  caps:
    deny: [ptrace, bpf, kmod, mount, raw_socket]
audit: full
`

const cxAgent = `apiVersion: oknek/v1
kind: AgentPolicy
metadata:
  name: cx-agent
  version: 1
selector:
  agentId: example-cx-agent
mode: observe
default: deny
allow:
  exec: [/usr/bin/node]
  files:
    read: ["/etc/ssl/certs/**"]
    write: ["/tmp/agent/**"]
    deny: ["~/.aws/**", "~/.ssh/**"]
  network:
    egress:
      - cidr: 10.20.0.0/16         # the backend API subnet
      - port: 443
      - resolver: 10.0.0.53
    deny:
      - cidr: 169.254.169.254/32
  caps:
    deny: [ptrace, bpf, kmod, mount, raw_socket, bind]
audit: full
`
