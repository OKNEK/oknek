// Package mcp reads the MCP server manifests an agent uses (.mcp.json,
// ~/.claude.json, .cursor/mcp.json) and matches spawned processes against them,
// so each stdio server can be bound to its own kernel identity (R24).
package mcp

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Server is one declared MCP server.
type Server struct {
	Name      string   `json:"name"`
	Transport string   `json:"transport"` // stdio | http | sse
	Command   string   `json:"command,omitempty"`
	Args      []string `json:"args,omitempty"`
	URL       string   `json:"url,omitempty"`
	Host      string   `json:"host,omitempty"` // URL host (http/sse)
	Source    string   `json:"source"`         // manifest file it came from
}

type rawServer struct {
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	URL     string   `json:"url"`
}

type rawManifest struct {
	MCPServers map[string]rawServer `json:"mcpServers"`
	Projects   map[string]struct {
		MCPServers map[string]rawServer `json:"mcpServers"`
	} `json:"projects"`
}

// Paths returns the manifest files that apply to an agent with this cwd + HOME.
func Paths(cwd, home string) []string {
	var out []string
	if cwd != "" {
		out = append(out, filepath.Join(cwd, ".mcp.json"), filepath.Join(cwd, ".cursor", "mcp.json"))
	}
	if home != "" {
		out = append(out, filepath.Join(home, ".claude.json"), filepath.Join(home, ".cursor", "mcp.json"))
	}
	return out
}

// Load parses every manifest that exists for (cwd, home). Later files do not
// override earlier ones: the project-local .mcp.json wins on a name clash.
func Load(cwd, home string) []Server {
	seen := map[string]bool{}
	var out []Server
	for _, p := range Paths(cwd, home) {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var m rawManifest
		if json.Unmarshal(b, &m) != nil {
			continue
		}
		add := func(name string, r rawServer) {
			if seen[name] {
				return
			}
			seen[name] = true
			out = append(out, fromRaw(name, r, p))
		}
		for name, r := range m.MCPServers {
			add(name, r)
		}
		if cwd != "" {
			if pr, ok := m.Projects[cwd]; ok {
				for name, r := range pr.MCPServers {
					add(name, r)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func fromRaw(name string, r rawServer, source string) Server {
	s := Server{Name: name, Command: r.Command, Args: r.Args, URL: r.URL, Source: source}
	t := strings.ToLower(r.Type)
	switch {
	case r.URL != "" && (t == "http" || t == "sse" || t == "streamable-http" || t == ""):
		if t == "" || t == "streamable-http" {
			t = "http"
		}
		s.Transport = t
		if u, err := url.Parse(r.URL); err == nil {
			s.Host = u.Hostname()
		}
	default:
		s.Transport = "stdio"
	}
	return s
}

// Significant returns the tokens of a stdio server's command line that identify
// it: the command basename plus every arg that is not a short flag. `npx -y
// @scope/server-x` -> ["npx", "@scope/server-x"].
func Significant(s Server) []string {
	var out []string
	if s.Command != "" {
		out = append(out, filepath.Base(s.Command))
	}
	for _, a := range s.Args {
		if strings.HasPrefix(a, "-") || len(a) < 3 {
			continue
		}
		out = append(out, a)
	}
	return out
}

// Match reports whether argv (from /proc/<pid>/cmdline) is this stdio server.
// Every significant token must appear as an argv element or as the basename of
// one (npx execs node with the CLI path; scripts exec their interpreter with the
// script path).
func Match(argv []string, s Server) bool {
	if s.Transport != "stdio" {
		return false
	}
	sig := Significant(s)
	if len(sig) == 0 {
		return false
	}
	for _, tok := range sig {
		found := false
		for _, a := range argv {
			if a == tok || filepath.Base(a) == tok || strings.HasSuffix(a, "/"+tok) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// ParseCmdline splits a /proc/<pid>/cmdline buffer.
func ParseCmdline(b []byte) []string {
	parts := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
