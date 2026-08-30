package mcp

import (
	"os"
	"path/filepath"
	"testing"
)

func w(t *testing.T, p, s string) {
	t.Helper()
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMergesManifestsProjectWins(t *testing.T) {
	cwd, home := t.TempDir(), t.TempDir()
	w(t, filepath.Join(cwd, ".mcp.json"), `{"mcpServers":{"github":{"command":"npx","args":["-y","@modelcontextprotocol/server-github"]},"docs":{"type":"http","url":"https://mcp.example.com/v1"}}}`)
	w(t, filepath.Join(home, ".claude.json"), `{"mcpServers":{"github":{"command":"OTHER"},"fs":{"command":"/usr/local/bin/mcp-fs","args":["--root","/srv"]}},"projects":{"`+cwd+`":{"mcpServers":{"proj":{"command":"python3","args":["-m","proj_mcp"]}}}}}`)
	w(t, filepath.Join(cwd, ".cursor", "mcp.json"), `{"mcpServers":{"sse1":{"type":"sse","url":"http://10.0.0.5:8080/sse"}}}`)
	ss := Load(cwd, home)
	names := map[string]Server{}
	for _, s := range ss {
		names[s.Name] = s
	}
	if len(ss) != 5 {
		t.Fatalf("want 5 servers, got %d: %+v", len(ss), ss)
	}
	if names["github"].Command != "npx" || names["github"].Transport != "stdio" {
		t.Fatalf("project .mcp.json must win: %+v", names["github"])
	}
	if names["docs"].Transport != "http" || names["docs"].Host != "mcp.example.com" {
		t.Fatalf("http: %+v", names["docs"])
	}
	if names["sse1"].Transport != "sse" || names["sse1"].Host != "10.0.0.5" {
		t.Fatalf("sse: %+v", names["sse1"])
	}
	if names["proj"].Args[1] != "proj_mcp" || names["fs"].Command != "/usr/local/bin/mcp-fs" {
		t.Fatalf("home + project scopes: %+v %+v", names["proj"], names["fs"])
	}
}

func TestMatchCmdlines(t *testing.T) {
	gh := Server{Name: "github", Transport: "stdio", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-github"}}
	fs := Server{Name: "fs", Transport: "stdio", Command: "/usr/local/bin/mcp-fs", Args: []string{"--root", "/srv"}}
	sh := Server{Name: "sh", Transport: "stdio", Command: "/tmp/w/srvA", Args: []string{"--name", "alpha"}}
	http := Server{Name: "docs", Transport: "http", URL: "https://x/y"}
	cases := []struct {
		argv []string
		s    Server
		want bool
	}{
		{ParseCmdline([]byte("npx\x00-y\x00@modelcontextprotocol/server-github\x00")), gh, true},
		{[]string{"node", "/usr/lib/node_modules/npm/bin/npx-cli.js", "-y", "@modelcontextprotocol/server-github"}, gh, false}, // no "npx" token
		{[]string{"node", "/usr/lib/node_modules/npm/bin/npx", "-y", "@modelcontextprotocol/server-github"}, gh, true},        // basename npx
		{[]string{"/usr/local/bin/mcp-fs", "--root", "/srv"}, fs, true},
		{[]string{"/usr/local/bin/mcp-fs", "--root", "/other"}, fs, false},
		{[]string{"/bin/bash", "/tmp/w/srvA", "--name", "alpha"}, sh, true}, // script exec'd via interpreter
		{[]string{"/bin/bash", "/tmp/w/srvB", "--name", "alpha"}, sh, false},
		{[]string{"curl", "https://x/y"}, http, false}, // remote servers are never child processes
	}
	for i, c := range cases {
		if got := Match(c.argv, c.s); got != c.want {
			t.Errorf("case %d %v vs %s: got %v want %v", i, c.argv, c.s.Name, got, c.want)
		}
	}
}

func TestSignificantSkipsFlagsAndShortTokens(t *testing.T) {
	s := Server{Command: "/opt/x/bin/server", Args: []string{"-v", "--port", "80", "cfg.yaml", "ab"}}
	got := Significant(s)
	want := []string{"server", "cfg.yaml"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("significant: %v", got)
	}
}
