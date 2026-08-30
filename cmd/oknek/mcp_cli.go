package main

import (
	"fmt"
	"os"
	"strings"
)

// oknek mcp   show every MCP server each agent declared: jailed identity, grants, pids, what it reached, blocks
func runMCP(configPath string) {
	c, _ := client(configPath)
	var s struct {
		Enabled bool `json:"enabled"`
		Enforce bool `json:"enforce"`
		Kernel  bool `json:"kernel"`
		Servers []struct {
			Agent     string   `json:"agent"`
			Name      string   `json:"name"`
			Transport string   `json:"transport"`
			Command   string   `json:"command"`
			Args      []string `json:"args"`
			Host      string   `json:"host"`
			Source    string   `json:"source"`
			PolicyID  int      `json:"policy_id"`
			Grants    []string `json:"grants"`
			PidsSeen  int      `json:"pids_seen"`
			PidsLive  int      `json:"pids_live"`
			Observed  []string `json:"observed"`
			Blocks    int      `json:"blocks"`
		} `json:"servers"`
	}
	if err := c.Call("mcp.status", nil, &s); err != nil {
		fmt.Fprintf(os.Stderr, "oknek: mcp: %v\n", err)
		os.Exit(1)
	}
	if !s.Enabled {
		fmt.Println("mcp (R24 MCP server jail) is disabled (set mcp.enabled in oknek.yaml)")
		return
	}
	mode := "OBSERVE · recording what each server reaches"
	if s.Enforce && s.Kernel {
		mode = "ENFORCE · stdio servers jailed to their grants at the kernel"
	}
	fmt.Printf("oknek mcp · R24 · %s\n", mode)
	if len(s.Servers) == 0 {
		fmt.Println("   no MCP servers declared by any running agent (manifests are read at `oknek run`)")
		return
	}
	for _, v := range s.Servers {
		id := "remote (grant host on the agent's profile)"
		if v.Transport == "stdio" {
			if v.PolicyID > 0 {
				id = fmt.Sprintf("jailed · policy %d", v.PolicyID)
			} else {
				id = "observing"
			}
		}
		what := v.Command + " " + strings.Join(v.Args, " ")
		if v.Transport != "stdio" {
			what = v.Host
		}
		fmt.Printf("   %s/%-14s %-6s %s\n", v.Agent, v.Name, v.Transport, id)
		fmt.Printf("      %s\n", strings.TrimSpace(what))
		if len(v.Grants) > 0 {
			fmt.Printf("      grants:   %s\n", strings.Join(v.Grants, ", "))
		}
		if v.Transport == "stdio" {
			fmt.Printf("      pids:     %d seen · %d live   blocks: %d\n", v.PidsSeen, v.PidsLive, v.Blocks)
		}
		if len(v.Observed) > 0 {
			fmt.Printf("      reached:  %s\n", strings.Join(v.Observed, ", "))
		}
	}
}
