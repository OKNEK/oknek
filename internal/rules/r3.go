package rules

import (
	"context"
	"path/filepath"
	"strings"
)

// R3 — plaintext credential read.
//
// Fires when an AI agent process opens a file matching the credential
// pattern list. Default action is Block — credential files should never
// be opened by an agent process under normal operation.
//
// Validation:
//   - Sysdig (March 2026) — agent config directories like ~/.claude/,
//     ~/.gemini/, ~/.codex/ have become the new ~/.aws/credentials in
//     terms of attacker priority.
//   - Anthropic's own disclosure that Claude Code stores plaintext OAuth
//     tokens in ~/.claude.json.
//
// Patterns are organized by match type for clarity (exact path / suffix /
// substring / basename) and evaluated in a single pass.
type R3 struct {
	ExactPaths  []string // absolute path equals one of these
	Suffixes    []string // path ends with one of these
	Substrings  []string // path contains one of these
	Basenames   []string // filepath.Base(path) equals one of these
	Action      Verdict
}

// Default credential file patterns. Users can extend any of the four lists
// via config to add organization-specific secret stores.
var (
	DefaultR3ExactPaths = []string{
		"/etc/shadow",
		"/etc/passwd",
		"/etc/group",
		"/etc/gshadow",
	}
	DefaultR3Suffixes = []string{
		"/.aws/credentials",
		"/.aws/config",
		"/.claude.json",
		"/.claudeconfig.json",
		"/.netrc",
		"/.pgpass",
		"/.npmrc", // contains npm auth tokens
	}
	DefaultR3Substrings = []string{
		"/.ssh/id_",       // any SSH private key (id_rsa, id_ed25519, id_ecdsa, ...)
		"/.ssh/identity",  // legacy SSH key naming
		"/.gnupg/",        // GnuPG keyring
		"/.kube/config",   // kubeconfig with cluster credentials
		"/.docker/config.json", // docker registry auth
		"/.gemini/",       // Gemini config dir
		"/.codex/",        // Codex config dir
		"/.claude/credentials", // Claude credentials subpath
	}
	DefaultR3Basenames = []string{
		".env",
		".env.local",
		".env.production",
		".env.development",
		".env.staging",
	}
)

// NewR3 returns Rule 3 with default patterns and Block action.
func NewR3() *R3 {
	return &R3{
		ExactPaths: append([]string(nil), DefaultR3ExactPaths...),
		Suffixes:   append([]string(nil), DefaultR3Suffixes...),
		Substrings: append([]string(nil), DefaultR3Substrings...),
		Basenames:  append([]string(nil), DefaultR3Basenames...),
		Action:     VerdictBlock,
	}
}

func (r *R3) ID() string   { return "R3" }
func (r *R3) Name() string { return "plaintext credential read" }
func (r *R3) Kind() Kind   { return KindFileOpened }

func (r *R3) Match(ctx context.Context, e Event) (Match, bool) {
	p, ok := e.Payload.(FileOpenPayload)
	if !ok {
		return Match{}, false
	}
	matched, category := r.matchCredentialPath(p.Path)
	if matched == "" {
		return Match{}, false
	}
	return Match{
		RuleID:  r.ID(),
		Name:    r.Name(),
		Verdict: r.Action,
		Evidence: map[string]interface{}{
			"path":             p.Path,
			"matched_pattern":  matched,
			"matched_category": category,
			"mode":             p.Mode,
			"process":          p.Process,
			"agent_identifier": e.AgentID,
			"pid":              e.PID,
			"ppid":             e.PPID,
		},
	}, true
}

// matchCredentialPath returns the matching pattern and its category, or "" if
// nothing matches.
//
// Public-key-style exclusions (.pub, .crt, .cer, .pem-cert) are filtered before
// substring matching because shareable certificates and public keys are not
// credentials by definition. Adjust DefaultR3Exclusions if your environment
// treats certain .pub files as sensitive.
func (r *R3) matchCredentialPath(path string) (pattern, category string) {
	for _, p := range r.ExactPaths {
		if path == p {
			return p, "exact"
		}
	}
	for _, s := range r.Suffixes {
		if strings.HasSuffix(path, s) {
			return s, "suffix"
		}
	}
	if !isPublicKeyOrCert(path) {
		for _, s := range r.Substrings {
			if strings.Contains(path, s) {
				return s, "substring"
			}
		}
	}
	base := filepath.Base(path)
	for _, b := range r.Basenames {
		if base == b {
			return b, "basename"
		}
	}
	return "", ""
}

// isPublicKeyOrCert returns true when path looks like a shareable public key
// or certificate (not a credential).
func isPublicKeyOrCert(path string) bool {
	ext := filepath.Ext(path)
	switch ext {
	case ".pub", ".crt", ".cer":
		return true
	}
	return false
}
