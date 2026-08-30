package main

// Okredo Attest — daemon half. Mints a kernel-attested identity token for a running
// watched agent: subject spiffe://oknek/<install>/host/<host>/agent/<agent>, signed
// with the Okular ed25519 key, carrying the enforcement posture exactly as `oknek
// doctor` would print it, the Okular head/anchor, the Okredo profile and the R21
// session taint. Pushed to a webhook on register, on taint clear, and on an interval.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/oknek/oknek/internal/config"
	"github.com/oknek/oknek/internal/hooks/ebpf"
	"github.com/oknek/oknek/internal/identity"
	"github.com/oknek/oknek/internal/ipc"
	"github.com/oknek/oknek/internal/okular"
	"github.com/oknek/oknek/internal/store"
)

type identityService struct {
	cfg          *config.Config
	db           *store.Store
	loader       *ebpf.Loader
	ledger       *okular.Ledger
	profilesByID map[uint16]string
	doctor       func() map[string]interface{}
	poster       *identity.Poster
	host         string
}

func newIdentityService(cfg *config.Config, db *store.Store, loader *ebpf.Loader, ledger *okular.Ledger,
	profiles map[string]uint16, doctor func() map[string]interface{}) *identityService {
	byID := map[uint16]string{}
	for name, id := range profiles {
		byID[id] = name
	}
	h, _ := os.Hostname()
	s := &identityService{cfg: cfg, db: db, loader: loader, ledger: ledger, profilesByID: byID, doctor: doctor, host: h}
	if cfg.Identity.Enabled {
		s.poster = identity.New(cfg.Identity.WebhookURL, cfg.Identity.Headers)
		switch {
		case ledger == nil:
			log.Printf("identity: enabled but okular is off — Okredo Attest needs the audit signing key; DISABLED")
		case s.poster == nil:
			log.Printf("identity: Okredo Attest ENABLED (issue-only; no webhook_url) · ttl %ds", cfg.Identity.TTLSeconds)
		default:
			log.Printf("identity: Okredo Attest ENABLED -> %s · every %ds · ttl %ds", cfg.Identity.WebhookURL, cfg.Identity.IntervalSeconds, cfg.Identity.TTLSeconds)
		}
	}
	return s
}

func (s *identityService) ready() error {
	if s.ledger == nil {
		return errors.New("identity: okular must be enabled (the attestation is signed with the audit key)")
	}
	return nil
}

// Issue mints a token for a registered agent. ttl<=0 = configured default.
func (s *identityService) Issue(agent string, ttl time.Duration, aud string) (string, identity.Claims, error) {
	var c identity.Claims
	if err := s.ready(); err != nil {
		return "", c, err
	}
	agents := s.loader.Agents()
	pid, ok := agents[agent]
	if !ok {
		return "", c, fmt.Errorf("identity: agent %q is not registered (start it with `oknek run --agent %s`)", agent, agent)
	}
	policy := s.loader.PolicyOf(pid)
	profile := s.profilesByID[policy]
	doc := map[string]interface{}{}
	if s.doctor != nil {
		doc = s.doctor()
	}
	pins := 0
	if l, ok := doc["pins"].([]string); ok {
		pins = len(l)
	}
	expected, _ := doc["pins_expected"].(int)
	verdict, _ := doc["verdict"].(string)
	mode, _ := doc["hook_mode"].(string)
	egressEnf, _ := doc["egress_enforce"].(bool)
	sgEnf, _ := doc["self_guard_enforce"].(bool)
	taint := s.loader.Taints()[agent]
	headSeq, headHash := s.ledger.Head()
	var anchorSeq int64
	if a := s.ledger.LatestAnchor(); a != nil {
		anchorSeq = a.Seq
	}
	if ttl <= 0 {
		ttl = time.Duration(s.cfg.Identity.TTLSeconds) * time.Second
	}
	if aud == "" {
		aud = s.cfg.Identity.Audience
	}
	now := time.Now().Unix()
	c = identity.Claims{
		Iss: "oknek",
		Sub: identity.SPIFFE(s.db.Meta("install_id"), s.host, agent),
		Iat: now,
		Exp: now + int64(ttl.Seconds()),
		Oknek: map[string]interface{}{
			"version":    version,
			"install_id": s.db.Meta("install_id"),
			"host":       s.host,
			"agent":      agent,
			"profile":    profile,
			"policy_id":  policy,
			"pid":        pid,
			"enforcement": map[string]interface{}{
				"verdict":             verdict,
				"mode":                mode,
				"kernel_enforced":     verdict == "KERNEL-ENFORCED",
				"pins":                fmt.Sprintf("%d/%d", pins, expected),
				"egress_jail":         enfWord(egressEnf),
				"self_guard":          enfWord(sgEnf),
				"rule_of_two_profile": s.cfg.Okredo.Profiles[profile].RuleOfTwo,
			},
			"taint":  map[string]interface{}{"bits": taint, "u": taint&1 != 0, "p": taint&2 != 0, "x": taint&4 != 0},
			"okular": map[string]interface{}{"head_seq": headSeq, "head_hash": headHash, "anchor_seq": anchorSeq},
		},
	}
	if aud != "" {
		c.Aud = []string{aud}
	}
	tok, err := identity.Issue(c, s.ledger.Sign, identity.KID(s.ledger.PubKey()))
	return tok, c, err
}

func enfWord(b bool) string {
	if b {
		return "enforcing"
	}
	return "observe"
}

// Push mints and posts for one agent (register / clear / refresh). nil-safe, async.
func (s *identityService) Push(agent, event string) {
	if s == nil || s.poster == nil || !s.cfg.Identity.Enabled {
		return
	}
	tok, _, err := s.Issue(agent, 0, "")
	if err != nil {
		return
	}
	s.poster.Post(tok, event, agent)
}

// RunPusher refreshes every live agent's attestation on the configured interval.
func (s *identityService) RunPusher(ctx context.Context) {
	if s.poster == nil {
		return
	}
	iv := time.Duration(s.cfg.Identity.IntervalSeconds) * time.Second
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for agent := range s.loader.Agents() {
				s.Push(agent, "refresh")
			}
		}
	}
}

func identityIssueHandler(s *identityService) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		var in struct {
			Agent      string `json:"agent"`
			TTLSeconds int    `json:"ttl_seconds"`
			Aud        string `json:"aud"`
		}
		if len(req.Params) > 0 {
			_ = json.Unmarshal(req.Params, &in)
		}
		if in.Agent == "" {
			return nil, errors.New("identity.issue: agent required")
		}
		tok, claims, err := s.Issue(in.Agent, time.Duration(in.TTLSeconds)*time.Second, in.Aud)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"token": tok, "claims": claims}, nil
	}
}

func identityPubkeyHandler(s *identityService) ipc.Handler {
	return func(ctx context.Context, req *ipc.Request) (interface{}, error) {
		if err := s.ready(); err != nil {
			return nil, err
		}
		pub := s.ledger.PubKey()
		return map[string]interface{}{"pubkey_hex": s.ledger.PubKeyHex(), "kid": identity.KID(pub), "jwks": identity.JWKS(pub)}, nil
	}
}
