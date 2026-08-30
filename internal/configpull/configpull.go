// Package configpull is the daemon side of Dean's approve→apply loop. The daemon
// polls the dashboard for human-APPROVED config changes (outbound-only, mirroring
// the feed poster), applies ONLY whitelisted tuning, seals each change into the
// Okular tamper-proof ledger, and acks.
//
// ORDER IS RECORD-FIRST, FAIL-CLOSED (matching internal/okular/control_events):
//
//	validate → SEAL (Okular, fail-closed) → apply → ack(with seal receipt)
//
// A change is never applied unless it first validates against the allowlist AND is
// durably sealed. If sealing or applying fails, the change is NOT acked — it stays
// pending and is retried on the next poll. Dean can only ever *propose*; a human
// approved; this loop is the only thing that touches the running config, and it is
// bounded to the same four tunable surfaces as the server-side validator.
package configpull

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// Diff is one approved config change. Mirrors oknek-web/functions/_lib/policy.js.
type Diff struct {
	Op    string `json:"op"`
	Agent string `json:"agent,omitempty"`
	Dest  string `json:"dest,omitempty"`
	Host  string `json:"host,omitempty"`
	Mode  string `json:"mode,omitempty"`
	Path  string `json:"path,omitempty"`
	Limit int    `json:"limit,omitempty"`
}

// change is one row from GET /api/config/pending.
type change struct {
	ID   string `json:"id"`
	Diff Diff   `json:"diff"`
}

type pendingResp struct {
	OK      bool     `json:"ok"`
	Changes []change `json:"changes"`
}

// Applier folds a validated diff into the running/effective policy. The shipped
// OverlayStore persists it to disk; a Linux build can wrap it to also hot-apply the
// fields the eBPF loader supports (R11 egress adds). Never receives an unvalidated diff.
type Applier interface {
	Apply(d Diff) error
}

// Sealer records an applied policy change into the tamper-proof ledger, record-first
// and fail-closed: a non-nil error means "not durably sealed — do not proceed".
// enforce=true marks a host observe→enforce flip (the loud POLICY-ENFORCE event).
// Returns a short receipt (e.g. "anchor#12 seq=340 ab12cd…") echoed back on ack.
type Sealer interface {
	Seal(name string, version int, enforce bool) (receipt string, err error)
}

// Puller runs the config-pull loop.
type Puller struct {
	pendingURL string
	ackURL     string
	key        string
	client     *http.Client
	applier    Applier
	sealer     Sealer
	logger     *log.Logger
	version    int // monotonic, stamped onto each Okular policy event
}

// New returns a Puller, or nil if any dependency is missing (loop disabled). The
// loop REQUIRES a sealer — an unsealed policy change must never be applied.
func New(pendingURL, ackURL, key string, applier Applier, sealer Sealer, logger *log.Logger) *Puller {
	if pendingURL == "" || ackURL == "" || key == "" || applier == nil || sealer == nil {
		return nil
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Puller{
		pendingURL: pendingURL, ackURL: ackURL, key: key,
		client: &http.Client{Timeout: 10 * time.Second},
		applier: applier, sealer: sealer, logger: logger,
	}
}

// Run polls every interval until ctx is cancelled. Same shape as the other daemon
// goroutines (ticker + ctx.Done). One immediate pull, then on the tick.
func (p *Puller) Run(ctx context.Context, interval time.Duration) {
	if p == nil {
		return
	}
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if err := p.PullOnce(ctx); err != nil {
		p.logger.Printf("configpull: %v", err)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := p.PullOnce(ctx); err != nil {
				p.logger.Printf("configpull: %v", err)
			}
		}
	}
}

// PullOnce fetches pending approved changes and applies each (seal → apply → ack).
// A failure on one change is logged and skipped; it stays pending for the next poll.
func (p *Puller) PullOnce(ctx context.Context) error {
	changes, err := p.fetchPending(ctx)
	if err != nil {
		return err
	}
	for _, c := range changes {
		if err := p.handle(ctx, c); err != nil {
			p.logger.Printf("configpull: change %s not applied (stays pending): %v", c.ID, err)
		}
	}
	return nil
}

func (p *Puller) handle(ctx context.Context, c change) error {
	// 1. Validate against the allowlist (defense in depth — the server validated too).
	if err := Validate(c.Diff); err != nil {
		return fmt.Errorf("rejected by allowlist: %w", err)
	}
	// 2. Seal FIRST (record-first, fail-closed). Never apply an unsealed change.
	p.version++
	enforce := c.Diff.Op == "host_mode" && c.Diff.Mode == "enforce"
	receipt, err := p.sealer.Seal(Describe(c.Diff), p.version, enforce)
	if err != nil {
		p.version-- // seal didn't take; don't burn the version number
		return fmt.Errorf("seal failed (fail-closed): %w", err)
	}
	// 3. Apply.
	if err := p.applier.Apply(c.Diff); err != nil {
		return fmt.Errorf("apply failed (sealed but not acked; will retry): %w", err)
	}
	// 4. Ack with the seal receipt.
	if err := p.ack(ctx, c.ID, receipt); err != nil {
		return fmt.Errorf("ack failed: %w", err)
	}
	p.logger.Printf("configpull: applied %s — %s [%s]", c.ID, Describe(c.Diff), receipt)
	return nil
}

func (p *Puller) fetchPending(ctx context.Context) ([]change, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.pendingURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("authorization", "Bearer "+p.key)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pending fetch: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pending fetch: HTTP %d", resp.StatusCode)
	}
	var pr pendingResp
	if err := json.Unmarshal(body, &pr); err != nil {
		return nil, fmt.Errorf("pending decode: %w", err)
	}
	return pr.Changes, nil
}

func (p *Puller) ack(ctx context.Context, id, receipt string) error {
	body, _ := json.Marshal(map[string]interface{}{"id": id, "seal": receipt})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.ackURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("authorization", "Bearer "+p.key)
	req.Header.Set("content-type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
