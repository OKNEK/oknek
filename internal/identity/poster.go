package identity

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

// Poster pushes attestations to an IdP/SIEM webhook. Fire-and-forget, never on the
// enforcement path; failures are logged at most once a minute.
type Poster struct {
	url     string
	headers map[string]string
	client  *http.Client
	mu      sync.Mutex
	lastErr time.Time
	Sent    int64 // for tests/status
}

// New returns nil when url is empty (disabled); Post on a nil Poster is a no-op.
func New(url string, headers map[string]string) *Poster {
	if url == "" {
		return nil
	}
	return &Poster{url: url, headers: headers, client: &http.Client{Timeout: 5 * time.Second}}
}

// Post sends {"attestation": <jwt>, "event": <event>, "agent": <agent>} asynchronously.
func (p *Poster) Post(token, event, agent string) {
	if p == nil {
		return
	}
	body, _ := json.Marshal(map[string]string{"attestation": token, "event": event, "agent": agent})
	go func() {
		req, err := http.NewRequest(http.MethodPost, p.url, bytes.NewReader(body))
		if err != nil {
			p.logErr(err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "oknekd-identity/1")
		for k, v := range p.headers {
			req.Header.Set(k, v)
		}
		resp, err := p.client.Do(req)
		if err != nil {
			p.logErr(err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			p.logErr(&statusErr{resp.StatusCode})
			return
		}
		p.mu.Lock()
		p.Sent++
		p.mu.Unlock()
	}()
}

type statusErr struct{ code int }

func (e *statusErr) Error() string { return "webhook returned " + http.StatusText(e.code) }

func (p *Poster) logErr(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if time.Since(p.lastErr) < time.Minute {
		return
	}
	p.lastErr = time.Now()
	log.Printf("identity: webhook %s: %v (quiet for 60s)", p.url, err)
}
