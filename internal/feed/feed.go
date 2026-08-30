// Package feed ships block events from oknekd to the oknek dashboard's ingest
// endpoint (Cloudflare). Best-effort and non-blocking: a failed POST never
// stalls the rule engine, and the event is always still in the local store.
package feed

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"time"
)

// Poster POSTs events to the dashboard ingest endpoint with a bearer key.
type Poster struct {
	url    string
	key    string
	host   string
	client *http.Client
}

// New returns a Poster, or nil if url/key are empty (feed disabled — events
// still land in the local store).
func New(url, key string) *Poster {
	if url == "" || key == "" {
		return nil
	}
	h, _ := os.Hostname()
	return &Poster{url: url, key: key, host: h, client: &http.Client{Timeout: 5 * time.Second}}
}

// Post fires the event at the ingest endpoint in the background. nil-safe.
func (p *Poster) Post(id string, ts int64, agentID, ruleID, verdict, payloadJSON string) {
	if p == nil {
		return
	}
	var pm map[string]interface{}
	_ = json.Unmarshal([]byte(payloadJSON), &pm)
	path, _ := pm["path"].(string)
	enf, _ := pm["enforcement"].(string)
	if enf == "" {
		enf = "ld_preload"
	}
	body, _ := json.Marshal(map[string]interface{}{
		"id": id, "ts": ts, "host": p.host, "agent_id": agentID,
		"rule_id": ruleID, "verdict": verdict, "enforcement": enf,
		"path": path, "payload_json": payloadJSON,
	})
	go func() {
		req, err := http.NewRequest(http.MethodPost, p.url, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("authorization", "Bearer "+p.key)
		req.Header.Set("content-type", "application/json")
		resp, err := p.client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}()
}
