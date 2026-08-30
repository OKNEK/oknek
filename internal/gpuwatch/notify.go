package gpuwatch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/oknek/oknek/internal/rules"
)

// deanLine renders the human-facing Dean notification. draft is the clawback
// text (empty on live alerts).
func deanLine(p rules.CostAnomalyPayload, draft string) string {
	state := "is still down"
	if p.Resolved {
		state = "recovered"
	}
	msg := fmt.Sprintf(
		"Dean · oknek · %s · %s %s after %s the pod billed while broken. Est. exposure ~$%.2f @ $%.2f/hr.",
		p.PodID, p.Service, state, rules.HumanDuration(p.DownSeconds), p.ExposureUSD, p.HourlyUSD,
	)
	if p.Resolved && draft != "" {
		msg += "\nClawback draft: " + draft
	}
	return msg
}

// postWebhook fires a Discord/Slack-style {"content": msg} payload, best-effort
// and non-blocking. Empty url is a no-op.
func postWebhook(url, msg string) {
	if url == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"content": msg})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("content-type", "application/json")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
}
