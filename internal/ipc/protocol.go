// Package ipc implements the local Unix-socket protocol between oknekd and
// the oknek CLI. Wire format is JSON-over-newline: one JSON object per line,
// requests and responses framed by '\n'. Single round-trip per call.
package ipc

import "encoding/json"

// Request is a single CLI→daemon call.
type Request struct {
	ID     string          `json:"id,omitempty"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is the daemon's reply. Exactly one of Result or Error is set.
type Response struct {
	ID     string          `json:"id,omitempty"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}
