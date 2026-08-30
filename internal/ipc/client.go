package ipc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Client is a one-shot client. A new TCP/Unix connection is opened per Call.
type Client struct {
	socket  string
	timeout time.Duration
}

// NewClient returns a Client configured to dial socket with a 3-second timeout.
func NewClient(socket string) *Client {
	return &Client{socket: socket, timeout: 3 * time.Second}
}

// Call sends a single request and reads a single response.
// If v is non-nil, the response Result is unmarshaled into v.
func (c *Client) Call(method string, params interface{}, v interface{}) error {
	conn, err := net.DialTimeout("unix", c.socket, c.timeout)
	if err != nil {
		return fmt.Errorf("dial %s: %w", c.socket, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))

	var raw json.RawMessage
	if params != nil {
		data, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("marshal params: %w", err)
		}
		raw = data
	}
	req := Request{Method: method, Params: raw}
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("read: %w", err)
		}
		return fmt.Errorf("no response from daemon")
	}
	var resp Response
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}
	if resp.Error != "" {
		return fmt.Errorf("daemon: %s", resp.Error)
	}
	if v != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, v); err != nil {
			return fmt.Errorf("unmarshal result: %w", err)
		}
	}
	return nil
}
