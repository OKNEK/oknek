// Package gpuwatch implements the R9 billed-while-broken governor: a background
// watcher that polls workload health on a pod and emits a cost-anomaly event
// when a service stays down while the pod keeps billing.
package gpuwatch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"time"
)

// HealthProbe reports whether a watched workload is currently up.
type HealthProbe interface {
	Healthy(ctx context.Context) (ok bool, detail string, err error)
}

// PortProbe is healthy when something accepts a TCP connection on 127.0.0.1:Port.
type PortProbe struct {
	Port int
	Dial func(network, address string, timeout time.Duration) (net.Conn, error) // default net.DialTimeout
}

func (p PortProbe) Healthy(ctx context.Context) (bool, string, error) {
	dial := p.Dial
	if dial == nil {
		dial = net.DialTimeout
	}
	conn, err := dial("tcp", fmt.Sprintf("127.0.0.1:%d", p.Port), 2*time.Second)
	if err != nil {
		return false, fmt.Sprintf("no listener on :%d", p.Port), nil
	}
	conn.Close()
	return true, fmt.Sprintf("listening on :%d", p.Port), nil
}

// ProcessProbe is healthy when `pgrep -f Pattern` finds a process. A non-match
// (pgrep exit 1) is "down", not an error; only a failure to *run* pgrep is an
// error (so a missing binary never silently reports every service down).
type ProcessProbe struct {
	Pattern string
	Run     func(ctx context.Context, name string, args ...string) ([]byte, error) // default execRun
}

func (p ProcessProbe) Healthy(ctx context.Context) (bool, string, error) {
	run := p.Run
	if run == nil {
		run = execRun
	}
	out, err := run(ctx, "pgrep", "-f", p.Pattern)
	if err != nil {
		var execErr *exec.Error // binary missing / failed to start
		if errors.As(err, &execErr) {
			return false, "", fmt.Errorf("cannot run pgrep: %w", err)
		}
		return false, "no process matches " + p.Pattern, nil
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return false, "no process matches " + p.Pattern, nil
	}
	return true, "process present", nil
}

func execRun(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}
