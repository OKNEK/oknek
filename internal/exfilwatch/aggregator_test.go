package exfilwatch

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/oknek/oknek/internal/config"
)

// capture is a test EmitFunc collecting emitted events.
type capture struct {
	mu   sync.Mutex
	rows []struct{ ruleID, verdict, payload string }
}

func (c *capture) emit(id string, ts int64, agentID, ruleID, verdict, payload string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rows = append(c.rows, struct{ ruleID, verdict, payload string }{ruleID, verdict, payload})
	return nil
}
func (c *capture) count() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.rows) }

func newAgg(cap *capture) *Aggregator {
	return New(config.NormalizeExfilWatch(config.ExfilWatchConfig{Enabled: true}), cap.emit, nil)
}

const sec = int64(1_000_000_000)

func TestBeacon_RegularCadenceFires(t *testing.T) {
	cap := &capture{}
	a := newAgg(cap)
	// 6 connects to the same dest, exactly 30s apart → 5 perfectly-regular intervals.
	for i := int64(0); i < 6; i++ {
		a.Observe("agent-1", "curl", 4242, "185.10.20.30", 443, i*30*sec)
	}
	if cap.count() != 1 {
		t.Fatalf("want exactly 1 beacon alert, got %d", cap.count())
	}
	if cap.rows[0].ruleID != "R12" || cap.rows[0].verdict != "warn" {
		t.Errorf("bad event: %+v", cap.rows[0])
	}
	// process evidence carried through to the payload
	if !strings.Contains(cap.rows[0].payload, `"process":"curl"`) {
		t.Errorf("beacon payload missing process evidence: %s", cap.rows[0].payload)
	}
}

func TestBeacon_JitteryDoesNotFire(t *testing.T) {
	cap := &capture{}
	a := newAgg(cap)
	// wildly irregular intervals to the same dest → not a beacon.
	for _, off := range []int64{0, 2, 31, 33, 90, 91} {
		a.Observe("agent-1", "curl", 4242, "185.10.20.30", 443, off*sec)
	}
	if cap.count() != 0 {
		t.Fatalf("jittery traffic should not beacon, got %d alerts", cap.count())
	}
}

func velocityAlerts(c *capture) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, r := range c.rows {
		if strings.Contains(r.payload, `"pattern":"velocity"`) {
			n++
		}
	}
	return n
}

func TestVelocity_BurstFires(t *testing.T) {
	cap := &capture{}
	a := newAgg(cap) // defaults: window 30s, max 40
	// 45 connects within a few seconds, spread across distinct dests so the
	// beacon detector never trips — isolates the velocity signal.
	for i := int64(0); i < 45; i++ {
		a.Observe("agent-1", "curl", 4242, fmt.Sprintf("10.0.0.%d", i), 443, i*int64(50_000_000)) // 50ms apart
	}
	if got := velocityAlerts(cap); got != 1 {
		t.Fatalf("want 1 velocity alert, got %d", got)
	}
}

func TestVelocity_UnderThresholdQuiet(t *testing.T) {
	cap := &capture{}
	a := newAgg(cap)
	for i := int64(0); i < 20; i++ { // 20 < 40
		a.Observe("agent-1", "curl", 4242, fmt.Sprintf("10.0.0.%d", i), 443, i*int64(50_000_000))
	}
	if velocityAlerts(cap) != 0 {
		t.Fatalf("under-threshold burst must stay quiet")
	}
}

func TestVelocity_CooldownSuppresses(t *testing.T) {
	cap := &capture{}
	a := newAgg(cap)
	// first burst → 1 alert
	for i := int64(0); i < 45; i++ {
		a.Observe("agent-1", "curl", 4242, fmt.Sprintf("10.0.0.%d", i), 443, i*int64(50_000_000))
	}
	// second burst 10s later (< 300s cooldown) → suppressed
	base := int64(10) * sec
	for i := int64(0); i < 45; i++ {
		a.Observe("agent-1", "curl", 4242, fmt.Sprintf("10.1.0.%d", i), 443, base+i*int64(50_000_000))
	}
	if velocityAlerts(cap) != 1 {
		t.Fatalf("cooldown should hold velocity to 1 alert, got %d", velocityAlerts(cap))
	}
}
