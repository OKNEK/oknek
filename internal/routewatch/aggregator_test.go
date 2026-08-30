package routewatch

import (
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

func TestAggregator_WindowAccumulateAndStatus(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	agg := New(60, 100.0, nil, clk.Now, nil)
	agg.Record("api.openai.com", "worker", 4821, 0.03)
	agg.Record("api.openai.com", "worker", 4821, 0.03)
	agg.Record("api.anthropic.com", "other", 99, 0.02)
	st := agg.Status()
	if !st.Enabled {
		t.Fatal("status should be enabled")
	}
	if st.Lifetime != 3 {
		t.Errorf("lifetime = %d, want 3", st.Lifetime)
	}
	if len(st.Processes) != 2 {
		t.Fatalf("process groups = %d, want 2", len(st.Processes))
	}
	if st.Processes[0].Process != "worker" || st.Processes[0].Count != 2 {
		t.Errorf("top process = %+v, want worker x2", st.Processes[0])
	}
	if got := st.WindowUSD; got < 0.0799 || got > 0.0801 {
		t.Errorf("window usd = %v, want ~0.08", got)
	}
}

func TestAggregator_PrunesOldSamples(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	agg := New(60, 100.0, nil, clk.Now, nil)
	agg.Record("api.openai.com", "w", 1, 0.50)
	clk.t = clk.t.Add(120 * time.Second)
	agg.Record("api.openai.com", "w", 1, 0.10)
	st := agg.Status()
	if st.Lifetime != 2 {
		t.Errorf("lifetime = %d, want 2 (lifetime never prunes)", st.Lifetime)
	}
	if got := st.WindowUSD; got < 0.0999 || got > 0.1001 {
		t.Errorf("window usd = %v, want ~0.10 (old sample pruned)", got)
	}
}

func TestAggregator_SoftCapEmitsOnceThenReArms(t *testing.T) {
	var emits int
	emit := func(id string, ts int64, a, r, v, p string) error { emits++; return nil }
	clk := &fakeClock{t: time.Unix(1000, 0)}
	agg := New(60, 1.00, emit, clk.Now, nil)

	for i := 0; i < 6; i++ {
		agg.Record("api.openai.com", "w", 1, 0.20)
	}
	if emits != 1 {
		t.Fatalf("emits = %d, want 1 at crossing", emits)
	}
	agg.Record("api.openai.com", "w", 1, 0.20)
	if emits != 1 {
		t.Fatalf("emits = %d, want still 1 (debounced)", emits)
	}
	clk.t = clk.t.Add(120 * time.Second)
	for i := 0; i < 6; i++ {
		agg.Record("api.openai.com", "w", 1, 0.20)
	}
	if emits != 2 {
		t.Fatalf("emits = %d, want 2 after re-arm", emits)
	}
}

func TestAggregator_NilSafe(t *testing.T) {
	var agg *Aggregator
	agg.Record("x", "y", 1, 1.0)
	if agg.Status().Enabled {
		t.Error("nil aggregator status should be disabled")
	}
}

func TestAggregator_StatusOverBudgetReflectsCurrentWindow(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	agg := New(60, 1.00, func(id string, ts int64, a, r, v, p string) error { return nil }, clk.Now, nil)
	for i := 0; i < 6; i++ { // $1.20 > $1.00 → over budget
		agg.Record("api.openai.com", "w", 1, 0.20)
	}
	if !agg.Status().OverBudget {
		t.Fatal("should be over budget while window is full")
	}
	clk.t = clk.t.Add(120 * time.Second) // window decays, no new Record
	st := agg.Status()
	if st.OverBudget {
		t.Errorf("OverBudget should reflect the now-empty window, got OverBudget=true with WindowUSD=%v", st.WindowUSD)
	}
}
