package attest

import "testing"

// A continuous heartbeat stream (every interval <= maxGap) attests cleanly.
func TestCheckContinuousStreamHasNoGaps(t *testing.T) {
	beats := []int64{100, 110, 120, 130, 140}
	r := Check(beats, 15)
	if !r.Continuous {
		t.Fatalf("want continuous, got gaps: %+v", r.Gaps)
	}
	if len(r.Gaps) != 0 {
		t.Fatalf("want 0 gaps, got %d: %+v", len(r.Gaps), r.Gaps)
	}
	if r.Beats != 5 {
		t.Fatalf("want Beats=5, got %d", r.Beats)
	}
}

// A single interval larger than maxGap is a silence — enforcement went dark.
func TestCheckDetectsASilenceGap(t *testing.T) {
	// 100 -> 110 ok; 110 -> 200 is a 90s gap (> 15) = enforcement silenced.
	beats := []int64{100, 110, 200, 210}
	r := Check(beats, 15)
	if r.Continuous {
		t.Fatal("want non-continuous (a 90s gap exists)")
	}
	if len(r.Gaps) != 1 {
		t.Fatalf("want exactly 1 gap, got %d: %+v", len(r.Gaps), r.Gaps)
	}
	g := r.Gaps[0]
	if g.AfterTS != 110 || g.BeforeTS != 200 || g.Seconds != 90 {
		t.Fatalf("want gap{after:110 before:200 secs:90}, got %+v", g)
	}
}

// Heartbeats may arrive out of order (DB scan order, concurrent writers); the
// detector must sort before measuring intervals, never invent a negative gap.
func TestCheckSortsUnorderedBeats(t *testing.T) {
	// Unsorted; sorted = {100,110,120,200}: intervals 10,10,80 -> exactly one gap.
	beats := []int64{200, 100, 120, 110}
	r := Check(beats, 15)
	if len(r.Gaps) != 1 {
		t.Fatalf("want 1 gap after sorting, got %d: %+v", len(r.Gaps), r.Gaps)
	}
	if r.Gaps[0].AfterTS != 120 || r.Gaps[0].BeforeTS != 200 {
		t.Fatalf("want gap 120->200, got %+v", r.Gaps[0])
	}
}

// More than one silence is reported individually (not collapsed).
func TestCheckReportsMultipleGaps(t *testing.T) {
	beats := []int64{0, 10, 100, 110, 300}
	r := Check(beats, 15)
	if len(r.Gaps) != 2 {
		t.Fatalf("want 2 gaps, got %d: %+v", len(r.Gaps), r.Gaps)
	}
	if r.Gaps[0].Seconds != 90 || r.Gaps[1].Seconds != 190 {
		t.Fatalf("want gaps of 90s then 190s, got %+v", r.Gaps)
	}
}

// Fewer than two beats cannot form an interval; that is reported as continuous
// (the "did enforcement ever start" question is the daemon's, not the detector's).
func TestCheckTooFewBeatsIsContinuous(t *testing.T) {
	for _, beats := range [][]int64{nil, {}, {42}} {
		r := Check(beats, 15)
		if !r.Continuous || len(r.Gaps) != 0 {
			t.Fatalf("beats=%v: want continuous/no-gaps, got %+v", beats, r)
		}
	}
}

// An interval exactly equal to maxGap is within tolerance (not a gap).
func TestCheckIntervalEqualToMaxIsNotAGap(t *testing.T) {
	beats := []int64{100, 115, 130} // both intervals == 15
	r := Check(beats, 15)
	if !r.Continuous {
		t.Fatalf("interval == maxGap must be allowed, got %+v", r.Gaps)
	}
}

// A heartbeat stream where every beat reported enforcing=true attests clean.
func TestScanEnforcingAllTrue(t *testing.T) {
	r := ScanEnforcing([]bool{true, true, true})
	if !r.AllEnforcing || r.DisabledBeats != 0 || r.Beats != 3 {
		t.Fatalf("want all-enforcing/0-disabled/3-beats, got %+v", r)
	}
}

// Any heartbeat reporting enforcing=false is an alarm (enforcement was observed off,
// even with no time gap — the silent-flip case the gap detector cannot see).
func TestScanEnforcingFlagsADisabledBeat(t *testing.T) {
	r := ScanEnforcing([]bool{true, true, false, true})
	if r.AllEnforcing {
		t.Fatal("want AllEnforcing=false (one beat was enforcing=false)")
	}
	if r.DisabledBeats != 1 {
		t.Fatalf("want 1 disabled beat, got %d", r.DisabledBeats)
	}
}

// No beats is vacuously all-enforcing (the "did it start" question is the daemon's).
func TestScanEnforcingEmptyIsClean(t *testing.T) {
	r := ScanEnforcing(nil)
	if !r.AllEnforcing || r.Beats != 0 {
		t.Fatalf("want clean/0, got %+v", r)
	}
}

// SinceNewest is the terminal-silence signal: how long since the last beat (vs now).
// The interval-only Check() can't see a permanently-stopped stream — this can.
func TestSinceNewestNoBeats(t *testing.T) {
	if has, _ := SinceNewest(nil, 100); has {
		t.Fatal("no beats -> hasBeats=false")
	}
}

func TestSinceNewestMeasuresFromNewest(t *testing.T) {
	has, since := SinceNewest([]int64{100, 90, 95}, 130) // newest=100, now=130
	if !has || since != 30 {
		t.Fatalf("want since=30 from newest beat, got has=%v since=%d", has, since)
	}
}
