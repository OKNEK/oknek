// Package attest turns the Okular heartbeat stream into a tamper-evident liveness
// proof. The loader appends a signed "alive" heartbeat to the hash-chained ledger
// every H seconds; this detector walks those timestamps and flags any silence
// longer than a tolerance as a gap.
//
// Why it matters for anti-unpin: a root insider may still stop enforcement by a
// vector we cannot deny in-kernel (reboot to drop the `bpf` LSM, a kernel exploit,
// or the boot-race before the guard attaches). Those cannot be *prevented* — but
// because the ledger is append-only and anchored, the silence they cause leaves an
// un-backfillable gap. You can stop enforcement; you cannot do it quietly.
package attest

import "sort"

// Gap is a stretch of silence between two consecutive heartbeats that exceeds the
// tolerance — i.e. enforcement was (or appeared) down across this interval.
type Gap struct {
	AfterTS  int64 `json:"after_ts"`  // last heartbeat before the silence (unix seconds)
	BeforeTS int64 `json:"before_ts"` // first heartbeat after the silence
	Seconds  int64 `json:"seconds"`   // BeforeTS - AfterTS
}

// Report is the outcome of an attestation check.
type Report struct {
	Beats      int   // number of heartbeats examined
	Gaps       []Gap // silences longer than the tolerance, in time order
	Continuous bool  // true when no gap exceeded the tolerance
}

// EnforcingReport summarizes the enforce-state carried in the heartbeat payloads.
// The gap detector (Check) only sees silence; this catches a heartbeat that is still
// arriving but reports enforcement OFF — defense-in-depth for any path that flips
// enforce without stopping the beat.
type EnforcingReport struct {
	Beats         int  // heartbeats examined
	DisabledBeats int  // heartbeats that reported enforcing=false
	AllEnforcing  bool // true when every beat reported enforcing=true (vacuous when none)
}

// ScanEnforcing flags any heartbeat that reported enforcement was not active.
func ScanEnforcing(enforcing []bool) EnforcingReport {
	r := EnforcingReport{Beats: len(enforcing), AllEnforcing: true}
	for _, on := range enforcing {
		if !on {
			r.DisabledBeats++
			r.AllEnforcing = false
		}
	}
	return r
}

// SinceNewest reports how long (in the same unit as the beats, typically seconds)
// since the most recent heartbeat, given nowTS. hasBeats is false when there are none.
// This is the TERMINAL-silence signal: Check() only measures intervals BETWEEN recorded
// beats, so a stream that stopped forever (e.g. a reboot that dropped the bpf LSM, with
// the daemon answering from stale pre-reboot beats) looks "continuous" to Check but shows
// a large SinceNewest. The caller flags silence when this exceeds the tolerance.
func SinceNewest(beats []int64, nowTS int64) (hasBeats bool, since int64) {
	if len(beats) == 0 {
		return false, 0
	}
	max := beats[0]
	for _, b := range beats {
		if b > max {
			max = b
		}
	}
	return true, nowTS - max
}

// Check examines heartbeat timestamps (unix seconds, any order) and reports every
// interval strictly greater than maxGapSeconds as a Gap. An interval exactly equal
// to maxGapSeconds is within tolerance. Fewer than two beats cannot form an
// interval and is reported as continuous.
func Check(beats []int64, maxGapSeconds int64) Report {
	r := Report{Beats: len(beats), Continuous: true}
	if len(beats) < 2 {
		return r
	}
	sorted := append([]int64(nil), beats...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	for i := 1; i < len(sorted); i++ {
		delta := sorted[i] - sorted[i-1]
		if delta > maxGapSeconds {
			r.Gaps = append(r.Gaps, Gap{AfterTS: sorted[i-1], BeforeTS: sorted[i], Seconds: delta})
			r.Continuous = false
		}
	}
	return r
}
