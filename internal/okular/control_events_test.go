package okular

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// failingShipper points a shipper at a server that 500s every request, so any Ship()
// fails — used to prove the record-first/fail-closed contract.
func failingShipper(t *testing.T) *WORMShipper {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return shipperTo(srv)
}

func freshLedgerN(t *testing.T) *Ledger {
	t.Helper()
	l, err := Open(t.TempDir() + "/okular.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// A disarm/policy control event is recorded in the ledger AND checkpointed by an anchor.
func TestEmitDisarmRecordsAndAnchors(t *testing.T) {
	l := freshLedgerN(t)
	a, err := l.EmitDisarm(1000, EvDisarmAuthorized, "tok-1", "")
	if err != nil {
		t.Fatalf("EmitDisarm: %v", err)
	}
	if a == nil {
		t.Fatal("expected an anchor checkpointing the event")
	}
	evs, err := l.Timeline(controlAgent, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Rule != EvDisarmAuthorized {
		t.Fatalf("want one %s event, got %+v", EvDisarmAuthorized, evs)
	}
}

// THE core property: with a shipper configured, if the off-box escrow PUT fails, the
// emit MUST return an error so the caller aborts the disarm/enforce. Fail-closed.
func TestEmitControlFailsClosedWhenShipFails(t *testing.T) {
	l := freshLedgerN(t)
	l.SetShipper(failingShipper(t))
	if _, err := l.EmitDisarm(1000, EvDisarmAuthorized, "tok-1", ""); err == nil {
		t.Fatal("expected fail-closed error when WORM escrow PUT fails, got nil")
	}
	if _, err := l.EmitPolicy(2000, EvPolicyEnforce, "coding-agent", 3, "enforce"); err == nil {
		t.Fatal("expected fail-closed error for policy emit when escrow fails, got nil")
	}
}

// A DISARMED with no preceding matching DISARM-AUTHORIZED is tamper — a silent off-switch.
func TestVerifyControlCatchesDisarmWithoutAuth(t *testing.T) {
	l := freshLedgerN(t)
	if _, err := l.EmitDisarm(1000, EvDisarmed, "tok-ghost", ""); err != nil {
		t.Fatal(err)
	}
	ok, issues, _, err := l.VerifyControlEvents()
	if err != nil {
		t.Fatal(err)
	}
	if ok || len(issues) == 0 {
		t.Fatalf("want a control issue for unauthorized disarm, got ok=%v issues=%v", ok, issues)
	}
}

// A properly authorized disarm (AUTHORIZED then DISARMED, same token) verifies clean.
func TestVerifyControlHappyPairing(t *testing.T) {
	l := freshLedgerN(t)
	if _, err := l.EmitDisarm(1000, EvDisarmAuthorized, "tok-1", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := l.EmitDisarm(1100, EvDisarmed, "tok-1", ""); err != nil {
		t.Fatal(err)
	}
	ok, issues, _, err := l.VerifyControlEvents()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || len(issues) != 0 {
		t.Fatalf("want clean pairing, got ok=%v issues=%v", ok, issues)
	}
}

// The off-box verifier (VerifyRemote) must APPLY the disarm-pairing rule, not just expose
// it — a DISARMED-without-auth in the escrowed history makes verify-remote report tamper.
func TestVerifyRemoteReportsControlIssues(t *testing.T) {
	l := freshLedgerN(t)
	if _, err := l.EmitDisarm(1000, EvDisarmed, "tok-ghost", ""); err != nil { // no auth → silent off-switch
		t.Fatal(err)
	}
	anchors, err := l.Anchors()
	if err != nil || len(anchors) == 0 {
		t.Fatalf("expected the control event to be anchored: %v", err)
	}
	srv := mockS3(objsFromAnchors(anchors))
	defer srv.Close()
	l.SetShipper(shipperTo(srv))
	r, err := l.VerifyRemote(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if r.OK || !hasIssue(r, "off-switch") {
		t.Fatalf("want VerifyRemote to report the unauthorized disarm, got OK=%v issues=%v", r.OK, r.Issues)
	}
}

// POLICY-ENFORCE events are surfaced (so a reviewer sees who opened an agent up, and when).
func TestVerifyControlSurfacesPolicyEnforce(t *testing.T) {
	l := freshLedgerN(t)
	if _, err := l.EmitPolicy(1000, EvPolicySet, "coding-agent", 1, "observe"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.EmitPolicy(2000, EvPolicyEnforce, "coding-agent", 2, "enforce"); err != nil {
		t.Fatal(err)
	}
	ok, _, enforced, err := l.VerifyControlEvents()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("clean policy history should verify ok")
	}
	if len(enforced) != 1 || enforced[0].Name != "coding-agent" || enforced[0].Mode != "enforce" {
		t.Fatalf("want one surfaced ENFORCE for coding-agent, got %+v", enforced)
	}
}
