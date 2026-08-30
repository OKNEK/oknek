package disarm

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/oknek/oknek/internal/okular"
)

// fakeRec records control events and can simulate an escrow failure on a chosen kind.
type fakeRec struct {
	events []string
	failOn string
}

func (f *fakeRec) EmitDisarm(ts int64, kind, tokenID, reason string) error {
	if kind == f.failOn {
		return errors.New("escrow down")
	}
	f.events = append(f.events, kind+":"+tokenID)
	return nil
}

func (f *fakeRec) has(kind, tokenID string) bool {
	for _, e := range f.events {
		if e == kind+":"+tokenID {
			return true
		}
	}
	return false
}

func setup(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, filepath.Join(t.TempDir(), "disarm.marker")
}

func signed(t *testing.T, priv ed25519.PrivateKey) Token {
	t.Helper()
	tok, err := SignToken(priv, Token{HostID: "box-1", TokenID: "tok-1", IssuedAt: 1000, ExpiresAt: 2000})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// A valid token records DISARM-AUTHORIZED (record-first) and stages a verifiable marker.
func TestRequestDisarm_ValidStagesMarker(t *testing.T) {
	pub, priv, mp := setup(t)
	rec := &fakeRec{}
	a := NewAuthorizer(pub, "box-1", mp, rec, 0)
	if err := a.RequestDisarm(signed(t, priv), 1500); err != nil {
		t.Fatalf("valid request should succeed, got %v", err)
	}
	if !rec.has(okular.EvDisarmAuthorized, "tok-1") {
		t.Fatalf("expected DISARM-AUTHORIZED recorded, got %v", rec.events)
	}
	m, err := ReadMarker(mp)
	if err != nil || m.Verify(pub, "box-1", 1500) != nil {
		t.Fatalf("a verifiable marker should be staged, read=%v", err)
	}
}

// A forged token records a DENIED attempt and stages NO marker (can't disarm).
func TestRequestDisarm_ForgedRecordsDeniedNoMarker(t *testing.T) {
	pub, _, mp := setup(t)
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	rec := &fakeRec{}
	a := NewAuthorizer(pub, "box-1", mp, rec, 0)
	forged := signed(t, attacker)
	if err := a.RequestDisarm(forged, 1500); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("forged token must be rejected, got %v", err)
	}
	if !rec.has(okular.EvDisarmDenied, "tok-1") {
		t.Fatalf("expected DISARM-DENIED recorded, got %v", rec.events)
	}
	if _, err := ReadMarker(mp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("no marker may be staged for a forged token")
	}
}

// Record-first/fail-closed: if DISARM-AUTHORIZED can't be escrowed, NO marker is staged.
func TestRequestDisarm_FailClosedNoMarker(t *testing.T) {
	pub, priv, mp := setup(t)
	rec := &fakeRec{failOn: okular.EvDisarmAuthorized}
	a := NewAuthorizer(pub, "box-1", mp, rec, 0)
	if err := a.RequestDisarm(signed(t, priv), 1500); err == nil {
		t.Fatal("expected fail-closed error when authorization can't be recorded")
	}
	if _, err := ReadMarker(mp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("no marker may be staged when the authorization wasn't escrowed")
	}
}

// Boot with no marker → arm normally.
func TestBootCheck_NoMarkerArms(t *testing.T) {
	pub, _, mp := setup(t)
	a := NewAuthorizer(pub, "box-1", mp, &fakeRec{}, 0)
	arm, err := a.BootCheck(1500)
	if !arm || err != nil {
		t.Fatalf("no marker should arm cleanly, got arm=%v err=%v", arm, err)
	}
}

// Boot with a valid staged marker → DON'T arm, record DISARMED, consume the marker.
func TestBootCheck_ValidMarkerDisarms(t *testing.T) {
	pub, priv, mp := setup(t)
	rec := &fakeRec{}
	a := NewAuthorizer(pub, "box-1", mp, rec, 0)
	if err := a.RequestDisarm(signed(t, priv), 1500); err != nil {
		t.Fatal(err)
	}
	arm, err := a.BootCheck(1600)
	if arm || err != nil {
		t.Fatalf("valid marker should disarm (not arm), got arm=%v err=%v", arm, err)
	}
	if !rec.has(okular.EvDisarmed, "tok-1") {
		t.Fatalf("expected DISARMED recorded at boot, got %v", rec.events)
	}
	if _, err := ReadMarker(mp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("marker should be consumed after disarm")
	}
}

// Boot with a FORGED marker → ignore it and arm normally (root can't fake an off-switch).
func TestBootCheck_ForgedMarkerArms(t *testing.T) {
	pub, _, mp := setup(t)
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	if err := WriteMarker(mp, Marker{Token: signed(t, attacker), StagedAt: 1200}); err != nil {
		t.Fatal(err)
	}
	rec := &fakeRec{}
	a := NewAuthorizer(pub, "box-1", mp, rec, 0)
	arm, _ := a.BootCheck(1500)
	if !arm {
		t.Fatal("a forged marker must be ignored — the box arms normally")
	}
	if rec.has(okular.EvDisarmed, "tok-1") {
		t.Fatal("a forged marker must NOT produce a DISARMED record")
	}
}

// Boot with a valid marker but escrow down → STAY ARMED (fail-closed), keep the marker.
func TestBootCheck_FailClosedKeepsArming(t *testing.T) {
	pub, priv, mp := setup(t)
	if err := WriteMarker(mp, Marker{Token: signed(t, priv), StagedAt: 1200}); err != nil {
		t.Fatal(err)
	}
	rec := &fakeRec{failOn: okular.EvDisarmed}
	a := NewAuthorizer(pub, "box-1", mp, rec, 0)
	arm, err := a.BootCheck(1500)
	if !arm || err == nil {
		t.Fatalf("can't-record-completion must stay armed with an error, got arm=%v err=%v", arm, err)
	}
	if _, rerr := ReadMarker(mp); rerr != nil {
		t.Fatal("marker must remain so the disarm can complete on a later boot")
	}
}
