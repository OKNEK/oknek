package disarm

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"github.com/oknek/oknek/internal/okular"
)

// ErrTokenTooOld rejects a token whose age exceeds the configured replay window.
var ErrTokenTooOld = errors.New("disarm: token older than the allowed window")

// AuditRecorder is the record-first audit sink the disarm flow needs — satisfied by
// LedgerRecorder(*okular.Ledger). EmitDisarm must return an error when (and only when) the
// event could not be durably escrowed off-box, so the flow can fail closed.
type AuditRecorder interface {
	EmitDisarm(ts int64, kind, tokenID, reason string) error
}

// Authorizer ties the disarm crypto (Token/Marker), the audit (record-first), and the
// on-disk marker into the Tier-A flow. It is pure Go and fully unit-testable; cmd/oknekd
// and cmd/oknek are thin wrappers over it. The only part it does NOT do is the actual
// kernel arm/unload — that's the loader's job, gated by BootCheck's verdict.
type Authorizer struct {
	pub        ed25519.PublicKey
	hostID     string
	markerPath string
	rec        AuditRecorder
	maxAgeSec  int64 // reject tokens older than this many seconds (0 = rely on ExpiresAt)
}

// NewAuthorizer builds an Authorizer. maxAgeSeconds<=0 disables the age/replay window.
func NewAuthorizer(pub ed25519.PublicKey, hostID, markerPath string, rec AuditRecorder, maxAgeSeconds int) *Authorizer {
	return &Authorizer{pub: pub, hostID: hostID, markerPath: markerPath, rec: rec, maxAgeSec: int64(maxAgeSeconds)}
}

// RequestDisarm verifies a disarm token and, if authorized, records DISARM-AUTHORIZED
// RECORD-FIRST (fail-closed) and stages a signed disarm-on-boot marker. A reboot then
// completes the disarm via BootCheck. On verification failure it records a DISARM-DENIED
// attempt and returns the typed reason; it never stages a marker for a bad token, and never
// stages one unless the authorization was durably escrowed.
func (a *Authorizer) RequestDisarm(tok Token, nowUnix int64) error {
	if err := VerifyToken(a.pub, tok, a.hostID, nowUnix); err != nil {
		_ = a.rec.EmitDisarm(nowUnix, okular.EvDisarmDenied, tok.TokenID, err.Error())
		return err
	}
	if a.maxAgeSec > 0 && tok.IssuedAt > 0 && nowUnix-tok.IssuedAt > a.maxAgeSec {
		_ = a.rec.EmitDisarm(nowUnix, okular.EvDisarmDenied, tok.TokenID, "token too old")
		return ErrTokenTooOld
	}
	// record-first, fail-closed: the authorization must be immutable off-box BEFORE we
	// stage a marker that will drop enforcement at the next boot.
	if err := a.rec.EmitDisarm(nowUnix, okular.EvDisarmAuthorized, tok.TokenID, tok.Reason); err != nil {
		return fmt.Errorf("disarm authorization not recorded (fail-closed, not staged): %w", err)
	}
	if err := WriteMarker(a.markerPath, Marker{Token: tok, StagedAt: nowUnix}); err != nil {
		return fmt.Errorf("stage disarm marker: %w", err)
	}
	return nil
}

// BootCheck is called by the loader at startup BEFORE arming. It returns shouldArm=false
// only when a VALID disarm marker is present AND the DISARMED completion is recorded — then
// it consumes the marker. In every other case it returns shouldArm=true (fail-safe = stay
// protected): no marker, an unreadable marker, a forged/invalid/expired marker (ignored), or
// a valid marker whose completion couldn't be escrowed (retried on a later boot). A non-nil
// err alongside shouldArm=true is advisory for logging, not a failure to arm.
func (a *Authorizer) BootCheck(nowUnix int64) (shouldArm bool, err error) {
	m, rerr := ReadMarker(a.markerPath)
	if rerr != nil {
		if errors.Is(rerr, os.ErrNotExist) {
			return true, nil // normal boot
		}
		return true, fmt.Errorf("ignoring unreadable disarm marker, arming: %w", rerr)
	}
	if verr := m.Verify(a.pub, a.hostID, nowUnix); verr != nil {
		// forged / invalid / expired marker — root can write the file but not forge the
		// signature; ignore it and arm normally.
		return true, fmt.Errorf("ignoring invalid disarm marker, arming: %w", verr)
	}
	// valid authorization → complete it RECORD-FIRST; only disarm if the completion lands.
	if rec := a.rec.EmitDisarm(nowUnix, okular.EvDisarmed, m.Token.TokenID, m.Token.Reason); rec != nil {
		return true, fmt.Errorf("disarm completion not recorded, staying armed (fail-closed): %w", rec)
	}
	_ = os.Remove(a.markerPath) // consume the marker — the disarm is complete
	return false, nil
}

// LedgerRecorder adapts an *okular.Ledger to AuditRecorder (record-first/fail-closed
// EmitDisarm). cmd/oknekd passes the live ledger through this.
func LedgerRecorder(l *okular.Ledger) AuditRecorder { return ledgerRec{l} }

type ledgerRec struct{ l *okular.Ledger }

func (r ledgerRec) EmitDisarm(ts int64, kind, tokenID, reason string) error {
	_, err := r.l.EmitDisarm(ts, kind, tokenID, reason)
	return err
}
