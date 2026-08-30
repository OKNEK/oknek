// Package disarm holds the crypto + on-disk formats for Tier-A gated graceful disarm
// (authorized uninstall). The trust split: the OFF-BOX private key signs an uninstall
// authorization; the box holds only the matching PUBLIC key, so on-box root can write any
// file but cannot forge a valid authorization. Two artifacts:
//
//   - Token  — an off-box-signed authorization bound to one host, with an expiry.
//   - Marker — the disarm-on-boot record oknekd stages after an authorized disarm; the
//     loader honors it ONLY if its embedded Token re-verifies at boot.
//
// A forged Token or Marker simply fails verification and is ignored (the box then arms
// normally); a root who blocks arming by other means is the existing, DETECTED boot-race
// gap, not a clean disarm. This package is pure Go — no kernel, fully unit-testable.
package disarm

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// tokenContext domain-separates these signatures from any other ed25519 use in the system.
const tokenContext = "oknek-disarm-token-v1"

// Verification failure reasons (typed so callers can distinguish + the audit can record why).
var (
	ErrBadSignature = errors.New("disarm: bad or missing signature")
	ErrHostMismatch = errors.New("disarm: token not bound to this host")
	ErrExpired      = errors.New("disarm: token expired")
)

// Token is an off-box-signed authorization to disarm/uninstall a SPECIFIC host.
type Token struct {
	HostID    string `json:"host_id"`          // binds the token to one box (no cross-host replay)
	TokenID   string `json:"token_id"`         // unique; ties to the DISARM-AUTHORIZED audit event
	IssuedAt  int64  `json:"issued_at"`        // unix seconds
	ExpiresAt int64  `json:"expires_at"`       // unix seconds; 0 = never (discouraged)
	Reason    string `json:"reason,omitempty"` // operator note (e.g. "decommission")
	Sig       string `json:"sig"`              // hex ed25519 over signingBytes()
}

// signingBytes is the canonical, deterministic content that gets signed (excludes Sig).
func (t Token) signingBytes() []byte {
	return []byte(fmt.Sprintf("%s\x1f%s\x1f%s\x1f%d\x1f%d\x1f%s",
		tokenContext, t.HostID, t.TokenID, t.IssuedAt, t.ExpiresAt, t.Reason))
}

// SignToken signs t with the OFF-BOX private key and returns it with Sig populated.
func SignToken(priv ed25519.PrivateKey, t Token) (Token, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return t, errors.New("disarm: invalid private key")
	}
	t.Sig = hex.EncodeToString(ed25519.Sign(priv, t.signingBytes()))
	return t, nil
}

// VerifyToken checks authenticity FIRST (signature vs the baked-in pubkey), then — only
// once the contents are trusted — host binding and expiry. Returns a typed error per failure.
func VerifyToken(pub ed25519.PublicKey, t Token, hostID string, nowUnix int64) error {
	sig, err := hex.DecodeString(t.Sig)
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, t.signingBytes(), sig) {
		return ErrBadSignature
	}
	if t.HostID != hostID {
		return ErrHostMismatch
	}
	if t.ExpiresAt != 0 && nowUnix > t.ExpiresAt {
		return ErrExpired
	}
	return nil
}

// Marker is the disarm-on-boot record. It embeds the off-box-signed Token; the loader
// trusts it only if Verify() passes, so the on-disk file being root-writable is not a hole.
type Marker struct {
	Token    Token `json:"token"`
	StagedAt int64 `json:"staged_at"` // when oknekd wrote it (audit/debug)
}

// Verify re-checks the embedded token at boot (signature + host + expiry).
func (m Marker) Verify(pub ed25519.PublicKey, hostID string, nowUnix int64) error {
	return VerifyToken(pub, m.Token, hostID, nowUnix)
}

// WriteMarker stages the marker atomically-ish at 0600 (owner-only).
func WriteMarker(path string, m Marker) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// ReadMarker reads a staged marker. A missing file returns an error matching os.ErrNotExist
// so callers can treat "no marker" as "arm normally".
func ReadMarker(path string) (Marker, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Marker{}, err // os.ReadFile already wraps os.ErrNotExist
	}
	var m Marker
	if err := json.Unmarshal(b, &m); err != nil {
		return Marker{}, fmt.Errorf("disarm: corrupt marker %s: %w", path, err)
	}
	return m, nil
}
