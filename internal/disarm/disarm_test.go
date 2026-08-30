package disarm

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func validToken() Token {
	return Token{HostID: "box-1", TokenID: "tok-1", IssuedAt: 1000, ExpiresAt: 2000, Reason: "decommission"}
}

// A token signed by the off-box key verifies for the right host, before expiry.
func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := keypair(t)
	tok, err := SignToken(priv, validToken())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyToken(pub, tok, "box-1", 1500); err != nil {
		t.Fatalf("valid token should verify, got %v", err)
	}
}

// THE property: a token signed by a DIFFERENT key (a forging root who doesn't hold the
// off-box private key) does NOT verify against the baked-in pubkey.
func TestVerifyWrongKeyRejected(t *testing.T) {
	pub, _ := keypair(t)
	_, attacker := keypair(t)
	tok, _ := SignToken(attacker, validToken())
	if err := VerifyToken(pub, tok, "box-1", 1500); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("forged-key token must fail with ErrBadSignature, got %v", err)
	}
}

// A token bound to box-1 cannot disarm box-2 (no cross-host replay).
func TestVerifyWrongHostRejected(t *testing.T) {
	pub, priv := keypair(t)
	tok, _ := SignToken(priv, validToken())
	if err := VerifyToken(pub, tok, "box-2", 1500); !errors.Is(err, ErrHostMismatch) {
		t.Fatalf("wrong-host token must fail with ErrHostMismatch, got %v", err)
	}
}

// An expired token is rejected.
func TestVerifyExpiredRejected(t *testing.T) {
	pub, priv := keypair(t)
	tok, _ := SignToken(priv, validToken())
	if err := VerifyToken(pub, tok, "box-1", 2001); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired token must fail with ErrExpired, got %v", err)
	}
}

// Mutating any signed field after signing invalidates the signature.
func TestVerifyTamperedRejected(t *testing.T) {
	pub, priv := keypair(t)
	tok, _ := SignToken(priv, validToken())
	tok.HostID = "box-evil" // change a field but keep the old signature
	if err := VerifyToken(pub, tok, "box-evil", 1500); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered token must fail with ErrBadSignature, got %v", err)
	}
}

// A staged disarm-on-boot marker round-trips and re-verifies its embedded token at boot.
func TestMarkerRoundTripAndVerify(t *testing.T) {
	pub, priv := keypair(t)
	tok, _ := SignToken(priv, validToken())
	path := filepath.Join(t.TempDir(), "disarm.marker")
	if err := WriteMarker(path, Marker{Token: tok, StagedAt: 1200}); err != nil {
		t.Fatal(err)
	}
	m, err := ReadMarker(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(pub, "box-1", 1500); err != nil {
		t.Fatalf("a legitimately-staged marker must verify at boot, got %v", err)
	}
}

// THE marker property: root can WRITE a marker file, but a marker whose token isn't signed
// by the off-box key is rejected at boot — so a forged marker can't be a clean off-switch.
func TestMarkerForgedTokenRejected(t *testing.T) {
	pub, _ := keypair(t)
	_, attacker := keypair(t)
	forged, _ := SignToken(attacker, validToken()) // root forges a marker with its own key
	path := filepath.Join(t.TempDir(), "disarm.marker")
	if err := WriteMarker(path, Marker{Token: forged, StagedAt: 1200}); err != nil {
		t.Fatal(err)
	}
	m, _ := ReadMarker(path)
	if err := m.Verify(pub, "box-1", 1500); err == nil {
		t.Fatal("a forged marker must NOT verify — the loader would then arm normally")
	}
}

// No marker = a clean os.ErrNotExist so the loader treats "no marker" as "arm normally".
func TestReadMarkerMissing(t *testing.T) {
	_, err := ReadMarker(filepath.Join(t.TempDir(), "absent.marker"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing marker must be os.ErrNotExist, got %v", err)
	}
}
