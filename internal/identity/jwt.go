// Package identity is Okredo Attest: a kernel-issued, short-lived, EdDSA-signed
// identity document for a watched agent session — JWT-SVID-shaped so any IdP, NHI
// product or SIEM can consume it. Unlike a token the agent holds, it is minted by
// the enforcer beneath the agent and carries the enforcement posture (from
// `oknek doctor`), the Okular audit anchor, and the R21 session taint that back it.
package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Claims is the attestation body. Oknek holds the posture/audit/taint facts.
type Claims struct {
	Iss   string                 `json:"iss"`
	Sub   string                 `json:"sub"`
	Aud   []string               `json:"aud,omitempty"`
	Iat   int64                  `json:"iat"`
	Exp   int64                  `json:"exp"`
	Oknek map[string]interface{} `json:"oknek"`
}

// Signer signs a message with the daemon's ed25519 key (the Okular key; the private
// key never leaves the okular package).
type Signer func(msg []byte) []byte

var (
	ErrFormat    = errors.New("identity: malformed token")
	ErrAlg       = errors.New("identity: unsupported alg (want EdDSA)")
	ErrSignature = errors.New("identity: signature invalid")
	ErrExpired   = errors.New("identity: token expired")
	ErrNotYet    = errors.New("identity: token not yet valid")
)

// SPIFFE builds the subject id: spiffe://oknek/<install>/host/<host>/agent/<agent>.
func SPIFFE(installID, host, agent string) string {
	return fmt.Sprintf("spiffe://oknek/%s/host/%s/agent/%s", seg(installID), seg(host), seg(agent))
}

func seg(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		}
		return '-'
	}, s)
}

// KID is a stable key id: first 8 hex chars of sha256(pubkey).
func KID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])[:8]
}

// Issue mints a compact JWS (header.payload.signature) with alg EdDSA.
func Issue(c Claims, sign Signer, kid string) (string, error) {
	if c.Iss == "" || c.Sub == "" || c.Exp <= c.Iat {
		return "", errors.New("identity: claims need iss, sub and exp > iat")
	}
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid})
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signing := b64(hdr) + "." + b64(body)
	sig := sign([]byte(signing))
	return signing + "." + b64(sig), nil
}

// Verify checks structure, alg, signature and the time window at `now` (unix secs).
func Verify(token string, pub ed25519.PublicKey, now int64) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, ErrFormat
	}
	hdrB, err := unb64(parts[0])
	if err != nil {
		return c, ErrFormat
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hdrB, &hdr); err != nil {
		return c, ErrFormat
	}
	if hdr.Alg != "EdDSA" {
		return c, ErrAlg
	}
	sig, err := unb64(parts[2])
	if err != nil {
		return c, ErrFormat
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return c, ErrSignature
	}
	body, err := unb64(parts[1])
	if err != nil {
		return c, ErrFormat
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return c, ErrFormat
	}
	if now >= c.Exp {
		return c, ErrExpired
	}
	if now+60 < c.Iat { // 60s skew
		return c, ErrNotYet
	}
	return c, nil
}

// JWKS renders the public key as a minimal JSON Web Key Set (OKP / Ed25519).
func JWKS(pub ed25519.PublicKey) string {
	b, _ := json.Marshal(map[string]interface{}{"keys": []map[string]string{{
		"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": KID(pub), "x": b64(pub),
	}}})
	return string(b)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
