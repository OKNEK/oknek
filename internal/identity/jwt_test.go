package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func keys(t *testing.T) (ed25519.PublicKey, Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, func(m []byte) []byte { return ed25519.Sign(priv, m) }
}

func TestIssueVerifyRoundTrip(t *testing.T) {
	pub, sign := keys(t)
	c := Claims{Iss: "oknek", Sub: SPIFFE("inst-1", "web-1", "claude-code"), Aud: []string{"idp"}, Iat: 1000, Exp: 1300,
		Oknek: map[string]interface{}{"agent": "claude-code", "enforcement": map[string]interface{}{"kernel_enforced": true}}}
	tok, err := Issue(c, sign, KID(pub))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(tok, ".") != 2 {
		t.Fatalf("not compact JWS: %s", tok)
	}
	got, err := Verify(tok, pub, 1100)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sub != "spiffe://oknek/inst-1/host/web-1/agent/claude-code" || got.Exp != 1300 {
		t.Fatalf("claims: %+v", got)
	}
	if got.Oknek["agent"] != "claude-code" {
		t.Fatalf("oknek claims lost: %+v", got.Oknek)
	}
}

func TestVerifyRejectsTamperExpiryAndWrongKey(t *testing.T) {
	pub, sign := keys(t)
	c := Claims{Iss: "oknek", Sub: "spiffe://oknek/i/host/h/agent/a", Iat: 1000, Exp: 1300, Oknek: map[string]interface{}{"x": 1}}
	tok, _ := Issue(c, sign, KID(pub))
	if _, err := Verify(tok, pub, 1300); !errors.Is(err, ErrExpired) {
		t.Fatalf("want expired, got %v", err)
	}
	parts := strings.Split(tok, ".")
	// flip a payload char (base64url-safe swap)
	p := []byte(parts[1])
	if p[5] == 'A' {
		p[5] = 'B'
	} else {
		p[5] = 'A'
	}
	if _, err := Verify(parts[0]+"."+string(p)+"."+parts[2], pub, 1100); !errors.Is(err, ErrSignature) {
		t.Fatalf("want signature error, got %v", err)
	}
	other, _ := keys(t)
	if _, err := Verify(tok, other, 1100); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := Verify("a.b", pub, 1100); !errors.Is(err, ErrFormat) {
		t.Fatalf("format: %v", err)
	}
}

func TestSPIFFESanitizesAndJWKS(t *testing.T) {
	if got := SPIFFE("2026-05-30T17:32:03", "ubu 1/ok", "claude code"); got != "spiffe://oknek/2026-05-30T17-32-03/host/ubu-1-ok/agent/claude-code" {
		t.Fatalf("spiffe: %s", got)
	}
	pub, _ := keys(t)
	j := JWKS(pub)
	if !strings.Contains(j, `"kty":"OKP"`) || !strings.Contains(j, `"crv":"Ed25519"`) || !strings.Contains(j, KID(pub)) {
		t.Fatalf("jwks: %s", j)
	}
	if len(KID(pub)) != 8 {
		t.Fatal("kid length")
	}
}

func TestPosterNilSafe(t *testing.T) {
	var p *Poster
	p.Post("tok", "refresh", "a") // must not panic
	if New("", nil) != nil {
		t.Fatal("empty url must disable")
	}
}
