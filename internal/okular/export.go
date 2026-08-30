package okular

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// Bundle is a sealed, portable export of an agent's audit timeline. The signature
// is ed25519 over the SHA-256 of the bundle's content (every field except pubkey +
// signature), so it's tamper-evident on its own AND verifiable against the daemon's
// pinned public key. Each entry also carries its hash-chain links, so the *internal*
// integrity is checkable offline too.
type Bundle struct {
	Format      string  `json:"okular_export"`
	Agent       string  `json:"agent"`
	GeneratedTS int64   `json:"generated_ts"`
	HeadSeq     int64   `json:"head_seq"`
	HeadHash    string  `json:"head_hash"`
	Count       int     `json:"count"`
	Entries     []Entry `json:"entries"`
	PubKey      string  `json:"pubkey"`
	Signature   string  `json:"signature"`
}

const bundleFormat = "okular-export-v1"

// loadOrCreateKey loads the ed25519 signing key from path (the 32-byte seed), or
// generates and persists one (0600) on first use.
func (l *Ledger) loadOrCreateKey(path string) error {
	if seed, err := os.ReadFile(path); err == nil && len(seed) == ed25519.SeedSize {
		l.priv = ed25519.NewKeyFromSeed(seed)
		l.pub = l.priv.Public().(ed25519.PublicKey)
		return nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, priv.Seed(), 0o600); err != nil {
		return err
	}
	l.priv = priv
	l.pub = priv.Public().(ed25519.PublicKey)
	return nil
}

// PubKeyHex returns the daemon's audit signing public key (pin this out-of-band to
// verify a bundle's authenticity, not just its integrity).
func (l *Ledger) PubKeyHex() string { return hex.EncodeToString(l.pub) }

// PubKey returns the audit signing public key (Okredo Attest verifies with it).
func (l *Ledger) PubKey() ed25519.PublicKey { return l.pub }

// Sign signs msg with the ledger's ed25519 key. The private key never leaves this
// package; Okredo Attest tokens are signed through this method.
func (l *Ledger) Sign(msg []byte) []byte { return ed25519.Sign(l.priv, msg) }

// bundleDigest is the SHA-256 over the bundle's content with pubkey+signature
// blanked, computed deterministically (struct field order; no maps).
func bundleDigest(b *Bundle) [32]byte {
	c := *b
	c.PubKey = ""
	c.Signature = ""
	raw, _ := json.Marshal(&c)
	return sha256.Sum256(raw)
}

// ExportSigned builds a sealed bundle of an agent's timeline (chronological) and
// signs it. ts is the generation time (passed in so the caller controls the clock).
func (l *Ledger) ExportSigned(agent string, limit int, ts int64) (*Bundle, error) {
	entries, err := l.Timeline(agent, limit) // newest-first
	if err != nil {
		return nil, err
	}
	// reverse to chronological order for a readable export
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	seq, head := l.Head()
	b := &Bundle{
		Format: bundleFormat, Agent: agent, GeneratedTS: ts,
		HeadSeq: seq, HeadHash: head, Count: len(entries), Entries: entries,
	}
	dig := bundleDigest(b)
	b.PubKey = hex.EncodeToString(l.pub)
	b.Signature = hex.EncodeToString(ed25519.Sign(l.priv, dig[:]))
	return b, nil
}

// VerifyBundle checks a bundle offline: (1) the ed25519 signature over the content
// matches the embedded pubkey (sigOK); (2) the entries' internal hash chain is
// self-consistent — each entry.hash = H(prev_hash || entry) and the prev links join
// (chainOK). An auditor additionally compares PubKey to the daemon's pinned key.
func VerifyBundle(b *Bundle) (sigOK, chainOK bool, err error) {
	pub, err := hex.DecodeString(b.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false, false, fmt.Errorf("bad pubkey")
	}
	sig, err := hex.DecodeString(b.Signature)
	if err != nil {
		return false, false, fmt.Errorf("bad signature")
	}
	dig := bundleDigest(b)
	sigOK = ed25519.Verify(pub, dig[:], sig)

	chainOK = true
	for _, e := range b.Entries {
		want := hashEntry(e.PrevHash, e.TS, e.Agent, e.Rule, e.Verdict, e.Payload)
		if e.Hash != want {
			chainOK = false
			break
		}
	}
	return sigOK, chainOK, nil
}
