// Package canary is R23's userspace half: plant realistic decoy credentials where
// no real file exists. The kernel half (oknek_canary_inodes) turns any watched-agent
// open of a decoy into a critical alert (or a block). A canary is never planted over
// a real file and is never removed if its bytes no longer match what we planted.
package canary

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrExists is returned when a real file already occupies the canary path.
var ErrExists = errors.New("canary: real file exists, refusing to overwrite")

// ErrChanged is returned by Remove when the file's bytes no longer match the decoy.
var ErrChanged = errors.New("canary: file content changed since planting, refusing to remove")

// Plant writes a decoy at path (mode 0600, parent dirs 0700) and returns its SHA-256.
func Plant(path string) (sha string, err error) {
	if _, err := os.Lstat(path); err == nil {
		return "", ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	body := Decoy(filepath.Base(path))
	// O_EXCL: if something raced us into existence, do not clobber it.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", ErrExists
		}
		return "", err
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

// Remove deletes the decoy only if its bytes still hash to expectSHA.
func Remove(path, expectSHA string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != expectSHA {
		return ErrChanged
	}
	return os.Remove(path)
}

// Decoy returns realistic-looking fake secret content for a file named basename.
// The random suffix makes every planted canary unique (a leaked value identifies
// the host it came from).
func Decoy(basename string) []byte {
	tag := randHex(8)
	switch {
	case basename == "credentials" || basename == "config":
		return []byte(fmt.Sprintf("[default]\naws_access_key_id = AKIA%s\naws_secret_access_key = %s\nregion = us-east-1\n",
			strings.ToUpper(randAlnum(16)), randAlnum(40)))
	case strings.HasPrefix(basename, "id_rsa") || strings.HasPrefix(basename, "id_ed25519") || strings.HasSuffix(basename, ".pem"):
		return []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n" + wrap(randB64(280)) + "-----END OPENSSH PRIVATE KEY-----\n")
	case strings.HasPrefix(basename, ".env"):
		return []byte(fmt.Sprintf("DATABASE_URL=postgres://app:%s@db-primary.internal:5432/app\nSTRIPE_SECRET_KEY=sk_live_%s\nJWT_SECRET=%s\n",
			randAlnum(20), randAlnum(24), randHex(32)))
	case strings.HasSuffix(basename, ".json"):
		return []byte(fmt.Sprintf("{\n  \"api_key\": \"%s\",\n  \"service_account\": \"backup-%s@internal\",\n  \"token\": \"%s\"\n}\n",
			randAlnum(32), tag, randHex(40)))
	default:
		return []byte(fmt.Sprintf("token=%s\n", randHex(32)))
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randAlnum(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	out := make([]byte, n)
	for i := range b {
		out[i] = alnum[int(b[i])%len(alnum)]
	}
	return string(out)
}

func randB64(n int) string {
	const b64 = alnum + "+/"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	out := make([]byte, n)
	for i := range b {
		out[i] = b64[int(b[i])%len(b64)]
	}
	return string(out)
}

func wrap(s string) string {
	var sb strings.Builder
	for len(s) > 70 {
		sb.WriteString(s[:70] + "\n")
		s = s[70:]
	}
	if s != "" {
		sb.WriteString(s + "\n")
	}
	return sb.String()
}
