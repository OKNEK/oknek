package okular

// WORM anchor shipping: each signed anchor is PUT as an immutable object to an
// S3-compatible store with Object-Lock (COMPLIANCE retention). This is the off-box
// witness that makes "detected, not prevented" TRUE against on-box root: once an
// anchor is published, root cannot rewrite it (Object-Lock blocks overwrite/delete
// even for the account, for the retention window), so a later full-ledger rewrite
// can't be made to match the head-hashes already escrowed off-box.
//
// HONESTY: the ed25519 signing key is still on-box, so root who reads it can sign
// NEW (forward) anchors — but it cannot alter what's already escrowed, and the
// off-box verifier compares the S3 server-side PutObject time to the anchor's
// claimed ts, so a back-dated "nothing happened" anchor is detectable. Moving the
// signing key off-box is the further hardening (documented, not done here).
//
// Minimal SigV4 (no AWS SDK — keeps the single static binary lean); path-style URLs
// so the same code targets S3-compatible stores. Content-MD5 is sent (AWS requires it on
// Object-Lock PUTs). VERIFIED against MinIO Object-Lock by effect; NOT yet verified against
// a real AWS S3 Object-Lock bucket (do that before claiming AWS support in marketing).

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// WORMConfig configures off-box anchor escrow to an S3-compatible Object-Lock store.
// Zero value disabled. Endpoint empty => AWS (s3.<region>.amazonaws.com, https).
type WORMConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Endpoint      string `yaml:"endpoint"` // host[:port] for MinIO; empty = AWS
	Insecure      bool   `yaml:"insecure"` // http (MinIO dev) instead of https
	Region        string `yaml:"region"`   // e.g. us-east-1
	Bucket        string `yaml:"bucket"`   // Object-Lock-enabled bucket
	Prefix        string `yaml:"prefix"`   // key prefix, e.g. "anchors"
	AccessKey     string `yaml:"access_key"`
	SecretKey     string `yaml:"secret_key"`
	HostID        string `yaml:"host_id"`        // partition key; defaults to hostname
	RetentionDays int    `yaml:"retention_days"` // Object-Lock retain window (default 365)
}

// WORMShipper PUTs anchors to the configured store. now is injectable for testing.
type WORMShipper struct {
	cfg    WORMConfig
	client *http.Client
	now    func() time.Time
}

// NewWORMShipper builds a shipper from config (no network call). HostID defaults to
// the hostname; RetentionDays defaults to 365.
func NewWORMShipper(cfg WORMConfig, hostname string) *WORMShipper {
	if cfg.HostID == "" {
		cfg.HostID = hostname
	}
	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = 365
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	return &WORMShipper{cfg: cfg, client: &http.Client{Timeout: 15 * time.Second}, now: time.Now}
}

func (w *WORMShipper) host() string {
	if w.cfg.Endpoint != "" {
		return w.cfg.Endpoint
	}
	return "s3." + w.cfg.Region + ".amazonaws.com"
}

func (w *WORMShipper) scheme() string {
	if w.cfg.Insecure {
		return "http"
	}
	return "https"
}

// objectKey is the per-anchor key: <prefix>/<host>/<zero-padded seq>.json — unique
// per anchor, so we never overwrite (Object-Lock would reject it anyway).
func (w *WORMShipper) objectKey(seq int64) string {
	p := strings.Trim(w.cfg.Prefix, "/")
	if p != "" {
		p += "/"
	}
	return fmt.Sprintf("%s%s/%020d.json", p, w.cfg.HostID, seq)
}

// Ship PUTs one anchor as an immutable object. Returns an error on any non-2xx so the
// daemon can log the gap loudly (a blocked ship leaves a missing seq the verifier sees).
func (w *WORMShipper) Ship(a *Anchor) error {
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return w.put(w.objectKey(a.Seq), body)
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// awsURIEncode is RFC3986 percent-encoding per the SigV4 spec. In the canonical query
// (and to be safe in keys) slashes ARE encoded; in the canonical path they are not.
func awsURIEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// canonicalQuery builds the SigV4 canonical query string (sorted, RFC3986-encoded).
// The same string is set as the request RawQuery so signature and wire-form match exactly.
func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, awsURIEncode(k, true)+"="+awsURIEncode(v, true))
		}
	}
	return strings.Join(parts, "&")
}

// signedDo signs (SigV4, path-style) and sends one S3 request. canonURI is the path
// (e.g. /bucket/key or /bucket); extra are additional signed headers (e.g. object-lock
// on PUT). Caller closes resp.Body.
func (w *WORMShipper) signedDo(method, canonURI string, q url.Values, body []byte, extra map[string]string) (*http.Response, error) {
	t := w.now().UTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])
	host := w.host()

	hdrs := map[string]string{
		"host": host, "x-amz-content-sha256": payloadHash, "x-amz-date": amzDate,
	}
	for k, v := range extra {
		hdrs[k] = v
	}
	names := make([]string, 0, len(hdrs))
	for k := range hdrs {
		names = append(names, k)
	}
	sort.Strings(names)
	var canon strings.Builder
	for _, k := range names {
		canon.WriteString(k + ":" + strings.TrimSpace(hdrs[k]) + "\n")
	}
	signedHeaders := strings.Join(names, ";")
	cq := canonicalQuery(q)

	canonicalRequest := strings.Join([]string{
		method, awsURIEncode(canonURI, false), cq, canon.String(), signedHeaders, payloadHash,
	}, "\n")
	crHash := sha256.Sum256([]byte(canonicalRequest))
	scope := dateStamp + "/" + w.cfg.Region + "/s3/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, hex.EncodeToString(crHash[:]),
	}, "\n")
	kDate := hmacSHA256([]byte("AWS4"+w.cfg.SecretKey), []byte(dateStamp))
	kSigning := hmacSHA256(hmacSHA256(hmacSHA256(kDate, []byte(w.cfg.Region)), []byte("s3")), []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))
	authz := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		w.cfg.AccessKey, scope, signedHeaders, signature)

	req, err := http.NewRequest(method, w.scheme()+"://"+host+canonURI, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.URL.RawQuery = cq // exact match with what we signed
	for k, v := range hdrs {
		if k == "host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", authz)
	return w.client.Do(req)
}

func (w *WORMShipper) put(key string, body []byte) error {
	retainUntil := w.now().UTC().AddDate(0, 0, w.cfg.RetentionDays).Format("2006-01-02T15:04:05Z")
	// AWS REQUIRES Content-MD5 on any Object-Lock PUT (returns HTTP 400 without it). MinIO
	// doesn't enforce it, which is why this was missing — but it's mandatory for real S3.
	md5sum := md5.Sum(body)
	resp, err := w.signedDo("PUT", "/"+w.cfg.Bucket+"/"+key, nil, body, map[string]string{
		"x-amz-object-lock-mode":              "COMPLIANCE",
		"x-amz-object-lock-retain-until-date": retainUntil,
		"content-md5":                         base64.StdEncoding.EncodeToString(md5sum[:]),
	})
	if err != nil {
		return fmt.Errorf("worm ship: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("worm ship: %s -> %d: %s", key, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// RemoteObject is one escrowed object: its key, body, and the store's server-side
// last-modified time (used to catch a back-dated anchor).
type RemoteObject struct {
	Key          string
	Body         []byte
	LastModified time.Time
}

// parseLastModified reads the HTTP Last-Modified header, which is RFC1123 per the
// HTTP spec (NOT RFC3339 — the earlier bug parsed it as RFC3339, always yielding
// zero time). A present-but-unparseable value is a HARD error, never a swallowed
// zero-time: a zero LastModified silently passes a back-dating check = fail-open,
// exactly the false-green class the 19-bug review targeted. An absent header yields
// the zero time, which downstream back-dating treats as "cannot verify" (fail-closed).
func parseLastModified(h http.Header) (time.Time, error) {
	raw := h.Get("Last-Modified")
	if raw == "" {
		return time.Time{}, nil
	}
	t, err := http.ParseTime(raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("unparseable Last-Modified %q: %w", raw, err)
	}
	return t, nil
}

// Get fetches one object's body + server-side LastModified.
func (w *WORMShipper) Get(key string) (RemoteObject, error) {
	resp, err := w.signedDo("GET", "/"+w.cfg.Bucket+"/"+key, nil, nil, nil)
	if err != nil {
		return RemoteObject{}, fmt.Errorf("worm get: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		return RemoteObject{}, fmt.Errorf("worm get %s -> %d: %s", key, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	lm, err := parseLastModified(resp.Header)
	if err != nil {
		return RemoteObject{}, fmt.Errorf("worm get %s: %w", key, err)
	}
	return RemoteObject{Key: key, Body: data, LastModified: lm}, nil
}

// ObjectVersion is one version (or delete-marker) of an escrowed key. The verifier
// enumerates these so a DELETE-MARKER hiding a still-locked anchor is detected (a
// plain ListObjectsV2 only returns current versions, so a delete-marked trailing
// anchor would vanish from view and read as "no problem").
type ObjectVersion struct {
	Key            string
	VersionId      string
	LastModified   time.Time
	IsDeleteMarker bool
}

type listVersionsResult struct {
	Versions []struct {
		Key          string `xml:"Key"`
		VersionId    string `xml:"VersionId"`
		LastModified string `xml:"LastModified"`
	} `xml:"Version"`
	DeleteMarkers []struct {
		Key          string `xml:"Key"`
		VersionId    string `xml:"VersionId"`
		LastModified string `xml:"LastModified"`
	} `xml:"DeleteMarker"`
	IsTruncated         bool   `xml:"IsTruncated"`
	NextKeyMarker       string `xml:"NextKeyMarker"`
	NextVersionIdMarker string `xml:"NextVersionIdMarker"`
}

// ListVersions enumerates ALL versions + delete-markers under prefix/<host>/ (S3
// ListObjectVersions), following key/version markers.
func (w *WORMShipper) ListVersions() ([]ObjectVersion, error) {
	prefix := strings.Trim(w.cfg.Prefix, "/")
	if prefix != "" {
		prefix += "/"
	}
	prefix += w.cfg.HostID + "/"
	var out []ObjectVersion
	keyMarker, verMarker := "", ""
	for {
		q := url.Values{"versions": {""}, "prefix": {prefix}}
		if keyMarker != "" {
			q.Set("key-marker", keyMarker)
		}
		if verMarker != "" {
			q.Set("version-id-marker", verMarker)
		}
		resp, err := w.signedDo("GET", "/"+w.cfg.Bucket, q, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("worm list-versions: %w", err)
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("worm list-versions -> %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
		}
		var lr listVersionsResult
		if err := xml.Unmarshal(data, &lr); err != nil {
			return nil, fmt.Errorf("worm list-versions parse: %w", err)
		}
		for _, v := range lr.Versions {
			lm, _ := time.Parse(time.RFC3339Nano, v.LastModified)
			out = append(out, ObjectVersion{Key: v.Key, VersionId: v.VersionId, LastModified: lm})
		}
		for _, d := range lr.DeleteMarkers {
			lm, _ := time.Parse(time.RFC3339Nano, d.LastModified)
			out = append(out, ObjectVersion{Key: d.Key, VersionId: d.VersionId, LastModified: lm, IsDeleteMarker: true})
		}
		if !lr.IsTruncated || (lr.NextKeyMarker == "" && lr.NextVersionIdMarker == "") {
			break
		}
		keyMarker, verMarker = lr.NextKeyMarker, lr.NextVersionIdMarker
	}
	return out, nil
}

// GetVersion fetches a SPECIFIC version's body — so a still-locked anchor is read
// even when a delete-marker hides the current version (a plain Get would 404).
func (w *WORMShipper) GetVersion(key, versionId string) (RemoteObject, error) {
	q := url.Values{}
	if versionId != "" {
		q.Set("versionId", versionId)
	}
	resp, err := w.signedDo("GET", "/"+w.cfg.Bucket+"/"+key, q, nil, nil)
	if err != nil {
		return RemoteObject{}, fmt.Errorf("worm get-version: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		return RemoteObject{}, fmt.Errorf("worm get-version %s@%s -> %d: %s", key, versionId, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	lm, err := parseLastModified(resp.Header)
	if err != nil {
		return RemoteObject{}, fmt.Errorf("worm get-version %s@%s: %w", key, versionId, err)
	}
	return RemoteObject{Key: key, Body: data, LastModified: lm}, nil
}
