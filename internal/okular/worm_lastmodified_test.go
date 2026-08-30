package okular

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestShipper points a WORMShipper at an httptest server (path-style, insecure).
func newTestShipper(url string) *WORMShipper {
	endpoint := strings.TrimPrefix(url, "http://")
	return NewWORMShipper(WORMConfig{
		Endpoint: endpoint, Insecure: true, Region: "us-east-1",
		Bucket: "b", AccessKey: "k", SecretKey: "s",
	}, "host")
}

// A valid RFC1123 Last-Modified (the format S3/HTTP actually sends) must parse to a
// non-zero time. The prior bug parsed it as RFC3339 and silently got zero-time —
// which would pass a back-dating check that should have failed (fail-open).
func TestWORMGetParsesRFC1123LastModified(t *testing.T) {
	const raw = "Wed, 21 Oct 2026 07:28:00 GMT"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", raw)
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	obj, err := newTestShipper(srv.URL).Get("anchors/host/x.json")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if obj.LastModified.IsZero() {
		t.Fatal("LastModified is zero — RFC1123 header not parsed (fail-open regression)")
	}
	want, _ := http.ParseTime(raw)
	if !obj.LastModified.Equal(want) {
		t.Fatalf("LastModified = %v, want %v", obj.LastModified, want)
	}
}

// A present-but-malformed Last-Modified must be a hard error — never a swallowed
// zero-time that reads as "no back-dating".
func TestWORMGetRejectsMalformedLastModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", "not-a-date")
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	if _, err := newTestShipper(srv.URL).Get("anchors/host/x.json"); err == nil {
		t.Fatal("want error on malformed Last-Modified, got nil (error swallowed)")
	}
}

// GetVersion shares the same parse path; the malformed header must error there too.
func TestWORMGetVersionRejectsMalformedLastModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", "garbage")
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	if _, err := newTestShipper(srv.URL).GetVersion("anchors/host/x.json", "v1"); err == nil {
		t.Fatal("want error on malformed Last-Modified in GetVersion, got nil")
	}
}
