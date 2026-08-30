package okular

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestRealAWSWORMRoundTrip is the box-session harness for OPEN-ITEMS #1/#6: it proves the
// off-box-immutable claim against a REAL S3 Object-Lock bucket (not MinIO). It exercises the
// two bits that were only ever tested against MinIO:
//   - PUT with Content-MD5 must be ACCEPTED by real AWS (the missing header was a real-AWS 400).
//   - ListObjectVersions (?versions) XML must parse on real AWS.
//
// then confirms the immutable escrow catches a real local rewrite. It SKIPS unless a bucket is
// configured, so local + CI stay green; on the box, set:
//
//	OKNEK_REALAWS_BUCKET, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
//	AWS_REGION (default us-east-1), OKNEK_REALAWS_ENDPOINT (e.g. s3.us-east-1.amazonaws.com),
//	OKNEK_REALAWS_PREFIX (default oknek-test)
//
// The bucket MUST have Object-Lock (COMPLIANCE) enabled. Verifying that a locked version
// cannot be deleted is a separate manual step in the box checklist (the shipper has no Delete
// by design): `aws s3api delete-object ...` must be refused.
func TestRealAWSWORMRoundTrip(t *testing.T) {
	bucket := os.Getenv("OKNEK_REALAWS_BUCKET")
	if bucket == "" {
		t.Skip("real-AWS WORM test: set OKNEK_REALAWS_BUCKET (+AWS creds, OKNEK_REALAWS_ENDPOINT) to run against real S3")
	}
	region := envOr("AWS_REGION", "us-east-1")
	// Unique hostID per run: object keys and ListVersions both scope to <prefix>/<hostID>/,
	// so each run is isolated from the immutable (still-locked) objects of prior runs.
	runID := fmt.Sprintf("realaws-%d", time.Now().UnixNano())
	cfg := WORMConfig{
		Enabled:   true,
		Endpoint:  envOr("OKNEK_REALAWS_ENDPOINT", "s3."+region+".amazonaws.com"),
		Insecure:  false,
		Region:    region,
		Bucket:    bucket,
		Prefix:    envOr("OKNEK_REALAWS_PREFIX", "oknek-test"),
		HostID:    runID,
		AccessKey: os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		// Short COMPLIANCE lock for a throwaway test bucket: the objects are immutable
		// (proving WORM) but auto-unlock in 1 day so the bucket isn't pinned for a year.
		RetentionDays: 1,
	}

	l, err := Open(t.TempDir() + "/okular.db")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.SetShipper(NewWORMShipper(cfg, runID))

	// Ship 3 real anchors. EmitAnchor PUTs to S3 with Content-MD5 — a non-nil error here is
	// the exact real-AWS 400 the Content-MD5 fix targets.
	// Realistic, near-now timestamps: a real S3 stamps LastModified at wall-clock time, so
	// the anchor's claimed ts must be ~now or the (correct) back-dating check fires.
	base := time.Now().UnixNano()
	for i := 1; i <= 3; i++ {
		ts := base + int64(i) // distinct, ~now
		if err := l.Append(ts, "agent", "R3", "block", "{}"); err != nil {
			t.Fatal(err)
		}
		a, err := l.EmitAnchor(ts)
		if err != nil {
			t.Fatalf("ship anchor %d to REAL S3 failed (Content-MD5 / SigV4?): %v", i, err)
		}
		if a == nil {
			t.Fatalf("anchor %d not emitted", i)
		}
	}

	// verify-remote against real S3: ListVersions (?versions) XML must parse and the fresh
	// escrow must be clean.
	r, err := l.VerifyRemote(10 * time.Minute)
	if err != nil {
		t.Fatalf("VerifyRemote against real S3 failed (?versions XML?): %v", err)
	}
	if !r.OK || r.Anchors != 3 {
		t.Fatalf("fresh real-S3 escrow should be clean/3, got OK=%v anchors=%d issues=%v", r.OK, r.Anchors, r.Issues)
	}

	// Tamper the LOCAL ledger; the immutable off-box escrow must catch it.
	if _, err := l.db.Exec("UPDATE okular_ledger SET hash='deadbeef' WHERE seq = 2"); err != nil {
		t.Fatal(err)
	}
	r2, _ := l.VerifyRemote(10 * time.Minute)
	if r2.OK || !hasIssue(r2, "REWRITTEN") {
		t.Fatalf("real-S3 escrow must catch the local rewrite, got OK=%v issues=%v", r2.OK, r2.Issues)
	}

	// Immutability BY EFFECT: the locked version must be UNDELETABLE. A real WORM store
	// refuses a versioned DELETE under COMPLIANCE retention — this is the actual guarantee
	// (that root can't destroy escrowed history), not merely that the PUT was accepted.
	vers, err := l.shipper.ListVersions()
	if err != nil || len(vers) == 0 {
		t.Fatalf("list versions for delete-test: %v (n=%d)", err, len(vers))
	}
	v := vers[0]
	resp, derr := l.shipper.signedDo("DELETE", "/"+cfg.Bucket+"/"+v.Key, url.Values{"versionId": {v.VersionId}}, nil, nil)
	if derr != nil {
		t.Fatalf("delete attempt transport error: %v", derr)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		t.Fatalf("IMMUTABILITY BROKEN: locked version %s@%s was DELETED (HTTP %d) — Object-Lock not enforced",
			v.Key, v.VersionId, resp.StatusCode)
	}
	t.Logf("real WORM OK: 3 anchors shipped (Content-MD5 accepted), ?versions parsed, local rewrite caught, "+
		"locked-version DELETE REFUSED -> %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
