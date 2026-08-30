package okular

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockObj is one object the fake S3 serves: the anchor body + its server-side time.
type mockObj struct {
	body []byte
	lm   time.Time
}

// mockS3 serves S3 ListObjectVersions (?versions) + a versioned GET for a fixed
// key->object map, so VerifyRemote (which enumerates versions) can be exercised against
// controllable escrow contents with no real S3. dms marks keys that also carry a
// delete-marker (the locked Version still exists — i.e. the tail-hiding combined attack).
func mockS3(objs map[string]mockObj) *httptest.Server { return mockS3DM(objs, nil) }

func mockS3DM(objs map[string]mockObj, dms map[string]bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("versions") {
			var b strings.Builder
			b.WriteString(`<ListVersionsResult>`)
			for k, o := range objs {
				fmt.Fprintf(&b, `<Version><Key>%s</Key><VersionId>v-%s</VersionId><LastModified>%s</LastModified></Version>`,
					xmlEsc(k), xmlEsc(k), o.lm.UTC().Format(time.RFC3339Nano))
			}
			for k := range dms {
				fmt.Fprintf(&b, `<DeleteMarker><Key>%s</Key><VersionId>dm-%s</VersionId><LastModified>%s</LastModified></DeleteMarker>`,
					xmlEsc(k), xmlEsc(k), objs[k].lm.UTC().Format(time.RFC3339Nano))
			}
			b.WriteString(`<IsTruncated>false</IsTruncated></ListVersionsResult>`)
			w.Write([]byte(b.String()))
			return
		}
		// GET /bucket/<key> (versioned or not — one version per key in the mock)
		key := strings.TrimPrefix(r.URL.Path, "/anchors/")
		o, ok := objs[key]
		if !ok {
			http.Error(w, "no such key", 404)
			return
		}
		w.Header().Set("Last-Modified", o.lm.UTC().Format(http.TimeFormat))
		w.Write(o.body)
	}))
}

func xmlEsc(s string) string { var b strings.Builder; xml.EscapeText(&b, []byte(s)); return b.String() }

// shipperTo points a shipper at the mock server's host.
func shipperTo(srv *httptest.Server) *WORMShipper {
	host := strings.TrimPrefix(srv.URL, "http://")
	return NewWORMShipper(WORMConfig{
		Enabled: true, Endpoint: host, Insecure: true, Region: "us-east-1",
		Bucket: "anchors", Prefix: "oknek", HostID: "h", AccessKey: "ak", SecretKey: "sk",
	}, "h")
}

// freshLedger builds a ledger with n sealed entries and returns it plus the n anchors
// it would escrow (one per advancing head), signed with the ledger's key.
func freshLedger(t *testing.T, n int) (*Ledger, []Anchor) {
	t.Helper()
	dir := t.TempDir()
	l, err := Open(dir + "/okular.db")
	if err != nil {
		t.Fatal(err)
	}
	var anchors []Anchor
	for i := 1; i <= n; i++ {
		if err := l.Append(int64(i*1000), "agent", "R3", "block", "{}"); err != nil {
			t.Fatal(err)
		}
		a, err := l.EmitAnchor(int64(i * 1000)) // ts = i*1000 ns; no shipper set => local only
		if err != nil || a == nil {
			t.Fatalf("emit %d: %v", i, err)
		}
		anchors = append(anchors, *a)
	}
	return l, anchors
}

// objsFromAnchors lays anchors into the mock keyspace with LastModified ≈ ts (legit).
func objsFromAnchors(anchors []Anchor) map[string]mockObj {
	m := map[string]mockObj{}
	for _, a := range anchors {
		body, _ := json.Marshal(a)
		key := fmt.Sprintf("oknek/h/%020d.json", a.Seq)
		m[key] = mockObj{body: body, lm: time.Unix(0, a.TS)} // escrowed at ~claimed ts
	}
	return m
}

func TestVerifyRemoteHappyPath(t *testing.T) {
	l, anchors := freshLedger(t, 3)
	defer l.Close()
	srv := mockS3(objsFromAnchors(anchors))
	defer srv.Close()
	l.SetShipper(shipperTo(srv))
	r, err := l.VerifyRemote(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK || r.Anchors != 3 {
		t.Fatalf("want OK/3, got OK=%v anchors=%d issues=%v", r.OK, r.Anchors, r.Issues)
	}
}

func TestVerifyRemoteCatchesGap(t *testing.T) {
	l, anchors := freshLedger(t, 3)
	defer l.Close()
	objs := objsFromAnchors(anchors)
	delete(objs, fmt.Sprintf("oknek/h/%020d.json", 2)) // a blocked ship / hidden object
	srv := mockS3(objs)
	defer srv.Close()
	l.SetShipper(shipperTo(srv))
	r, _ := l.VerifyRemote(5 * time.Minute)
	if r.OK || !hasIssue(r, "GAP") {
		t.Fatalf("want GAP issue, got %+v", r.Issues)
	}
}

func TestVerifyRemoteCatchesBackDating(t *testing.T) {
	l, anchors := freshLedger(t, 2)
	defer l.Close()
	objs := objsFromAnchors(anchors)
	// anchor #2 escrowed an hour AFTER its claimed ts = back-dated content.
	k := fmt.Sprintf("oknek/h/%020d.json", 2)
	o := objs[k]
	o.lm = time.Unix(0, anchors[1].TS).Add(time.Hour)
	objs[k] = o
	srv := mockS3(objs)
	defer srv.Close()
	l.SetShipper(shipperTo(srv))
	r, _ := l.VerifyRemote(5 * time.Minute)
	if r.OK || !hasIssue(r, "BACK-DATED") {
		t.Fatalf("want BACK-DATED issue, got %+v", r.Issues)
	}
}

func TestVerifyRemoteCatchesBadSignature(t *testing.T) {
	l, anchors := freshLedger(t, 2)
	defer l.Close()
	objs := objsFromAnchors(anchors)
	// corrupt anchor #1's signature (still valid JSON + chain, bad sig).
	a := anchors[0]
	a.Signature = strings.Repeat("00", 64)
	body, _ := json.Marshal(a)
	objs[fmt.Sprintf("oknek/h/%020d.json", 1)] = mockObj{body: body, lm: time.Unix(0, a.TS)}
	srv := mockS3(objs)
	defer srv.Close()
	l.SetShipper(shipperTo(srv))
	r, _ := l.VerifyRemote(5 * time.Minute)
	if r.OK || !hasIssue(r, "bad signature") {
		t.Fatalf("want bad-signature issue, got %+v", r.Issues)
	}
}

func TestVerifyRemoteCatchesLedgerRewrite(t *testing.T) {
	l, anchors := freshLedger(t, 2)
	defer l.Close()
	srv := mockS3(objsFromAnchors(anchors))
	defer srv.Close()
	l.SetShipper(shipperTo(srv))
	// rewrite the on-box ledger entry at anchor #2's head_seq (escrow is immutable).
	if _, err := l.db.Exec("UPDATE okular_ledger SET hash='deadbeef' WHERE seq=2"); err != nil {
		t.Fatal(err)
	}
	r, _ := l.VerifyRemote(5 * time.Minute)
	if r.OK || !hasIssue(r, "LEDGER REWRITTEN") {
		t.Fatalf("want LEDGER REWRITTEN issue, got %+v", r.Issues)
	}
}

func TestVerifyRemoteCatchesLedgerDelete(t *testing.T) {
	l, anchors := freshLedger(t, 2)
	defer l.Close()
	srv := mockS3(objsFromAnchors(anchors))
	defer srv.Close()
	l.SetShipper(shipperTo(srv))
	// root DELETES the on-box ledger row at anchor #2's head_seq (truncation, not edit).
	if _, err := l.db.Exec("DELETE FROM okular_ledger WHERE seq=2"); err != nil {
		t.Fatal(err)
	}
	r, _ := l.VerifyRemote(5 * time.Minute)
	if r.OK || !hasIssue(r, "TRUNCATED") {
		t.Fatalf("want TRUNCATED issue after DELETE, got %+v", r.Issues)
	}
}

func TestVerifyRemoteCatchesTrailingShipStop(t *testing.T) {
	l, anchors := freshLedger(t, 3) // local knows anchors 1..3
	defer l.Close()
	objs := objsFromAnchors(anchors)
	delete(objs, fmt.Sprintf("oknek/h/%020d.json", 3)) // escrow only got 1,2 (trailing stop / hidden tail)
	srv := mockS3(objs)
	defer srv.Close()
	l.SetShipper(shipperTo(srv))
	r, _ := l.VerifyRemote(5 * time.Minute)
	if r.OK || !hasIssue(r, "TRAILING SHIP-STOP") {
		t.Fatalf("want TRAILING SHIP-STOP issue, got %+v", r.Issues)
	}
}

func TestVerifyRemoteCatchesDeleteMarkerTail(t *testing.T) {
	l, anchors := freshLedger(t, 3)
	defer l.Close()
	objs := objsFromAnchors(anchors)
	// The combined attack: root adds a delete-marker on anchor #3 (hiding it from a plain
	// object list) and could rewrite local .anchors to match — but the locked version still
	// exists, so version-enumeration recovers it AND flags the delete-marker as tamper.
	dm := map[string]bool{fmt.Sprintf("oknek/h/%020d.json", 3): true}
	srv := mockS3DM(objs, dm)
	defer srv.Close()
	l.SetShipper(shipperTo(srv))
	r, _ := l.VerifyRemote(5 * time.Minute)
	if r.OK || !hasIssue(r, "HIDDEN by a delete-marker") {
		t.Fatalf("want delete-marker tamper issue, got %+v", r.Issues)
	}
	if r.NewestSeq != 3 {
		t.Fatalf("want NewestSeq=3 (locked version recovered despite the delete-marker), got %d", r.NewestSeq)
	}
}

func TestVerifyRemoteFlagsMissingTimestamp(t *testing.T) {
	l, anchors := freshLedger(t, 1)
	defer l.Close()
	objs := objsFromAnchors(anchors)
	k := fmt.Sprintf("oknek/h/%020d.json", 1)
	o := objs[k]
	o.lm = time.Time{} // zero / unparseable escrow timestamp
	objs[k] = o
	srv := mockS3(objs)
	defer srv.Close()
	l.SetShipper(shipperTo(srv))
	r, _ := l.VerifyRemote(5 * time.Minute)
	if r.OK || !hasIssue(r, "cannot verify back-dating") {
		t.Fatalf("want missing-timestamp issue (fail-closed), got %+v", r.Issues)
	}
}

func hasIssue(r RemoteVerifyResult, substr string) bool {
	for _, s := range r.Issues {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}
