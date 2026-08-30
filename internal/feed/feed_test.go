package feed

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type capture struct {
	auth string
	body map[string]interface{}
}

func TestPost_SendsBearerAndBody(t *testing.T) {
	got := make(chan capture, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]interface{}
		_ = json.Unmarshal(b, &m)
		got <- capture{auth: r.Header.Get("Authorization"), body: m}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	p := New(srv.URL, "okik_test")
	if p == nil {
		t.Fatal("New returned nil for valid url/key")
	}
	p.Post("e1", 123, "agentA", "R1", "block", `{"path":"/etc/shadow","enforcement":"ebpf"}`)

	select {
	case c := <-got:
		if c.auth != "Bearer okik_test" {
			t.Errorf("auth = %q, want Bearer okik_test", c.auth)
		}
		if c.body["id"] != "e1" || c.body["rule_id"] != "R1" || c.body["verdict"] != "block" {
			t.Errorf("body core fields wrong: %+v", c.body)
		}
		if c.body["agent_id"] != "agentA" || c.body["path"] != "/etc/shadow" || c.body["enforcement"] != "ebpf" {
			t.Errorf("body derived fields wrong: %+v", c.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no POST received within 3s")
	}
}

func TestNew_NilWhenEmpty(t *testing.T) {
	if New("", "k") != nil {
		t.Error("New with empty url should be nil")
	}
	if New("http://x", "") != nil {
		t.Error("New with empty key should be nil")
	}
}

func TestPost_NilSafe(t *testing.T) {
	var p *Poster
	p.Post("e", 1, "a", "R1", "block", "{}") // must not panic
}
