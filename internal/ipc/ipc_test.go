package ipc

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "oknek.sock")
	srv, err := NewServer(socket)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	srv.Handle("echo", func(ctx context.Context, req *Request) (interface{}, error) {
		return map[string]string{"got": string(req.Params)}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	// give the server a beat to start accepting
	time.Sleep(50 * time.Millisecond)

	client := NewClient(socket)
	var got map[string]string
	if err := client.Call("echo", map[string]string{"hello": "world"}, &got); err != nil {
		t.Fatalf("Call echo: %v", err)
	}
	if got["got"] == "" {
		t.Errorf("expected got to contain params, got: %v", got)
	}
}

func TestUnknownMethod(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "oknek.sock")
	srv, err := NewServer(socket)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	time.Sleep(50 * time.Millisecond)

	client := NewClient(socket)
	err = client.Call("does-not-exist", nil, nil)
	if err == nil {
		t.Fatalf("expected error for unknown method")
	}
}
