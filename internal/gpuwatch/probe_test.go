package gpuwatch

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"testing"
)

func TestPortProbe_ListeningVsClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	ok, _, err := PortProbe{Port: port}.Healthy(context.Background())
	if err != nil || !ok {
		t.Fatalf("listening port: ok=%v err=%v", ok, err)
	}

	ln.Close()
	ok, _, err = PortProbe{Port: port}.Healthy(context.Background())
	if err != nil {
		t.Fatalf("closed port should be unhealthy, not error: %v", err)
	}
	if ok {
		t.Fatal("closed port reported healthy")
	}
}

func TestProcessProbe_PresentAbsentError(t *testing.T) {
	present := ProcessProbe{Pattern: "x", Run: func(ctx context.Context, n string, a ...string) ([]byte, error) {
		return []byte("123\n"), nil
	}}
	if ok, _, err := present.Healthy(context.Background()); err != nil || !ok {
		t.Fatalf("present: ok=%v err=%v", ok, err)
	}

	absent := ProcessProbe{Pattern: "x", Run: func(ctx context.Context, n string, a ...string) ([]byte, error) {
		return nil, &exec.ExitError{ProcessState: &os.ProcessState{}} // pgrep exit 1
	}}
	if ok, _, err := absent.Healthy(context.Background()); err != nil || ok {
		t.Fatalf("absent: ok=%v err=%v", ok, err)
	}

	broken := ProcessProbe{Pattern: "x", Run: func(ctx context.Context, n string, a ...string) ([]byte, error) {
		return nil, &exec.Error{Name: "pgrep", Err: errors.New("not found")}
	}}
	if _, _, err := broken.Healthy(context.Background()); err == nil {
		t.Fatal("missing pgrep binary should surface a real error")
	}
}
