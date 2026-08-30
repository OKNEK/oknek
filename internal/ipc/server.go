package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// Handler processes a request and returns a result (JSON-serializable) or error.
type Handler func(ctx context.Context, req *Request) (interface{}, error)

// Server is a Unix-socket JSON-RPC-ish server.
type Server struct {
	socket   string
	listener net.Listener
	handlers map[string]Handler
	mu       sync.RWMutex
}

// NewServer creates the socket directory, listens on socket, and chmods it 0660.
// Stale sockets from prior runs are removed first.
func NewServer(socket string) (*Server, error) {
	if err := os.MkdirAll(filepath.Dir(socket), 0o750); err != nil {
		return nil, fmt.Errorf("mkdir socket dir: %w", err)
	}
	_ = os.Remove(socket) // stale socket cleanup; ignore error
	l, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", socket, err)
	}
	if err := os.Chmod(socket, 0o660); err != nil {
		l.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return &Server{
		socket:   socket,
		listener: l,
		handlers: make(map[string]Handler),
	}, nil
}

// Handle registers a handler for a method name. Safe to call before or after Serve.
func (s *Server) Handle(method string, h Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[method] = h
}

// Serve runs the accept loop until ctx is cancelled or the listener is closed.
func (s *Server) Serve(ctx context.Context) error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("ipc accept: %v", err)
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

// peerPIDKey is the context key under which a connection's SO_PEERCRED PID is stored.
type peerPIDKey struct{}

// PeerPIDFromContext returns the connecting peer's global PID (via SO_PEERCRED), if
// the platform supports it. Handlers use this for namespace-correct, spoof-proof
// agent identity instead of trusting a PID in the request body.
func PeerPIDFromContext(ctx context.Context) (int, bool) {
	pid, ok := ctx.Value(peerPIDKey{}).(int)
	return pid, ok && pid > 0
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if pid, ok := peerPID(conn); ok {
		ctx = context.WithValue(ctx, peerPIDKey{}, pid)
	}
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var req Request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			s.writeResp(conn, Response{Error: "invalid json: " + err.Error()})
			continue
		}
		s.mu.RLock()
		h, ok := s.handlers[req.Method]
		s.mu.RUnlock()
		if !ok {
			s.writeResp(conn, Response{ID: req.ID, Error: "unknown method: " + req.Method})
			continue
		}
		result, hErr := h(ctx, &req)
		resp := Response{ID: req.ID}
		if hErr != nil {
			resp.Error = hErr.Error()
		} else if result != nil {
			data, mErr := json.Marshal(result)
			if mErr != nil {
				resp.Error = "marshal result: " + mErr.Error()
			} else {
				resp.Result = data
			}
		}
		s.writeResp(conn, resp)
	}
}

func (s *Server) writeResp(conn net.Conn, resp Response) {
	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	_, _ = conn.Write(data)
}

// Close stops the server, removes the socket file, and releases the listener.
func (s *Server) Close() error {
	err := s.listener.Close()
	_ = os.Remove(s.socket)
	return err
}
