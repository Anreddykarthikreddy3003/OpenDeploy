// Package ipc provides typed, identity-checked request/response calls between
// OpenDeploy Tier-0 services over Unix domain sockets (PRD §4.1, SC-10).
//
// Every service listens on its own socket. Each operation is registered with
// the explicit set of caller identities allowed to invoke it. Caller identity
// comes from kernel SO_PEERCRED (the peer's UID mapped to a service
// identity), never from anything the caller sends. There is no generic
// "exec" operation anywhere in the IPC surface.
package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MaxBody bounds request/response bodies.
const MaxBody = 4 << 20

// Peer is the kernel-reported identity of a connected process.
type Peer struct {
	UID, GID uint32
	PID      int32
	Verified bool
}

// Caller is the resolved service identity of a peer.
type Caller struct {
	Identity string
	Peer     Peer
}

type ctxKey int

const peerKey ctxKey = 0

// Error is the wire error type. Code is a stable machine-readable string.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Common error codes.
const (
	CodeForbidden   = "forbidden"
	CodeBadRequest  = "bad_request"
	CodeNotFound    = "not_found"
	CodeConflict    = "conflict"
	CodeInternal    = "internal"
	CodeUnavailable = "unavailable"
	CodeDegraded    = "degraded"
)

// Errorf builds a typed error that is transmitted to the caller.
func Errorf(code, format string, a ...any) error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...)}
}

// IsCode reports whether err is an ipc Error with the given code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// IdentityMap resolves peer UIDs to service identities.
type IdentityMap struct {
	mu    sync.RWMutex
	byUID map[uint32]string
	// DevIdentityHeader enables the insecure development mode in which all
	// services share one UID and callers declare their identity. It must never
	// be enabled in production; hostd refuses to start services with it set.
	DevIdentityHeader bool
}

func NewIdentityMap(m map[uint32]string) *IdentityMap {
	cp := make(map[uint32]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return &IdentityMap{byUID: cp}
}

func (m *IdentityMap) Resolve(p Peer, declared string) (string, bool) {
	if m.DevIdentityHeader {
		if declared != "" {
			return declared, true
		}
	}
	if !p.Verified {
		return "", false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.byUID[p.UID]
	return id, ok
}

const devIdentityHeader = "X-OpenDeploy-Dev-Identity"

// Server is a typed IPC server bound to a Unix socket.
type Server struct {
	Name string
	ids  *IdentityMap
	mux  *http.ServeMux
	log  *slog.Logger
	srv  *http.Server
	ln   net.Listener
	ops  map[string]bool
	mu   sync.Mutex
}

func NewServer(name string, ids *IdentityMap, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{Name: name, ids: ids, mux: http.NewServeMux(), log: log, ops: map[string]bool{}}
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	return s
}

// Ops returns the registered operation names (for inventory tests).
func (s *Server) Ops() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.ops))
	for k := range s.ops {
		out = append(out, k)
	}
	return out
}

// Handler is a typed operation implementation.
type Handler[Req, Resp any] func(ctx context.Context, c Caller, req Req) (Resp, error)

// Handle registers op, callable only by the listed identities.
func Handle[Req, Resp any](s *Server, op string, allowed []string, h Handler[Req, Resp]) {
	if len(allowed) == 0 {
		panic("ipc: operation " + op + " registered with no allowed callers")
	}
	if strings.ContainsAny(op, " /") {
		panic("ipc: invalid op name " + op)
	}
	allow := map[string]bool{}
	for _, a := range allowed {
		allow[a] = true
	}
	s.mu.Lock()
	if s.ops[op] {
		s.mu.Unlock()
		panic("ipc: duplicate op " + op)
	}
	s.ops[op] = true
	s.mu.Unlock()
	s.mux.HandleFunc("POST /v1/"+op, func(w http.ResponseWriter, r *http.Request) {
		p, _ := r.Context().Value(peerKey).(Peer)
		id, ok := s.ids.Resolve(p, r.Header.Get(devIdentityHeader))
		if !ok || !allow[id] {
			s.log.Warn("ipc denied", "server", s.Name, "op", op, "identity", id, "uid", p.UID, "pid", p.PID)
			writeErr(w, http.StatusForbidden, &Error{Code: CodeForbidden, Message: "caller not permitted for " + op})
			return
		}
		var req Req
		dec := json.NewDecoder(io.LimitReader(r.Body, MaxBody))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeErr(w, http.StatusBadRequest, &Error{Code: CodeBadRequest, Message: "decode: " + err.Error()})
			return
		}
		resp, err := h(r.Context(), Caller{Identity: id, Peer: p}, req)
		if err != nil {
			var ie *Error
			if errors.As(err, &ie) {
				writeErr(w, statusFor(ie.Code), ie)
				return
			}
			s.log.Error("ipc handler failed", "server", s.Name, "op", op, "err", err)
			writeErr(w, http.StatusInternalServerError, &Error{Code: CodeInternal, Message: "internal error"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

func statusFor(code string) int {
	switch code {
	case CodeForbidden:
		return http.StatusForbidden
	case CodeBadRequest:
		return http.StatusBadRequest
	case CodeNotFound:
		return http.StatusNotFound
	case CodeConflict:
		return http.StatusConflict
	case CodeUnavailable, CodeDegraded:
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}

func writeErr(w http.ResponseWriter, status int, e *Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(e)
}

// Listen binds the socket at path with the given file mode. The parent
// directory must already exist with restrictive permissions.
func (s *Server) Listen(path string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		return err
	}
	s.ln = ln
	return nil
}

// Serve serves until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		return errors.New("ipc: Listen not called")
	}
	s.srv = &http.Server{
		Handler:           s.mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			p, _ := peerCred(c)
			return context.WithValue(ctx, peerKey, p)
		},
	}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(sh)
	}()
	err := s.srv.Serve(s.ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ServeListener serves on a pre-bound listener (tests, socket activation).
func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	s.ln = ln
	return s.Serve(ctx)
}

// Client calls a single IPC server.
type Client struct {
	hc          *http.Client
	devIdentity string
}

// NewClient dials the Unix socket at path.
func NewClient(path string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
		MaxIdleConns:    8,
		IdleConnTimeout: 60 * time.Second,
	}
	return &Client{hc: &http.Client{Transport: tr, Timeout: 5 * time.Minute}}
}

// WithDevIdentity sets the declared identity for insecure dev mode.
func (c *Client) WithDevIdentity(id string) *Client {
	cp := *c
	cp.devIdentity = id
	return &cp
}

// Healthy reports whether the server answers its health endpoint.
func (c *Client) Healthy(ctx context.Context) error {
	hr, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://ipc/healthz", nil)
	if err != nil {
		return err
	}
	res, err := c.hc.Do(hr)
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("health check: %s", res.Status)
	}
	return nil
}

// Call invokes op on the server.
func Call[Req, Resp any](ctx context.Context, c *Client, op string, req Req) (Resp, error) {
	var zero Resp
	body, err := json.Marshal(req)
	if err != nil {
		return zero, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://ipc/v1/"+op, bytes.NewReader(body))
	if err != nil {
		return zero, err
	}
	hr.Header.Set("Content-Type", "application/json")
	if c.devIdentity != "" {
		hr.Header.Set(devIdentityHeader, c.devIdentity)
	}
	res, err := c.hc.Do(hr)
	if err != nil {
		return zero, &Error{Code: CodeUnavailable, Message: err.Error()}
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, MaxBody))
	if err != nil {
		return zero, err
	}
	if res.StatusCode != http.StatusOK {
		var e Error
		if json.Unmarshal(data, &e) == nil && e.Code != "" {
			return zero, &e
		}
		return zero, &Error{Code: CodeInternal, Message: fmt.Sprintf("status %d", res.StatusCode)}
	}
	var out Resp
	if err := json.Unmarshal(data, &out); err != nil {
		return zero, err
	}
	return out, nil
}
