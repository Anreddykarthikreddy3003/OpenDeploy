// Package api is platformd's HTTP API (/api/v2), GitHub webhook ingress
// and embedded dashboard (PRD §15, §20.1, SC-11).
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/auth"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/model"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/platform"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// Session lifetimes.
const (
	SessionAbsolute = 12 * time.Hour
	SessionIdle     = 2 * time.Hour
	ReauthWindow    = 5 * time.Minute
	cookieSecure    = "__Host-od_session"
	cookiePlain     = "od_session"
	csrfHeader      = "X-CSRF-Token"
)

// Server is the HTTP API.
type Server struct {
	P          *platform.Platform
	S          *store.Store
	Log        *slog.Logger
	Sealer     *auth.Sealer
	UI         fs.FS // embedded dashboard (may be nil)
	RequireMFA bool
	// BootstrapToken must be presented to create the first owner.
	BootstrapToken string
	allowed        []netip.Prefix
	limiter        *limiter
	authLimiter    *limiter
	mux            *http.ServeMux
	webauthnState  sync.Map
}

// New builds the server.
func New(p *platform.Platform, sealer *auth.Sealer, ui fs.FS, requireMFA bool, bootstrapToken string) *Server {
	s := &Server{P: p, S: p.Store, Log: p.Log, Sealer: sealer, UI: ui, RequireMFA: requireMFA, BootstrapToken: bootstrapToken,
		limiter: newLimiter(30, 60), authLimiter: newLimiter(0.2, 10), mux: http.NewServeMux()}
	for _, c := range p.Node.API.RemoteAdmin.AllowedCIDRs {
		if pr, err := netip.ParsePrefix(c); err == nil {
			s.allowed = append(s.allowed, pr)
		}
	}
	s.routes()
	return s
}

// Handler returns the root handler with middleware.
func (s *Server) Handler() http.Handler {
	return s.recoverer(s.securityHeaders(s.remoteAdminGate(s.mux)))
}

// ---------------------------------------------------------------- context

type ctxKey int

const principalKey ctxKey = 1

// Principal is the authenticated caller.
type Principal struct {
	User    *store.User
	Session *store.Session
	Token   *store.APIToken
}

func (p *Principal) capRole() string {
	if p.Token != nil {
		return p.Token.RoleCap
	}
	return ""
}

func (p *Principal) mfa() bool {
	if p.Session != nil {
		return p.Session.MFAVerified
	}
	return false
}

func principal(r *http.Request) *Principal {
	p, _ := r.Context().Value(principalKey).(*Principal)
	return p
}

// ---------------------------------------------------------------- helpers

type apiError struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *apiError) Error() string { return e.Message }

func errf(status int, code, f string, a ...any) *apiError {
	return &apiError{Status: status, Code: code, Message: fmt.Sprintf(f, a...)}
}

var (
	errUnauthorized = errf(401, "unauthorized", "authentication required")
	errForbidden    = errf(403, "forbidden", "you do not have permission for this action")
	errNotFound     = errf(404, "not_found", "not found")
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	switch {
	case errors.As(err, &ae):
	case errors.Is(err, store.ErrNotFound):
		ae = errNotFound
	case errors.Is(err, store.ErrConflict):
		ae = errf(409, "conflict", "%s", err.Error())
	case errors.Is(err, state.ErrDegraded):
		ae = errf(503, "degraded", "platform state is in degraded read-only mode; repair or restore required")
	default:
		var ie *ipc.Error
		if errors.As(err, &ie) {
			switch ie.Code {
			case ipc.CodeNotFound:
				ae = errf(404, "not_found", "%s", ie.Message)
			case ipc.CodeBadRequest:
				ae = errf(400, "bad_request", "%s", ie.Message)
			case ipc.CodeForbidden:
				ae = errf(403, "forbidden", "%s", ie.Message)
			case ipc.CodeConflict:
				ae = errf(409, "conflict", "%s", ie.Message)
			default:
				ae = errf(503, "unavailable", "a platform service is unavailable")
			}
		} else {
			s.Log.Error("api error", "path", r.URL.Path, "err", err)
			ae = errf(500, "internal", "internal error")
		}
	}
	writeJSON(w, ae.Status, ae)
}

const maxJSONBody = 1 << 20

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return errf(400, "bad_request", "invalid JSON body: %v", err)
	}
	return nil
}

type handler func(w http.ResponseWriter, r *http.Request) error

func (s *Server) wrap(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			s.writeErr(w, r, err)
		}
	}
}

// clientIP returns the direct peer address (proxies are not trusted unless
// configured).
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	for _, tp := range s.P.Node.API.TrustedProxy {
		if host == tp {
			if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
				parts := strings.Split(xf, ",")
				return strings.TrimSpace(parts[len(parts)-1])
			}
		}
	}
	return host
}

// ---------------------------------------------------------------- middleware

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.Log.Error("panic in handler", "path", r.URL.Path, "panic", fmt.Sprint(v))
				writeJSON(w, 500, errf(500, "internal", "internal error"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self' https://github.com")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// remoteAdminGate enforces the interface/allowlist policy for non-loopback
// callers (PRD §15.1).
func (s *Server) remoteAdminGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, err := netip.ParseAddr(s.clientIP(r))
		if err == nil && !ip.Unmap().IsLoopback() && !strings.HasPrefix(r.URL.Path, "/webhooks/") {
			ok := false
			for _, pr := range s.allowed {
				if pr.Contains(ip.Unmap()) {
					ok = true
				}
			}
			if !ok || !s.P.Node.API.RemoteAdmin.Enabled {
				writeJSON(w, 403, errf(403, "forbidden", "remote administration is not permitted from this address"))
				return
			}
			if r.TLS == nil {
				writeJSON(w, 403, errf(403, "forbidden", "remote administration requires TLS"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// authn resolves the session cookie or bearer token.
func (s *Server) authn(r *http.Request) (*Principal, error) {
	ctx := r.Context()
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		tok := strings.TrimPrefix(h, "Bearer ")
		if !strings.HasPrefix(tok, "odt_") {
			return nil, errUnauthorized
		}
		t, err := s.S.GetAPITokenByHash(ctx, auth.HashToken(tok))
		if err != nil || t.RevokedAt != "" || (t.ExpiresAt != "" && t.ExpiresAt < state.Now()) {
			return nil, errUnauthorized
		}
		u, err := s.S.GetUser(ctx, t.UserID)
		if err != nil || u.Disabled {
			return nil, errUnauthorized
		}
		s.S.TouchAPIToken(ctx, t.ID)
		return &Principal{User: u, Token: t}, nil
	}
	c, err := r.Cookie(cookieSecure)
	if err != nil {
		c, err = r.Cookie(cookiePlain)
	}
	if err != nil || c.Value == "" {
		return nil, errUnauthorized
	}
	sess, err := s.S.GetSession(ctx, auth.HashToken(c.Value))
	if err != nil {
		return nil, errUnauthorized
	}
	now := state.Now()
	if sess.RevokedAt != "" || sess.ExpiresAt < now || sess.IdleExpiresAt < now {
		return nil, errUnauthorized
	}
	u, err := s.S.GetUser(ctx, sess.UserID)
	if err != nil || u.Disabled {
		return nil, errUnauthorized
	}
	_ = s.S.TouchSession(ctx, sess.ID, SessionIdle)
	return &Principal{User: u, Session: sess}, nil
}

// authed wraps a handler requiring authentication, CSRF protection for
// cookie sessions and completed MFA (unless allowPreMFA).
func (s *Server) authed(h handler, allowPreMFA bool) http.HandlerFunc {
	return s.wrap(func(w http.ResponseWriter, r *http.Request) error {
		if !s.limiter.allow(s.clientIP(r)) {
			return errf(429, "rate_limited", "too many requests")
		}
		p, err := s.authn(r)
		if err != nil {
			return err
		}
		if p.Session != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get(csrfHeader)), []byte(p.Session.CSRFToken)) != 1 {
				return errf(403, "csrf", "missing or invalid CSRF token")
			}
			if o := r.Header.Get("Origin"); o != "" && !sameOrigin(o, r) {
				return errf(403, "csrf", "cross-origin request rejected")
			}
		}
		if p.Session != nil && !p.Session.MFAVerified {
			needs := p.User.TOTPEnabled || p.User.WebAuthnCount > 0
			if needs && !allowPreMFA {
				return errf(401, "mfa_required", "multi-factor authentication required")
			}
			if !needs && s.mfaMandatory(p.User) && !allowPreMFA {
				return errf(403, "mfa_enrollment_required", "your role requires multi-factor authentication; enroll a second factor")
			}
		}
		ctx := context.WithValue(r.Context(), principalKey, p)
		return h(w, r.WithContext(ctx))
	})
}

func (s *Server) mfaMandatory(u *store.User) bool {
	return s.RequireMFA && (u.Role == model.RoleOwner || u.Role == model.RoleAdmin)
}

func sameOrigin(origin string, r *http.Request) bool {
	o := strings.TrimSuffix(origin, "/")
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return o == scheme+"://"+r.Host
}

// requireNode checks a node-scoped action (and re-auth for sensitive ones).
func (s *Server) requireNode(r *http.Request, a auth.Action) error {
	p := principal(r)
	if p == nil {
		return errUnauthorized
	}
	if !auth.AllowedNode(p.User.Role, p.capRole(), a) {
		s.auditDenied(r, string(a), "", "")
		return errForbidden
	}
	return s.requireReauth(r, a)
}

// requireProject loads the project and checks a project-scoped action. A
// project the caller cannot read is reported as not found (no IDOR oracle).
func (s *Server) requireProject(r *http.Request, id string, a auth.Action) (*store.Project, error) {
	p := principal(r)
	if p == nil {
		return nil, errUnauthorized
	}
	proj, err := s.S.GetProject(r.Context(), id)
	if err != nil {
		return nil, errNotFound
	}
	role, err := s.S.MemberRole(r.Context(), proj.ID, p.User.ID)
	if err != nil {
		return nil, err
	}
	if !auth.AllowedProject(p.User.Role, role, p.capRole(), auth.ProjectRead) {
		return nil, errNotFound
	}
	if !auth.AllowedProject(p.User.Role, role, p.capRole(), a) {
		s.auditDenied(r, string(a), "project", proj.ID)
		return nil, errForbidden
	}
	if err := s.requireReauth(r, a); err != nil {
		return nil, err
	}
	return proj, nil
}

// requireReauth enforces recent re-authentication (and MFA where the user
// has it) for sensitive actions. API tokens cannot perform them.
func (s *Server) requireReauth(r *http.Request, a auth.Action) error {
	if !auth.Sensitive(a) {
		return nil
	}
	p := principal(r)
	if p.Token != nil {
		return errf(403, "session_required", "this action requires an interactive session with recent re-authentication")
	}
	if p.Session.ReauthAt == "" || time.Since(state.ParseTime(p.Session.ReauthAt)) > ReauthWindow {
		return errf(401, "reauth_required", "re-enter your password (and second factor) to continue")
	}
	if (p.User.TOTPEnabled || p.User.WebAuthnCount > 0) && !p.Session.MFAVerified {
		return errf(401, "mfa_required", "multi-factor authentication required")
	}
	return nil
}

func (s *Server) auditDenied(r *http.Request, action, rtype, rid string) {
	s.audit(r, "authz.deny", rtype, rid, "", audit.Denied, map[string]string{"reason": action})
}

// audit records a user action.
func (s *Server) audit(r *http.Request, action, rtype, rid, projectID, result string, details map[string]string) {
	e := audit.Event{Action: action, ResourceType: rtype, ResourceID: rid, ProjectID: projectID, Result: result, Details: details,
		SourceIP: s.clientIP(r), ActorType: audit.ActorAnon}
	if p := principal(r); p != nil {
		e.ActorID = p.User.ID
		e.ActorType = audit.ActorUser
		e.MFA = p.mfa()
		if p.Session != nil {
			e.SessionID = p.Session.ID[:16]
		}
		if p.Token != nil {
			e.ActorType = audit.ActorToken
			if e.Details == nil {
				e.Details = map[string]string{}
			}
			e.Details["token_id"] = p.Token.ID
		}
	}
	if _, err := s.P.Audit.Append(r.Context(), e); err != nil {
		s.Log.Warn("audit append failed", "action", action, "err", err)
	}
}

// ---------------------------------------------------------------- limiter

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu    sync.Mutex
	rate  float64 // tokens per second
	burst float64
	m     map[string]*bucket
}

func newLimiter(rate, burst float64) *limiter {
	return &limiter{rate: rate, burst: burst, m: map[string]*bucket{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.m[key]
	if !ok {
		if len(l.m) > 10000 {
			l.m = map[string]*bucket{}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.m[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
