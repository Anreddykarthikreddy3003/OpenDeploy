package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/auth"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/daemon"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/model"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

type userView struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	Role          string `json:"role"`
	TOTPEnabled   bool   `json:"totp_enabled"`
	WebAuthnCount int    `json:"webauthn_count"`
	Disabled      bool   `json:"disabled"`
	CreatedAt     string `json:"created_at"`
}

func viewUser(u *store.User) userView {
	return userView{ID: u.ID, Email: u.Email, Name: u.Name, Role: u.Role, TOTPEnabled: u.TOTPEnabled, WebAuthnCount: u.WebAuthnCount, Disabled: u.Disabled, CreatedAt: u.CreatedAt}
}

func validEmail(e string) bool {
	a, err := mail.ParseAddress(e)
	return err == nil && a.Address == e && len(e) <= 254
}

// newSession creates a session and sets the cookie.
func (s *Server) newSession(w http.ResponseWriter, r *http.Request, u *store.User, mfa bool) (*store.Session, error) {
	tok, digest := auth.NewToken("ods_", 32)
	csrf, _ := auth.NewToken("", 24)
	now := time.Now()
	sess := &store.Session{ID: digest, UserID: u.ID, CSRFToken: csrf, MFAVerified: mfa, CreatedAt: state.FormatTime(now), LastSeenAt: state.FormatTime(now),
		ExpiresAt: state.FormatTime(now.Add(SessionAbsolute)), IdleExpiresAt: state.FormatTime(now.Add(SessionIdle)), SourceIP: s.clientIP(r),
		UserAgent: r.UserAgent(), ReauthAt: state.FormatTime(now)}
	if err := s.S.CreateSession(r.Context(), sess); err != nil {
		return nil, err
	}
	name, secure := s.cookieName(r)
	http.SetCookie(w, &http.Cookie{Name: name, Value: tok, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: int(SessionAbsolute.Seconds())})
	return sess, nil
}

// cookieName picks the __Host- cookie for TLS or loopback (secure context).
func (s *Server) cookieName(r *http.Request) (string, bool) {
	if r.TLS != nil {
		return cookieSecure, true
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	if host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1" {
		return cookieSecure, true
	}
	return cookiePlain, false
}

type sessionResp struct {
	User          userView `json:"user"`
	MFARequired   bool     `json:"mfa_required"`
	MFAEnrollment bool     `json:"mfa_enrollment_required"`
	CSRFToken     string   `json:"csrf_token"`
	MFAMethods    []string `json:"mfa_methods,omitempty"`
}

func (s *Server) sessionView(u *store.User, sess *store.Session) sessionResp {
	resp := sessionResp{User: viewUser(u), CSRFToken: sess.CSRFToken}
	if !sess.MFAVerified {
		if u.TOTPEnabled {
			resp.MFARequired = true
			resp.MFAMethods = append(resp.MFAMethods, "totp", "recovery")
		}
		if u.WebAuthnCount > 0 {
			resp.MFARequired = true
			resp.MFAMethods = append(resp.MFAMethods, "webauthn")
		}
		if !resp.MFARequired && s.mfaMandatory(u) {
			resp.MFAEnrollment = true
		}
	}
	return resp
}

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) error {
	n, err := s.S.CountUsers(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"needs_bootstrap": n == 0, "version": versionString(), "require_mfa": s.RequireMFA})
	return nil
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) error {
	if !s.authLimiter.allow("bootstrap:" + s.clientIP(r)) {
		return errf(429, "rate_limited", "too many attempts")
	}
	var req struct {
		Token    string `json:"token"`
		Email    string `json:"email"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	if s.BootstrapToken == "" || subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.BootstrapToken)) != 1 {
		s.audit(r, "auth.bootstrap", "user", "", "", audit.Denied, map[string]string{"reason": "invalid bootstrap token"})
		return errf(403, "forbidden", "invalid bootstrap token (see `opendeployctl admin bootstrap-token`)")
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if !validEmail(req.Email) {
		return errf(400, "bad_request", "invalid email")
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		return errf(400, "bad_request", "%v", err)
	}
	u := &store.User{Email: req.Email, Name: strings.TrimSpace(req.Name), PasswordHash: hash, Role: model.RoleOwner}
	if err := s.S.CreateUser(r.Context(), u, true); err != nil {
		return errf(409, "conflict", "the platform is already initialised")
	}
	if s.Bootstrapped != nil {
		s.Bootstrapped()
	}
	u, _ = s.S.GetUser(r.Context(), u.ID)
	sess, err := s.newSession(w, r, u, false)
	if err != nil {
		return err
	}
	s.audit(r.WithContext(withPrincipal(r, &Principal{User: u, Session: sess})), "auth.bootstrap", "user", u.ID, "", audit.Success, nil)
	writeJSON(w, 201, s.sessionView(u, sess))
	return nil
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) error {
	ip := s.clientIP(r)
	if !s.authLimiter.allow("login:" + ip) {
		return errf(429, "rate_limited", "too many login attempts; try again later")
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	u, err := s.S.GetUserByEmail(r.Context(), email)
	hash := ""
	if err == nil {
		hash = u.PasswordHash
	}
	ok := auth.VerifyPassword(hash, req.Password) // constant work even for unknown users
	fail := func(reason string) error {
		s.audit(r, "auth.login", "user", email, "", audit.Denied, map[string]string{"reason": reason})
		return errf(401, "invalid_credentials", "invalid email or password")
	}
	// A locked account answers the same whatever the password, so the lock
	// never confirms a guess.
	if err == nil && u.LockedUntil != "" && u.LockedUntil > state.Now() {
		s.audit(r, "auth.login", "user", email, "", audit.Denied, map[string]string{"reason": "locked"})
		return errf(429, "locked", "account temporarily locked after repeated failures")
	}
	if err != nil || !ok {
		if err == nil {
			_ = s.S.RecordLoginFailure(r.Context(), u.ID)
		}
		return fail("bad credentials")
	}
	if u.Disabled {
		return fail("account disabled")
	}
	needsMFA := u.TOTPEnabled || u.WebAuthnCount > 0
	if !needsMFA {
		// With a second factor, failures are reset only once it passes, so
		// guessing codes accumulates towards the lock.
		_ = s.S.ResetLoginFailures(r.Context(), u.ID)
	}
	// A session is MFA-complete only when no second factor is enrolled AND
	// none is required for the role; otherwise the user must verify (or
	// enroll) before anything but the MFA endpoints works.
	sess, err := s.newSession(w, r, u, !needsMFA && !s.mfaMandatory(u))
	if err != nil {
		return err
	}
	s.audit(r.WithContext(withPrincipal(r, &Principal{User: u, Session: sess})), "auth.login", "user", u.ID, "", audit.Success, map[string]string{"method": "password"})
	writeJSON(w, 200, s.sessionView(u, sess))
	return nil
}

func (s *Server) verifySecondFactor(r *http.Request, u *store.User, code, recovery string) (string, bool) {
	ctx := r.Context()
	if recovery != "" {
		ok, err := s.S.UseRecoveryCode(ctx, u.ID, auth.HashRecoveryCode(recovery))
		return "recovery", err == nil && ok
	}
	if !u.TOTPEnabled || len(u.TOTPSecretEnc) == 0 {
		return "totp", false
	}
	seed, err := s.Sealer.Open(u.TOTPSecretEnc, "totp:"+u.ID)
	if err != nil {
		return "totp", false
	}
	step, ok := auth.VerifyTOTP(string(seed), code, time.Now(), u.TOTPLastStep)
	if !ok {
		return "totp", false
	}
	if err := s.S.ConsumeTOTPStep(ctx, u.ID, step); err != nil {
		return "totp", false // concurrent replay
	}
	return "totp", true
}

func (s *Server) handleMFA(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	if p.Session == nil {
		return errf(400, "bad_request", "MFA applies to interactive sessions")
	}
	if !s.authLimiter.allow("mfa:" + p.User.ID) {
		return errf(429, "rate_limited", "too many attempts")
	}
	var req struct {
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	if s.lockedOut(r, p.User.ID) {
		return errf(429, "locked", "account temporarily locked after repeated failures")
	}
	method, ok := s.verifySecondFactor(r, p.User, req.Code, req.RecoveryCode)
	if !ok {
		_ = s.S.RecordLoginFailure(r.Context(), p.User.ID)
		s.audit(r, "auth.mfa", "user", p.User.ID, "", audit.Denied, map[string]string{"method": method})
		return errf(401, "invalid_code", "invalid verification code")
	}
	_ = s.S.ResetLoginFailures(r.Context(), p.User.ID)
	if err := s.S.MarkSessionMFA(r.Context(), p.Session.ID, method); err != nil {
		return err
	}
	s.audit(r, "auth.mfa", "user", p.User.ID, "", audit.Success, map[string]string{"method": method})
	p.Session.MFAVerified = true
	writeJSON(w, 200, s.sessionView(p.User, p.Session))
	return nil
}

func (s *Server) handleReauth(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	if p.Session == nil {
		return errf(400, "bad_request", "re-authentication applies to interactive sessions")
	}
	if !s.authLimiter.allow("reauth:" + p.User.ID) {
		return errf(429, "rate_limited", "too many attempts")
	}
	var req struct {
		Password     string          `json:"password"`
		Code         string          `json:"code"`
		RecoveryCode string          `json:"recovery_code"`
		WebAuthn     json.RawMessage `json:"webauthn"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	if !auth.VerifyPassword(p.User.PasswordHash, req.Password) {
		s.audit(r, "auth.reauth", "user", p.User.ID, "", audit.Denied, map[string]string{"reason": "password"})
		return errf(401, "invalid_credentials", "incorrect password")
	}
	if p.User.TOTPEnabled || p.User.WebAuthnCount > 0 {
		ok := false
		switch {
		case len(req.WebAuthn) > 0 && p.User.WebAuthnCount > 0:
			ok = s.finishWebAuthnLogin(r, p, req.WebAuthn) == nil
		case p.User.TOTPEnabled || req.RecoveryCode != "":
			_, ok = s.verifySecondFactor(r, p.User, req.Code, req.RecoveryCode)
		}
		if !ok {
			s.audit(r, "auth.reauth", "user", p.User.ID, "", audit.Denied, map[string]string{"reason": "second factor"})
			return errf(401, "invalid_code", "second factor verification failed")
		}
	}
	if err := s.S.MarkReauth(r.Context(), p.Session.ID); err != nil {
		return err
	}
	s.audit(r, "auth.reauth", "user", p.User.ID, "", audit.Success, nil)
	writeJSON(w, 200, map[string]any{"ok": true, "valid_for_seconds": int(ReauthWindow.Seconds())})
	return nil
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	if p.Session != nil {
		_ = s.S.RevokeSession(r.Context(), p.Session.ID, p.User.ID)
	}
	name, secure := s.cookieName(r)
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode})
	s.audit(r, "auth.logout", "user", p.User.ID, "", audit.Success, nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	if p.Session != nil {
		writeJSON(w, 200, s.sessionView(p.User, p.Session))
		return nil
	}
	writeJSON(w, 200, map[string]any{"user": viewUser(p.User), "token": p.Token.Name})
	return nil
}

func (s *Server) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	if p.Session == nil {
		return errf(403, "session_required", "interactive session required")
	}
	// Changing factors on an account that already has one needs that
	// factor now (not just the password) and signs out every other session:
	// otherwise a password-only session could enroll its own TOTP, or be
	// promoted to a full session while TOTP is off during re-enrollment.
	hasFactor := p.User.TOTPEnabled || p.User.WebAuthnCount > 0
	if hasFactor {
		if !p.Session.MFAVerified {
			return errf(401, "mfa_required", "multi-factor authentication required")
		}
		if err := s.requireReauth(r, auth.UsersManage); err != nil {
			return err
		}
	}
	secret := auth.NewTOTPSecret()
	enc, err := s.Sealer.Seal([]byte(secret), "totp:"+p.User.ID)
	if err != nil {
		return err
	}
	enabled := false
	if err := s.S.UpdateUser(r.Context(), p.User.ID, store.UserUpdate{TOTPSecretEnc: &enc, TOTPEnabled: &enabled}); err != nil {
		return err
	}
	if hasFactor {
		_, _ = s.S.RevokeUserSessions(r.Context(), p.User.ID, p.Session.ID)
	}
	writeJSON(w, 200, map[string]string{"secret": secret, "uri": auth.TOTPURI("OpenDeploy", p.User.Email, secret)})
	return nil
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	var req struct {
		Code string `json:"code"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	if !s.authLimiter.allow("mfa:" + p.User.ID) {
		return errf(429, "rate_limited", "too many attempts")
	}
	u, err := s.S.GetUser(r.Context(), p.User.ID)
	if err != nil {
		return err
	}
	if u.TOTPEnabled {
		return errf(409, "conflict", "TOTP is already enabled; start a new enrollment to replace it")
	}
	if u.WebAuthnCount > 0 && (p.Session == nil || !p.Session.MFAVerified) {
		return errf(401, "mfa_required", "multi-factor authentication required")
	}
	if s.lockedOut(r, u.ID) {
		return errf(429, "locked", "account temporarily locked after repeated failures")
	}
	seed, err := s.Sealer.Open(u.TOTPSecretEnc, "totp:"+u.ID)
	if err != nil || len(seed) == 0 {
		return errf(400, "bad_request", "start enrollment first")
	}
	step, ok := auth.VerifyTOTP(string(seed), req.Code, time.Now(), u.TOTPLastStep)
	if !ok {
		_ = s.S.RecordLoginFailure(r.Context(), u.ID)
		return errf(400, "invalid_code", "invalid verification code")
	}
	if err := s.S.ConsumeTOTPStep(r.Context(), u.ID, step); err != nil {
		return errf(400, "invalid_code", "invalid verification code") // concurrent replay
	}
	_ = s.S.ResetLoginFailures(r.Context(), u.ID)
	on := true
	if err := s.S.UpdateUser(r.Context(), u.ID, store.UserUpdate{TOTPEnabled: &on}); err != nil {
		return err
	}
	codes, hashes := auth.NewRecoveryCodes(10)
	if err := s.S.SetRecoveryCodes(r.Context(), u.ID, hashes); err != nil {
		return err
	}
	if p.Session != nil {
		_ = s.S.MarkSessionMFA(r.Context(), p.Session.ID, "totp")
		// Sessions opened before the factor existed were password-only.
		_, _ = s.S.RevokeUserSessions(r.Context(), u.ID, p.Session.ID)
	}
	s.audit(r, "auth.mfa_enroll", "user", u.ID, "", audit.Success, map[string]string{"method": "totp"})
	writeJSON(w, 200, map[string]any{"recovery_codes": codes})
	return nil
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	if err := s.requireReauth(r, auth.UsersManage); err != nil {
		return err
	}
	if s.mfaMandatory(p.User) && p.User.WebAuthnCount == 0 {
		return errf(409, "conflict", "your role requires MFA; enroll another factor before removing TOTP")
	}
	off := false
	empty := []byte{}
	if err := s.S.UpdateUser(r.Context(), p.User.ID, store.UserUpdate{TOTPEnabled: &off, TOTPSecretEnc: &empty}); err != nil {
		return err
	}
	// A pending pre-MFA session must not become a full one now that the
	// factor it was waiting for is gone.
	keep := ""
	if p.Session != nil {
		keep = p.Session.ID
	}
	_, _ = s.S.RevokeUserSessions(r.Context(), p.User.ID, keep)
	s.audit(r, "auth.mfa_remove", "user", p.User.ID, "", audit.Success, map[string]string{"method": "totp"})
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	ss, err := s.S.ListSessions(r.Context(), p.User.ID)
	if err != nil {
		return err
	}
	type view struct {
		ID        string `json:"id"`
		Current   bool   `json:"current"`
		CreatedAt string `json:"created_at"`
		LastSeen  string `json:"last_seen_at"`
		SourceIP  string `json:"source_ip"`
		UserAgent string `json:"user_agent"`
		MFA       bool   `json:"mfa"`
	}
	out := []view{}
	for _, x := range ss {
		out = append(out, view{ID: x.ID[:16], Current: p.Session != nil && x.ID == p.Session.ID, CreatedAt: x.CreatedAt, LastSeen: x.LastSeenAt,
			SourceIP: x.SourceIP, UserAgent: x.UserAgent, MFA: x.MFAVerified})
	}
	writeJSON(w, 200, out)
	return nil
}

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	if p.Session == nil {
		return errf(403, "session_required", "managing sessions and tokens requires an interactive session")
	}
	prefix := r.PathValue("id")
	ss, err := s.S.ListSessions(r.Context(), p.User.ID)
	if err != nil {
		return err
	}
	for _, x := range ss {
		if len(prefix) >= 16 && strings.HasPrefix(x.ID, prefix) {
			if err := s.S.RevokeSession(r.Context(), x.ID, p.User.ID); err != nil {
				return err
			}
			s.audit(r, "auth.session_revoke", "session", prefix, "", audit.Success, nil)
			writeJSON(w, 200, map[string]bool{"ok": true})
			return nil
		}
	}
	return errNotFound
}

func (s *Server) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	if p.Session == nil {
		return errf(403, "session_required", "managing sessions and tokens requires an interactive session")
	}
	keep := ""
	if p.Session != nil {
		keep = p.Session.ID
	}
	n, err := s.S.RevokeUserSessions(r.Context(), p.User.ID, keep)
	if err != nil {
		return err
	}
	s.audit(r, "auth.session_revoke", "session", "others", "", audit.Success, map[string]string{"count": itoa(int(n))})
	writeJSON(w, 200, map[string]int64{"revoked": n})
	return nil
}

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request) error {
	toks, err := s.S.ListAPITokens(r.Context(), principal(r).User.ID)
	if err != nil {
		return err
	}
	if toks == nil {
		toks = []*store.APIToken{}
	}
	writeJSON(w, 200, toks)
	return nil
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	if p.Token != nil {
		return errf(403, "session_required", "tokens cannot mint tokens")
	}
	var req struct {
		Name string `json:"name"`
		Role string `json:"role"`
		Days int    `json:"expires_in_days"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Name == "" || len(req.Name) > 64 {
		return errf(400, "bad_request", "name required (max 64)")
	}
	if req.Role == "" {
		req.Role = model.RoleDeveloper
	}
	if req.Role != model.RoleAdmin && req.Role != model.RoleDeveloper && req.Role != model.RoleViewer {
		return errf(400, "bad_request", "role must be admin, developer or viewer")
	}
	if req.Days <= 0 || req.Days > 365 {
		req.Days = 90
	}
	tok, digest := auth.NewToken("odt_", 32)
	t := &store.APIToken{UserID: p.User.ID, Name: req.Name, TokenHash: digest, RoleCap: req.Role,
		ExpiresAt: state.FormatTime(time.Now().Add(time.Duration(req.Days) * 24 * time.Hour))}
	if err := s.S.CreateAPIToken(r.Context(), t); err != nil {
		return err
	}
	s.audit(r, "auth.token_create", "api_token", t.ID, "", audit.Success, map[string]string{"role": req.Role})
	writeJSON(w, 201, map[string]any{"token": tok, "meta": t})
	return nil
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	if p.Session == nil {
		return errf(403, "session_required", "managing sessions and tokens requires an interactive session")
	}
	if err := s.S.RevokeAPIToken(r.Context(), r.PathValue("id"), p.User.ID); err != nil {
		return err
	}
	s.audit(r, "auth.token_revoke", "api_token", r.PathValue("id"), "", audit.Success, nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

// ---------------------------------------------------------------- users (owner)

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.SystemRead); err != nil {
		return err
	}
	us, err := s.S.ListUsers(r.Context())
	if err != nil {
		return err
	}
	out := make([]userView, 0, len(us))
	for _, u := range us {
		out = append(out, viewUser(u))
	}
	writeJSON(w, 200, out)
	return nil
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.UsersManage); err != nil {
		return err
	}
	var req struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if !validEmail(req.Email) || !auth.ValidRole(req.Role) {
		return errf(400, "bad_request", "valid email and role required")
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		return errf(400, "bad_request", "%v", err)
	}
	u := &store.User{Email: req.Email, Name: req.Name, Role: req.Role, PasswordHash: hash}
	if err := s.S.CreateUser(r.Context(), u, false); err != nil {
		return errf(409, "conflict", "a user with this email exists")
	}
	s.audit(r, "user.create", "user", u.ID, "", audit.Success, map[string]string{"role": req.Role})
	u, _ = s.S.GetUser(r.Context(), u.ID)
	writeJSON(w, 201, viewUser(u))
	return nil
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.UsersManage); err != nil {
		return err
	}
	id := r.PathValue("id")
	if !ids.HasPrefix(id, "usr") {
		return errNotFound
	}
	var req struct {
		Name     *string `json:"name"`
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
		Password *string `json:"password"`
		ResetMFA bool    `json:"reset_mfa"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	upd := store.UserUpdate{Name: req.Name, Disabled: req.Disabled}
	if req.Role != nil {
		if !auth.ValidRole(*req.Role) {
			return errf(400, "bad_request", "invalid role")
		}
		upd.Role = req.Role
	}
	if req.Password != nil {
		h, err := auth.HashPassword(*req.Password)
		if err != nil {
			return errf(400, "bad_request", "%v", err)
		}
		upd.PasswordHash = &h
	}
	if err := s.S.UpdateUser(r.Context(), id, upd); err != nil {
		if strings.Contains(err.Error(), "last owner") {
			return errf(409, "conflict", "%v", err)
		}
		return err
	}
	if req.ResetMFA {
		// Every factor: TOTP, security keys and unused recovery codes.
		if err := s.S.ResetMFA(r.Context(), id); err != nil {
			return err
		}
	}
	if (req.Disabled != nil && *req.Disabled) || req.Password != nil || req.ResetMFA || req.Role != nil {
		_, _ = s.S.RevokeUserSessions(r.Context(), id, "")
	}
	if (req.Disabled != nil && *req.Disabled) || req.Password != nil || req.ResetMFA {
		// Account recovery: tokens minted by whoever held the account go too.
		_, _ = s.S.RevokeUserTokens(r.Context(), id)
	}
	d := map[string]string{"user_id": id}
	if req.Role != nil {
		d["role"] = *req.Role
	}
	s.audit(r, "user.update", "user", id, "", audit.Success, d)
	u, err := s.S.GetUser(r.Context(), id)
	if err != nil {
		return err
	}
	writeJSON(w, 200, viewUser(u))
	return nil
}

func withPrincipal(r *http.Request, p *Principal) context.Context {
	return context.WithValue(r.Context(), principalKey, p)
}

func itoa(n int) string { return strconv.Itoa(n) }

func versionString() string { return daemon.Version }

// lockedOut reports whether the account is locked after repeated failures.
func (s *Server) lockedOut(r *http.Request, userID string) bool {
	u, err := s.S.GetUser(r.Context(), userID)
	return err == nil && u.LockedUntil != "" && u.LockedUntil > state.Now()
}
