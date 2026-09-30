package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/auth"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// WebAuthn (security keys / passkeys as a second factor, PRD §17).

const webauthnTimeout = 5 * time.Minute

type waPending struct {
	user string
	data webauthn.SessionData
	exp  time.Time
}

// waUser adapts a store user to the webauthn.User interface.
type waUser struct {
	u     *store.User
	creds []webauthn.Credential
	ids   map[string]string // credential id -> row id
}

func (w *waUser) WebAuthnID() []byte                         { return []byte(w.u.ID) }
func (w *waUser) WebAuthnName() string                       { return w.u.Email }
func (w *waUser) WebAuthnDisplayName() string                { return firstNonEmpty(w.u.Name, w.u.Email) }
func (w *waUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

func (s *Server) webauthnRoutes(pre, a func(handler) http.HandlerFunc) {
	m := s.mux
	m.HandleFunc("POST /api/v2/auth/webauthn/register/begin", pre(s.handleWARegisterBegin))
	m.HandleFunc("POST /api/v2/auth/webauthn/register/finish", pre(s.handleWARegisterFinish))
	m.HandleFunc("POST /api/v2/auth/webauthn/login/begin", pre(s.handleWALoginBegin))
	m.HandleFunc("POST /api/v2/auth/webauthn/login/finish", pre(s.handleWALoginFinish))
	m.HandleFunc("GET /api/v2/auth/webauthn/credentials", a(s.handleWACredentials))
	m.HandleFunc("DELETE /api/v2/auth/webauthn/credentials/{id}", a(s.handleWADelete))
}

// relyingParty derives the WebAuthn RP from the configured public URL, or
// (loopback/dev) from the request's own origin.
func (s *Server) relyingParty(r *http.Request) (*webauthn.WebAuthn, error) {
	origin := ""
	if pu := s.P.Node.API.PublicURL; pu != "" {
		origin = strings.TrimSuffix(pu, "/")
	} else {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		origin = scheme + "://" + r.Host
	}
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return nil, errf(500, "config", "api.public_url is invalid")
	}
	rpID := u.Hostname()
	if net.ParseIP(rpID) != nil {
		return nil, errf(400, "webauthn_unavailable", "security keys need a hostname: open the dashboard via its DNS name or localhost, or set api.public_url")
	}
	return webauthn.New(&webauthn.Config{RPID: rpID, RPDisplayName: "OpenDeploy", RPOrigins: []string{u.Scheme + "://" + u.Host},
		AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.VerificationPreferred},
		Timeouts: webauthn.TimeoutsConfig{Login: webauthn.TimeoutConfig{Enforce: true, Timeout: webauthnTimeout},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: webauthnTimeout}}})
}

func (s *Server) loadWAUser(r *http.Request, u *store.User) (*waUser, error) {
	rows, err := s.S.WebAuthnCreds(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	w := &waUser{u: u, ids: map[string]string{}}
	for _, row := range rows {
		plain, err := s.Sealer.Open(row.Data, "webauthn:"+u.ID)
		if err != nil {
			continue
		}
		var c webauthn.Credential
		if json.Unmarshal(plain, &c) != nil {
			continue
		}
		w.creds = append(w.creds, c)
		w.ids[string(c.ID)] = row.ID
	}
	return w, nil
}

func waKey(purpose string, p *Principal) string { return "wa:" + purpose + ":" + p.Session.ID }

func (s *Server) takePending(purpose string, p *Principal) (*waPending, error) {
	v, ok := s.webauthnState.LoadAndDelete(waKey(purpose, p))
	if !ok {
		return nil, errf(400, "bad_request", "no security-key ceremony in progress; start again")
	}
	pd := v.(waPending)
	if pd.user != p.User.ID || time.Now().After(pd.exp) {
		return nil, errf(400, "bad_request", "security-key ceremony expired; start again")
	}
	return &pd, nil
}

func (s *Server) handleWARegisterBegin(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	if p.Session == nil {
		return errf(403, "session_required", "interactive session required")
	}
	hasMFA := p.User.TOTPEnabled || p.User.WebAuthnCount > 0
	if hasMFA {
		// Pre-MFA sessions can never add factors; adding one to an already
		// protected account needs fresh re-authentication.
		if !p.Session.MFAVerified {
			return errf(401, "mfa_required", "verify your existing second factor first")
		}
		if err := s.requireReauth(r, auth.UsersManage); err != nil {
			return err
		}
	}
	rp, err := s.relyingParty(r)
	if err != nil {
		return err
	}
	wu, err := s.loadWAUser(r, p.User)
	if err != nil {
		return err
	}
	var excl []protocol.CredentialDescriptor
	for _, c := range wu.creds {
		excl = append(excl, c.Descriptor())
	}
	opts, sd, err := rp.BeginRegistration(wu, webauthn.WithExclusions(excl),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementPreferred, UserVerification: protocol.VerificationPreferred}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation))
	if err != nil {
		return err
	}
	s.webauthnState.Store(waKey("register", p), waPending{user: p.User.ID, data: *sd, exp: time.Now().Add(webauthnTimeout)})
	writeJSON(w, 200, opts)
	return nil
}

func (s *Server) handleWARegisterFinish(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	if p.Session == nil {
		return errf(403, "session_required", "interactive session required")
	}
	var req struct {
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	pd, err := s.takePending("register", p)
	if err != nil {
		return err
	}
	if (p.User.TOTPEnabled || p.User.WebAuthnCount > 0) && !p.Session.MFAVerified {
		return errf(401, "mfa_required", "verify your existing second factor first")
	}
	rp, err := s.relyingParty(r)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(req.Credential))
	if err != nil {
		return errf(400, "bad_request", "invalid security-key response")
	}
	wu, err := s.loadWAUser(r, p.User)
	if err != nil {
		return err
	}
	cred, err := rp.CreateCredential(wu, pd.data, parsed)
	if err != nil {
		s.audit(r, "auth.mfa_enroll", "user", p.User.ID, "", audit.Denied, map[string]string{"method": "webauthn", "reason": truncateStr(err.Error(), 200)})
		return errf(400, "webauthn_failed", "security-key registration failed")
	}
	plain, _ := json.Marshal(cred)
	sealed, err := s.Sealer.Seal(plain, "webauthn:"+p.User.ID)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Security key"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	firstFactor := !p.User.TOTPEnabled && p.User.WebAuthnCount == 0
	row := &store.WebAuthnCred{UserID: p.User.ID, Name: name, CredentialID: cred.ID, Data: sealed}
	if err := s.S.AddWebAuthnCred(r.Context(), row); err != nil {
		return err
	}
	_ = s.S.MarkSessionMFA(r.Context(), p.Session.ID, "webauthn")
	resp := map[string]any{"id": row.ID, "name": row.Name}
	if firstFactor {
		codes, hashes := auth.NewRecoveryCodes(10)
		if err := s.S.SetRecoveryCodes(r.Context(), p.User.ID, hashes); err != nil {
			return err
		}
		resp["recovery_codes"] = codes
	}
	s.audit(r, "auth.mfa_enroll", "user", p.User.ID, "", audit.Success, map[string]string{"method": "webauthn"})
	writeJSON(w, 200, resp)
	return nil
}

func (s *Server) handleWALoginBegin(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	if p.Session == nil {
		return errf(403, "session_required", "interactive session required")
	}
	if p.User.WebAuthnCount == 0 {
		return errf(400, "bad_request", "no security keys registered")
	}
	rp, err := s.relyingParty(r)
	if err != nil {
		return err
	}
	wu, err := s.loadWAUser(r, p.User)
	if err != nil {
		return err
	}
	opts, sd, err := rp.BeginLogin(wu)
	if err != nil {
		return err
	}
	s.webauthnState.Store(waKey("login", p), waPending{user: p.User.ID, data: *sd, exp: time.Now().Add(webauthnTimeout)})
	writeJSON(w, 200, opts)
	return nil
}

// finishWebAuthnLogin validates an assertion against the pending login
// ceremony of this session (MFA step or re-authentication).
func (s *Server) finishWebAuthnLogin(r *http.Request, p *Principal, body []byte) error {
	pd, err := s.takePending("login", p)
	if err != nil {
		return err
	}
	rp, err := s.relyingParty(r)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
	if err != nil {
		return err
	}
	wu, err := s.loadWAUser(r, p.User)
	if err != nil {
		return err
	}
	cred, err := rp.ValidateLogin(wu, pd.data, parsed)
	if err != nil {
		return err
	}
	if cred.Authenticator.CloneWarning {
		return errors.New("authenticator signature counter went backwards (possible cloned key)")
	}
	rowID, ok := wu.ids[string(cred.ID)]
	if !ok {
		return errors.New("unknown credential")
	}
	plain, _ := json.Marshal(cred)
	if sealed, err := s.Sealer.Seal(plain, "webauthn:"+p.User.ID); err == nil {
		_ = s.S.UpdateWebAuthnCred(r.Context(), rowID, sealed)
	}
	return nil
}

func (s *Server) handleWALoginFinish(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	if p.Session == nil {
		return errf(403, "session_required", "interactive session required")
	}
	if !s.authLimiter.allow("mfa:" + p.User.ID) {
		return errf(429, "rate_limited", "too many attempts")
	}
	body, err := readBody(r, 64<<10)
	if err != nil {
		return err
	}
	if err := s.finishWebAuthnLogin(r, p, body); err != nil {
		_ = s.S.RecordLoginFailure(r.Context(), p.User.ID)
		s.audit(r, "auth.mfa", "user", p.User.ID, "", audit.Denied, map[string]string{"method": "webauthn", "reason": truncateStr(err.Error(), 200)})
		return errf(401, "webauthn_failed", "security-key verification failed")
	}
	if err := s.S.MarkSessionMFA(r.Context(), p.Session.ID, "webauthn"); err != nil {
		return err
	}
	p.Session.MFAVerified = true
	s.audit(r, "auth.mfa", "user", p.User.ID, "", audit.Success, map[string]string{"method": "webauthn"})
	writeJSON(w, 200, s.sessionView(p.User, p.Session))
	return nil
}

func (s *Server) handleWACredentials(w http.ResponseWriter, r *http.Request) error {
	rows, err := s.S.WebAuthnCreds(r.Context(), principal(r).User.ID)
	if err != nil {
		return err
	}
	if rows == nil {
		rows = []*store.WebAuthnCred{}
	}
	writeJSON(w, 200, rows)
	return nil
}

func (s *Server) handleWADelete(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	if err := s.requireReauth(r, auth.UsersManage); err != nil {
		return err
	}
	if s.mfaMandatory(p.User) && !p.User.TOTPEnabled && p.User.WebAuthnCount <= 1 {
		return errf(409, "conflict", "your role requires MFA; enroll another factor before removing your last security key")
	}
	if err := s.S.DeleteWebAuthnCred(r.Context(), r.PathValue("id"), p.User.ID); err != nil {
		return err
	}
	s.audit(r, "auth.mfa_remove", "user", p.User.ID, "", audit.Success, map[string]string{"method": "webauthn"})
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func readBody(r *http.Request, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, errf(400, "bad_request", "could not read body")
	}
	if int64(len(b)) > limit {
		return nil, errf(413, "too_large", "request body too large")
	}
	return b, nil
}
