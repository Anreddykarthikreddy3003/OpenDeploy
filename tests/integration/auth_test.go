package integration

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/allinone"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/auth"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/runtime"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/services"
)

type apiErr struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ST-06 / Q21-Q26, Q54-Q55: MFA enforcement (WebAuthn + TOTP), replay and
// clone resistance, re-authentication, session revocation and token caps.
func TestAuthMFAAndSessions(t *testing.T) {
	ctx := context.Background()
	s, err := allinone.Start(ctx, allinone.Options{DataDir: t.TempDir(), Backend: runtime.NewFake(), Executor: &ociExec{}, Fetch: fixtureFetch, RequireMFA: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, port, _ := net.SplitHostPort(s.APIAddr)
	origin := "http://localhost:" + port // WebAuthn needs a hostname, not an IP
	c := newClient(t, origin)

	tok, _ := os.ReadFile(services.BootstrapTokenPath(s.Node))
	var sess struct {
		CSRFToken     string `json:"csrf_token"`
		MFAEnrollment bool   `json:"mfa_enrollment_required"`
		MFARequired   bool   `json:"mfa_required"`
		MFAMethods    []string
		User          struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if code := c.do("POST", "/api/v2/auth/bootstrap", map[string]string{"token": strings.TrimSpace(string(tok)), "email": "o@example.com",
		"password": "correct horse battery"}, &sess); code != 201 || !sess.MFAEnrollment {
		t.Fatalf("bootstrap %d %+v", code, sess)
	}
	if _, err := os.Stat(services.BootstrapTokenPath(s.Node)); !os.IsNotExist(err) {
		t.Fatalf("spent bootstrap token file still present: %v", err)
	}
	c.csrf = sess.CSRFToken
	ownerID := sess.User.ID
	var e apiErr
	if code := c.do("GET", "/api/v2/projects", nil, &e); code != 403 || e.Code != "mfa_enrollment_required" {
		t.Fatalf("owner without MFA reached the API: %d %+v", code, e)
	}

	// ---- enroll a security key
	key := newSoftKey(t, origin, "localhost")
	var opts map[string]any
	if code := c.do("POST", "/api/v2/auth/webauthn/register/begin", map[string]any{}, &opts); code != 200 {
		t.Fatalf("register begin %d %v", code, opts)
	}
	var reg struct {
		ID            string   `json:"id"`
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if code := c.do("POST", "/api/v2/auth/webauthn/register/finish", map[string]any{"name": "yubikey", "credential": key.create(opts)}, &reg); code != 200 ||
		len(reg.RecoveryCodes) != 10 {
		t.Fatalf("register finish %d %+v", code, reg)
	}
	if code := c.do("GET", "/api/v2/projects", nil, nil); code != 200 {
		t.Fatalf("after enrollment: %d", code)
	}
	// A registration ceremony cannot be finished twice.
	if code := c.do("POST", "/api/v2/auth/webauthn/register/finish", map[string]any{"credential": key.create(opts)}, nil); code != 400 {
		t.Fatalf("registration replay: %d", code)
	}

	// ---- login requires the key; assertions cannot be replayed
	c.do("POST", "/api/v2/auth/logout", nil, nil)
	c2 := newClient(t, origin)
	if code := c2.do("POST", "/api/v2/auth/login", map[string]string{"email": "o@example.com", "password": "correct horse battery"}, &sess); code != 200 ||
		!sess.MFARequired {
		t.Fatalf("login %d %+v", code, sess)
	}
	c2.csrf = sess.CSRFToken
	if code := c2.do("GET", "/api/v2/projects", nil, &e); code != 401 || e.Code != "mfa_required" {
		t.Fatalf("pre-MFA session reached the API: %d %+v", code, e)
	}
	// A pre-MFA session cannot add a factor.
	if code := c2.do("POST", "/api/v2/auth/webauthn/register/begin", map[string]any{}, &e); code != 401 {
		t.Fatalf("pre-MFA session started a registration: %d", code)
	}
	c2.do("POST", "/api/v2/auth/webauthn/login/begin", map[string]any{}, &opts)
	assertion := key.get(opts, ownerID, 1)
	if code := c2.do("POST", "/api/v2/auth/webauthn/login/finish", json.RawMessage(assertion), nil); code != 200 {
		t.Fatalf("webauthn login %d", code)
	}
	if code := c2.do("POST", "/api/v2/auth/webauthn/login/finish", json.RawMessage(assertion), nil); code == 200 {
		t.Fatal("assertion replay accepted")
	}
	if code := c2.do("GET", "/api/v2/projects", nil, nil); code != 200 {
		t.Fatalf("after MFA: %d", code)
	}

	// ---- re-authentication needs the second factor too
	if code := c2.do("POST", "/api/v2/auth/reauth", map[string]string{"password": "correct horse battery"}, nil); code != 401 {
		t.Fatalf("password-only reauth accepted for a key-protected account: %d", code)
	}
	c2.do("POST", "/api/v2/auth/webauthn/login/begin", map[string]any{}, &opts)
	if code := c2.do("POST", "/api/v2/auth/reauth", map[string]any{"password": "correct horse battery", "webauthn": key.get(opts, ownerID, 1)}, nil); code != 200 {
		t.Fatalf("reauth with key: %d", code)
	}
	// A cloned key (counter going backwards) is refused.
	c2.do("POST", "/api/v2/auth/webauthn/login/begin", map[string]any{}, &opts)
	if code := c2.do("POST", "/api/v2/auth/reauth", map[string]any{"password": "correct horse battery", "webauthn": key.get(opts, ownerID, -2)}, nil); code != 401 {
		t.Fatalf("cloned authenticator accepted: %d", code)
	}
	// Recovery codes work once.
	c3 := newClient(t, origin)
	c3.do("POST", "/api/v2/auth/login", map[string]string{"email": "o@example.com", "password": "correct horse battery"}, &sess)
	c3.csrf = sess.CSRFToken
	if code := c3.do("POST", "/api/v2/auth/mfa", map[string]string{"recovery_code": reg.RecoveryCodes[0]}, nil); code != 200 {
		t.Fatalf("recovery code: %d", code)
	}
	c4 := newClient(t, origin)
	c4.do("POST", "/api/v2/auth/login", map[string]string{"email": "o@example.com", "password": "correct horse battery"}, &sess)
	c4.csrf = sess.CSRFToken
	if code := c4.do("POST", "/api/v2/auth/mfa", map[string]string{"recovery_code": reg.RecoveryCodes[0]}, nil); code != 401 {
		t.Fatalf("recovery code reused: %d", code)
	}

	// ---- session revocation: "sign out other sessions" kills c3
	if code := c2.do("POST", "/api/v2/auth/sessions/revoke-others", nil, nil); code != 200 {
		t.Fatalf("revoke others: %d", code)
	}
	if code := c3.do("GET", "/api/v2/projects", nil, nil); code != 401 {
		t.Fatalf("revoked session still valid: %d", code)
	}

	// ---- an admin created later must enroll MFA before using the API
	if code := c2.do("POST", "/api/v2/users", map[string]string{"email": "a@example.com", "password": "admin password 123", "role": "admin"}, nil); code != 201 {
		t.Fatalf("create admin: %d", code)
	}
	ad := newClient(t, origin)
	ad.do("POST", "/api/v2/auth/login", map[string]string{"email": "a@example.com", "password": "admin password 123"}, &sess)
	ad.csrf = sess.CSRFToken
	if !sess.MFAEnrollment {
		t.Fatalf("admin login did not demand MFA enrollment: %+v", sess)
	}
	if code := ad.do("GET", "/api/v2/projects", nil, &e); code != 403 || e.Code != "mfa_enrollment_required" {
		t.Fatalf("admin without MFA reached the API: %d %+v", code, e)
	}
	var totp struct {
		Secret string `json:"secret"`
	}
	ad.do("POST", "/api/v2/auth/totp/enroll", nil, &totp)
	code0, _ := auth.TOTPCode(totp.Secret, time.Now())
	if code := ad.do("POST", "/api/v2/auth/totp/confirm", map[string]string{"code": code0}, nil); code != 200 {
		t.Fatalf("totp confirm: %d", code)
	}
	if code := ad.do("GET", "/api/v2/projects", nil, nil); code != 200 {
		t.Fatalf("admin after TOTP: %d", code)
	}
	// The same TOTP code cannot be replayed for another login.
	ad2 := newClient(t, origin)
	ad2.do("POST", "/api/v2/auth/login", map[string]string{"email": "a@example.com", "password": "admin password 123"}, &sess)
	ad2.csrf = sess.CSRFToken
	if code := ad2.do("POST", "/api/v2/auth/mfa", map[string]string{"code": code0}, nil); code != 401 {
		t.Fatalf("TOTP replay accepted: %d", code)
	}

	// ---- API tokens are capped and cannot perform re-auth actions
	var created struct {
		Token string `json:"token"`
	}
	if code := c2.do("POST", "/api/v2/auth/tokens", map[string]any{"name": "ci", "role": "viewer"}, &created); code != 201 || !strings.HasPrefix(created.Token, "odt_") {
		t.Fatalf("token create: %d %+v", code, created)
	}
	tc := newClient(t, origin)
	tc.hc.Transport = bearer{created.Token}
	if code := tc.do("GET", "/api/v2/projects", nil, nil); code != 200 {
		t.Fatalf("token read: %d", code)
	}
	if code := tc.do("POST", "/api/v2/users", map[string]string{"email": "x@example.com", "password": "some password 123", "role": "owner"}, nil); code != 403 {
		t.Fatalf("viewer-capped token created a user: %d", code)
	}

	// ---- MFA removal keeps the mandatory factor
	var creds []struct {
		ID string `json:"id"`
	}
	c2.do("GET", "/api/v2/auth/webauthn/credentials", nil, &creds)
	if len(creds) != 1 {
		t.Fatalf("credentials: %+v", creds)
	}
	c2.do("POST", "/api/v2/auth/webauthn/login/begin", map[string]any{}, &opts)
	c2.do("POST", "/api/v2/auth/reauth", map[string]any{"password": "correct horse battery", "webauthn": key.get(opts, ownerID, 1)}, nil)
	if code := c2.do("DELETE", "/api/v2/auth/webauthn/credentials/"+creds[0].ID, nil, nil); code != 409 {
		t.Fatalf("owner removed their only factor: %d", code)
	}
}

// bearer authenticates requests with an API token (no cookies/CSRF).
type bearer struct{ tok string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}
