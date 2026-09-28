package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
)

type User struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	PasswordHash  string `json:"-"`
	Role          string `json:"role"`
	TOTPSecretEnc []byte `json:"-"`
	TOTPEnabled   bool   `json:"totp_enabled"`
	TOTPLastStep  int64  `json:"-"`
	FailedLogins  int    `json:"-"`
	LockedUntil   string `json:"-"`
	Disabled      bool   `json:"disabled"`
	CreatedAt     string `json:"created_at"`
	WebAuthnCount int    `json:"webauthn_count"`
}

const userCols = `id,email,name,password_hash,role,totp_secret_enc,totp_enabled,totp_last_step,failed_logins,locked_until,disabled,created_at,
(SELECT COUNT(*) FROM webauthn_credentials w WHERE w.user_id=users.id)`

func scanUser(r interface{ Scan(...any) error }) (*User, error) {
	var u User
	err := r.Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.Role, &u.TOTPSecretEnc, &u.TOTPEnabled, &u.TOTPLastStep, &u.FailedLogins,
		&u.LockedUntil, &u.Disabled, &u.CreatedAt, &u.WebAuthnCount)
	if err != nil {
		return nil, notFound(err)
	}
	return &u, nil
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.DB.R().QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser inserts a user. When first is true it only succeeds if no
// user exists yet (bootstrap owner, race-free).
func (s *Store) CreateUser(ctx context.Context, u *User, first bool) error {
	if u.ID == "" {
		u.ID = ids.New("usr")
	}
	now := state.Now()
	u.CreatedAt = now
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		if first {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return ErrConflict
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO users(id,email,name,password_hash,role,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
			u.ID, u.Email, u.Name, u.PasswordHash, u.Role, now, now)
		if isUnique(err) {
			return ErrConflict
		}
		return err
	})
}

func (s *Store) GetUser(ctx context.Context, id string) (*User, error) {
	return scanUser(s.DB.R().QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id=?`, id))
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.DB.R().QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE email=?`, email))
}

func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.DB.R().QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UserUpdate holds mutable user fields.
type UserUpdate struct {
	Name          *string
	Role          *string
	PasswordHash  *string
	TOTPSecretEnc *[]byte
	TOTPEnabled   *bool
	Disabled      *bool
}

func (s *Store) UpdateUser(ctx context.Context, id string, u UserUpdate) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		set := func(col string, v any) error {
			_, err := tx.ExecContext(ctx, `UPDATE users SET `+col+`=?, updated_at=? WHERE id=?`, v, state.Now(), id)
			return err
		}
		if u.Name != nil {
			if err := set("name", *u.Name); err != nil {
				return err
			}
		}
		if u.Role != nil {
			if *u.Role != "owner" {
				// Never demote the last owner.
				var owners int
				if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='owner' AND disabled=0 AND id!=?`, id).Scan(&owners); err != nil {
					return err
				}
				var cur string
				_ = tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id=?`, id).Scan(&cur)
				if cur == "owner" && owners == 0 {
					return errors.New("cannot demote the last owner")
				}
			}
			if err := set("role", *u.Role); err != nil {
				return err
			}
		}
		if u.PasswordHash != nil {
			if err := set("password_hash", *u.PasswordHash); err != nil {
				return err
			}
		}
		if u.TOTPSecretEnc != nil {
			if err := set("totp_secret_enc", *u.TOTPSecretEnc); err != nil {
				return err
			}
			if err := set("totp_last_step", 0); err != nil {
				return err
			}
		}
		if u.TOTPEnabled != nil {
			if err := set("totp_enabled", b2i(*u.TOTPEnabled)); err != nil {
				return err
			}
		}
		if u.Disabled != nil {
			if *u.Disabled {
				var owners int
				_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='owner' AND disabled=0 AND id!=?`, id).Scan(&owners)
				var cur string
				_ = tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id=?`, id).Scan(&cur)
				if cur == "owner" && owners == 0 {
					return errors.New("cannot disable the last owner")
				}
			}
			if err := set("disabled", b2i(*u.Disabled)); err != nil {
				return err
			}
		}
		return nil
	})
}

// RecordLoginFailure increments failures and applies exponential lockout.
func (s *Store) RecordLoginFailure(ctx context.Context, id string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT failed_logins FROM users WHERE id=?`, id).Scan(&n); err != nil {
			return notFound(err)
		}
		n++
		locked := ""
		if n >= 5 {
			d := time.Duration(1<<uint(min(n-5, 10))) * time.Minute
			locked = state.FormatTime(time.Now().Add(d))
		}
		_, err := tx.ExecContext(ctx, `UPDATE users SET failed_logins=?, locked_until=? WHERE id=?`, n, locked, id)
		return err
	})
}

func (s *Store) ResetLoginFailures(ctx context.Context, id string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE users SET failed_logins=0, locked_until='' WHERE id=?`, id)
		return err
	})
}

// ConsumeTOTPStep records the last accepted TOTP step (replay protection).
func (s *Store) ConsumeTOTPStep(ctx context.Context, id string, step int64) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET totp_last_step=? WHERE id=? AND totp_last_step<?`, step, id, step)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrConflict
		}
		return nil
	})
}

// Recovery codes

func (s *Store) SetRecoveryCodes(ctx context.Context, userID string, hashes []string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id=?`, userID); err != nil {
			return err
		}
		for _, h := range hashes {
			if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(user_id,code_hash) VALUES(?,?)`, userID, h); err != nil {
				return err
			}
		}
		return nil
	})
}

// UseRecoveryCode consumes a code; returns false when unknown/used.
func (s *Store) UseRecoveryCode(ctx context.Context, userID, hash string) (bool, error) {
	ok := false
	err := s.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at=''`, state.Now(), userID, hash)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		ok = n == 1
		return nil
	})
	return ok, err
}

// Sessions

type Session struct {
	ID            string `json:"id"`
	UserID        string `json:"user_id"`
	CSRFToken     string `json:"-"`
	MFAVerified   bool   `json:"mfa_verified"`
	MFAMethod     string `json:"mfa_method"`
	ReauthAt      string `json:"reauth_at"`
	CreatedAt     string `json:"created_at"`
	LastSeenAt    string `json:"last_seen_at"`
	ExpiresAt     string `json:"expires_at"`
	IdleExpiresAt string `json:"idle_expires_at"`
	SourceIP      string `json:"source_ip"`
	UserAgent     string `json:"user_agent"`
	RevokedAt     string `json:"revoked_at,omitempty"`
}

const sessCols = `id,user_id,csrf_token,mfa_verified,mfa_method,reauth_at,created_at,last_seen_at,expires_at,idle_expires_at,source_ip,user_agent,revoked_at`

func scanSession(r interface{ Scan(...any) error }) (*Session, error) {
	var x Session
	err := r.Scan(&x.ID, &x.UserID, &x.CSRFToken, &x.MFAVerified, &x.MFAMethod, &x.ReauthAt, &x.CreatedAt, &x.LastSeenAt, &x.ExpiresAt,
		&x.IdleExpiresAt, &x.SourceIP, &x.UserAgent, &x.RevokedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &x, nil
}

func (s *Store) CreateSession(ctx context.Context, x *Session) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sessions(`+sessCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			x.ID, x.UserID, x.CSRFToken, b2i(x.MFAVerified), x.MFAMethod, x.ReauthAt, x.CreatedAt, x.LastSeenAt, x.ExpiresAt, x.IdleExpiresAt,
			truncate(x.SourceIP, 64), truncate(x.UserAgent, 256), "")
		return err
	})
}

func (s *Store) GetSession(ctx context.Context, id string) (*Session, error) {
	return scanSession(s.DB.R().QueryRowContext(ctx, `SELECT `+sessCols+` FROM sessions WHERE id=?`, id))
}

// TouchSession extends the idle expiry (bounded by absolute expiry).
func (s *Store) TouchSession(ctx context.Context, id string, idle time.Duration) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		now := time.Now()
		_, err := tx.ExecContext(ctx, `UPDATE sessions SET last_seen_at=?, idle_expires_at=MIN(expires_at, ?) WHERE id=? AND revoked_at=''`,
			state.FormatTime(now), state.FormatTime(now.Add(idle)), id)
		return err
	})
}

func (s *Store) MarkSessionMFA(ctx context.Context, id, method string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		now := state.Now()
		_, err := tx.ExecContext(ctx, `UPDATE sessions SET mfa_verified=1, mfa_method=?, reauth_at=? WHERE id=?`, method, now, id)
		return err
	})
}

func (s *Store) MarkReauth(ctx context.Context, id string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE sessions SET reauth_at=? WHERE id=?`, state.Now(), id)
		return err
	})
}

func (s *Store) RevokeSession(ctx context.Context, id, userID string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		q := `UPDATE sessions SET revoked_at=? WHERE id=? AND revoked_at=''`
		args := []any{state.Now(), id}
		if userID != "" {
			q += ` AND user_id=?`
			args = append(args, userID)
		}
		res, err := tx.ExecContext(ctx, q, args...)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// RevokeUserSessions revokes all sessions of a user except keepID.
func (s *Store) RevokeUserSessions(ctx context.Context, userID, keepID string) (int64, error) {
	var n int64
	err := s.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=? WHERE user_id=? AND id!=? AND revoked_at=''`, state.Now(), userID, keepID)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	return n, err
}

func (s *Store) ListSessions(ctx context.Context, userID string) ([]*Session, error) {
	rows, err := s.DB.R().QueryContext(ctx, `SELECT `+sessCols+` FROM sessions WHERE user_id=? AND revoked_at='' AND expires_at>? ORDER BY last_seen_at DESC`, userID, state.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		x, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// PurgeSessions removes long-expired sessions.
func (s *Store) PurgeSessions(ctx context.Context) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at<?`, state.FormatTime(time.Now().Add(-7*24*time.Hour)))
		return err
	})
}

// API tokens

type APIToken struct {
	ID         string `json:"id"`
	UserID     string `json:"user_id"`
	Name       string `json:"name"`
	TokenHash  string `json:"-"`
	RoleCap    string `json:"role_cap"`
	CreatedAt  string `json:"created_at"`
	ExpiresAt  string `json:"expires_at"`
	LastUsedAt string `json:"last_used_at"`
	RevokedAt  string `json:"revoked_at,omitempty"`
}

const tokCols = `id,user_id,name,token_hash,role_cap,created_at,expires_at,last_used_at,revoked_at`

func scanTok(r interface{ Scan(...any) error }) (*APIToken, error) {
	var t APIToken
	if err := r.Scan(&t.ID, &t.UserID, &t.Name, &t.TokenHash, &t.RoleCap, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
		return nil, notFound(err)
	}
	return &t, nil
}

func (s *Store) CreateAPIToken(ctx context.Context, t *APIToken) error {
	if t.ID == "" {
		t.ID = ids.New("tok")
	}
	t.CreatedAt = state.Now()
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO api_tokens(id,user_id,name,token_hash,role_cap,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`,
			t.ID, t.UserID, t.Name, t.TokenHash, t.RoleCap, t.CreatedAt, t.ExpiresAt)
		return err
	})
}

func (s *Store) GetAPITokenByHash(ctx context.Context, h string) (*APIToken, error) {
	return scanTok(s.DB.R().QueryRowContext(ctx, `SELECT `+tokCols+` FROM api_tokens WHERE token_hash=?`, h))
}

func (s *Store) ListAPITokens(ctx context.Context, userID string) ([]*APIToken, error) {
	rows, err := s.DB.R().QueryContext(ctx, `SELECT `+tokCols+` FROM api_tokens WHERE user_id=? AND revoked_at='' ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*APIToken
	for rows.Next() {
		t, err := scanTok(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAPIToken(ctx context.Context, id, userID string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE api_tokens SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at=''`, state.Now(), id, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func (s *Store) TouchAPIToken(ctx context.Context, id string) {
	_ = s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE api_tokens SET last_used_at=? WHERE id=?`, state.Now(), id)
		return err
	})
}

// WebAuthn credentials

type WebAuthnCred struct {
	ID           string `json:"id"`
	UserID       string `json:"user_id"`
	Name         string `json:"name"`
	CredentialID []byte `json:"-"`
	Data         []byte `json:"-"`
	CreatedAt    string `json:"created_at"`
	LastUsedAt   string `json:"last_used_at"`
}

func (s *Store) AddWebAuthnCred(ctx context.Context, c *WebAuthnCred) error {
	if c.ID == "" {
		c.ID = ids.New("wac")
	}
	c.CreatedAt = state.Now()
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO webauthn_credentials(id,user_id,name,credential_id,data,created_at) VALUES(?,?,?,?,?,?)`,
			c.ID, c.UserID, c.Name, c.CredentialID, c.Data, c.CreatedAt)
		if isUnique(err) {
			return ErrConflict
		}
		return err
	})
}

func (s *Store) WebAuthnCreds(ctx context.Context, userID string) ([]*WebAuthnCred, error) {
	rows, err := s.DB.R().QueryContext(ctx, `SELECT id,user_id,name,credential_id,data,created_at,last_used_at FROM webauthn_credentials WHERE user_id=? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WebAuthnCred
	for rows.Next() {
		var c WebAuthnCred
		if err := rows.Scan(&c.ID, &c.UserID, &c.Name, &c.CredentialID, &c.Data, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

func (s *Store) UpdateWebAuthnCred(ctx context.Context, id string, data []byte) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE webauthn_credentials SET data=?, last_used_at=? WHERE id=?`, data, state.Now(), id)
		return err
	})
}

func (s *Store) DeleteWebAuthnCred(ctx context.Context, id, userID string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE id=? AND user_id=?`, id, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// Git connections

type GitConnection struct {
	ID             string `json:"id"`
	Provider       string `json:"provider"`
	AppID          int64  `json:"app_id"`
	InstallationID int64  `json:"installation_id"`
	AccountLogin   string `json:"account_login"`
	AccountType    string `json:"account_type"`
	Status         string `json:"status"`
	CreatedAt      string `json:"created_at"`
}

func (s *Store) UpsertGitConnection(ctx context.Context, g *GitConnection) error {
	now := state.Now()
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		var id string
		err := tx.QueryRowContext(ctx, `SELECT id FROM git_connections WHERE provider=? AND installation_id=?`, g.Provider, g.InstallationID).Scan(&id)
		if err == nil {
			g.ID = id
			_, err = tx.ExecContext(ctx, `UPDATE git_connections SET app_id=?, account_login=?, account_type=?, status=?, updated_at=? WHERE id=?`,
				g.AppID, g.AccountLogin, g.AccountType, g.Status, now, id)
			return err
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if g.ID == "" {
			g.ID = ids.New("gcn")
		}
		g.CreatedAt = now
		_, err = tx.ExecContext(ctx, `INSERT INTO git_connections(id,provider,app_id,installation_id,account_login,account_type,status,created_at,updated_at)
			VALUES(?,?,?,?,?,?,?,?,?)`, g.ID, g.Provider, g.AppID, g.InstallationID, g.AccountLogin, g.AccountType, g.Status, now, now)
		return err
	})
}

func (s *Store) GetGitConnection(ctx context.Context, id string) (*GitConnection, error) {
	var g GitConnection
	err := s.DB.R().QueryRowContext(ctx, `SELECT id,provider,app_id,installation_id,account_login,account_type,status,created_at FROM git_connections WHERE id=?`, id).
		Scan(&g.ID, &g.Provider, &g.AppID, &g.InstallationID, &g.AccountLogin, &g.AccountType, &g.Status, &g.CreatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &g, nil
}

func (s *Store) GitConnectionByInstallation(ctx context.Context, inst int64) (*GitConnection, error) {
	var g GitConnection
	err := s.DB.R().QueryRowContext(ctx, `SELECT id,provider,app_id,installation_id,account_login,account_type,status,created_at FROM git_connections WHERE provider='github' AND installation_id=?`, inst).
		Scan(&g.ID, &g.Provider, &g.AppID, &g.InstallationID, &g.AccountLogin, &g.AccountType, &g.Status, &g.CreatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &g, nil
}

func (s *Store) ListGitConnections(ctx context.Context) ([]GitConnection, error) {
	rows, err := s.DB.R().QueryContext(ctx, `SELECT id,provider,app_id,installation_id,account_login,account_type,status,created_at FROM git_connections ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GitConnection
	for rows.Next() {
		var g GitConnection
		if err := rows.Scan(&g.ID, &g.Provider, &g.AppID, &g.InstallationID, &g.AccountLogin, &g.AccountType, &g.Status, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) SetGitConnectionStatus(ctx context.Context, inst int64, status string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE git_connections SET status=?, updated_at=? WHERE provider='github' AND installation_id=?`, status, state.Now(), inst)
		return err
	})
}
