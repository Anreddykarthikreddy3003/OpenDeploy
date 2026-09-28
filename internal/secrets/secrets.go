// Package secrets implements secretd, the separate high-sensitivity secret
// broker (PRD §13, SC-06, Q9-Q12, Q19, Q65).
//
//   - Envelope encryption: every secret version has its own random DEK;
//     values are sealed with AES-256-GCM using an AAD that binds the
//     ciphertext to its identity (scope, project, environment, name,
//     version), so rows cannot be swapped between projects or names.
//   - DEKs are wrapped by the instance KEK (key ring on disk readable only
//     by the secretd user; KeyProvider allows TPM/KMS later).
//   - List APIs return metadata only. Reveal is a separate operation that
//     the caller must authorise (RBAC + recent re-auth) and that secretd
//     audits itself.
//   - Resolution enforces scope: previews never inherit production or
//     project secrets unless a project secret is explicitly marked for
//     previews via the dedicated "preview" scope; untrusted builds receive
//     nothing.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Scopes.
const (
	ScopeInstance    = "instance"
	ScopeProject     = "project"
	ScopePreview     = "preview" // project-level secrets applied to preview environments only
	ScopeEnvironment = "environment"
)

// Limits.
const (
	MaxValueBytes = 64 << 10
	MaxNameLen    = 128
)

var nameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)

// Errors.
var (
	ErrNotFound = errors.New("secret not found")
	ErrInvalid  = errors.New("invalid secret request")
	ErrDenied   = errors.New("secret access denied")
)

// KeyRing holds KEKs. The current key wraps new DEKs; older keys are kept
// until all DEKs are rewrapped.
type KeyRing struct {
	mu      sync.RWMutex
	path    string
	Current string            `json:"current"`
	Keys    map[string][]byte `json:"keys"`
}

// LoadOrCreateKeyRing reads the key ring file, creating a new KEK if absent.
func LoadOrCreateKeyRing(path string) (*KeyRing, error) {
	kr := &KeyRing{path: path, Keys: map[string][]byte{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if _, err := kr.newKey(); err != nil {
			return nil, err
		}
		return kr, kr.save()
	}
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(path)
	if err == nil && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must be mode 0600", path)
	}
	if err := json.Unmarshal(b, kr); err != nil {
		return nil, fmt.Errorf("key ring: %w", err)
	}
	if _, ok := kr.Keys[kr.Current]; !ok {
		return nil, errors.New("key ring: current key missing")
	}
	return kr, nil
}

func (k *KeyRing) newKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	id := ids.New("kek")
	k.Keys[id] = key
	k.Current = id
	return id, nil
}

func (k *KeyRing) save() error {
	if err := os.MkdirAll(filepath.Dir(k.path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(k)
	if err != nil {
		return err
	}
	tmp := k.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, k.path)
}

func (k *KeyRing) get(id string) ([]byte, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	v, ok := k.Keys[id]
	return v, ok
}

func (k *KeyRing) current() (string, []byte) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.Current, k.Keys[k.Current]
}

func seal(key, plaintext, aad []byte) (ct, nonce []byte, err error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return g.Seal(nil, nonce, plaintext, aad), nonce, nil
}

func open(key, ct, nonce, aad []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce, ct, aad)
}

// Ref identifies a secret's scope.
type Ref struct {
	Scope         string `json:"scope"`
	ProjectID     string `json:"project_id,omitempty"`
	EnvironmentID string `json:"environment_id,omitempty"`
	Name          string `json:"name"`
}

func (r Ref) validate() error {
	if !nameRE.MatchString(r.Name) {
		return fmt.Errorf("%w: name %q", ErrInvalid, r.Name)
	}
	switch r.Scope {
	case ScopeInstance:
		if r.ProjectID != "" || r.EnvironmentID != "" {
			return fmt.Errorf("%w: instance scope takes no project/environment", ErrInvalid)
		}
	case ScopeProject, ScopePreview:
		if !ids.HasPrefix(r.ProjectID, "prj") || r.EnvironmentID != "" {
			return fmt.Errorf("%w: project scope requires project only", ErrInvalid)
		}
	case ScopeEnvironment:
		if !ids.HasPrefix(r.ProjectID, "prj") || !ids.HasPrefix(r.EnvironmentID, "env") {
			return fmt.Errorf("%w: environment scope requires project and environment", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: scope %q", ErrInvalid, r.Scope)
	}
	return nil
}

func aad(r Ref, version int64) []byte {
	return []byte(fmt.Sprintf("opendeploy-secret-v1|%s|%s|%s|%s|%d", r.Scope, r.ProjectID, r.EnvironmentID, r.Name, version))
}

// Meta is non-sensitive secret metadata.
type Meta struct {
	ID string `json:"id"`
	Ref
	Version      int64  `json:"version"`
	Sensitive    bool   `json:"sensitive"`
	BuildVisible bool   `json:"build_visible"`
	CreatedAt    string `json:"created_at"`
	CreatedBy    string `json:"created_by"`
	// Preview shows a non-sensitive value (sensitive=false) for UI display.
	Preview string `json:"preview,omitempty"`
}

// Store is secretd's store.
type Store struct {
	db  *state.DB
	kr  *KeyRing
	log *slog.Logger
}

// Open opens the secret DB.
func Open(ctx context.Context, path string, kr *KeyRing, log *slog.Logger) (*Store, error) {
	sub, _ := fs.Sub(migrationsFS, "migrations")
	db, err := state.Open(ctx, path, state.Options{Migrations: sub, Logger: log})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, kr: kr, log: log}
	if db.Degraded() == "" {
		cur, _ := kr.current()
		_ = db.Tx(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO keks(id,created_at) VALUES(?,?)`, cur, state.Now())
			return err
		})
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Set stores a new version of a secret.
func (s *Store) Set(ctx context.Context, r Ref, value []byte, sensitive, buildVisible bool, actor string) (*Meta, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	if len(value) > MaxValueBytes {
		return nil, fmt.Errorf("%w: value exceeds %d bytes", ErrInvalid, MaxValueBytes)
	}
	var out *Meta
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		var ver sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT MAX(version) FROM secrets WHERE scope=? AND project_id=? AND environment_id=? AND name=?`,
			r.Scope, r.ProjectID, r.EnvironmentID, r.Name).Scan(&ver); err != nil {
			return err
		}
		version := ver.Int64 + 1
		dek := make([]byte, 32)
		if _, err := rand.Read(dek); err != nil {
			return err
		}
		ct, nonce, err := seal(dek, value, aad(r, version))
		if err != nil {
			return err
		}
		kid, kek := s.kr.current()
		wd, dn, err := seal(kek, dek, append([]byte(kid+"|"), aad(r, version)...))
		if err != nil {
			return err
		}
		now := state.Now()
		if _, err := tx.ExecContext(ctx, `UPDATE secrets SET superseded_at=? WHERE scope=? AND project_id=? AND environment_id=? AND name=? AND superseded_at='' AND deleted_at=''`,
			now, r.Scope, r.ProjectID, r.EnvironmentID, r.Name); err != nil {
			return err
		}
		id := ids.New("sec")
		if _, err := tx.ExecContext(ctx, `INSERT INTO secrets(id,scope,project_id,environment_id,name,version,sensitive,build_visible,ciphertext,nonce,wrapped_dek,dek_nonce,kek_id,created_at,created_by)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, r.Scope, r.ProjectID, r.EnvironmentID, r.Name, version, sensitive, buildVisible, ct, nonce, wd, dn, kid, now, actor); err != nil {
			return err
		}
		out = &Meta{ID: id, Ref: r, Version: version, Sensitive: sensitive, BuildVisible: buildVisible, CreatedAt: now, CreatedBy: actor}
		return nil
	})
	return out, err
}

type row struct {
	Meta
	ct, nonce, wd, dn []byte
	kid               string
}

func (s *Store) decrypt(r *row) ([]byte, error) {
	kek, ok := s.kr.get(r.kid)
	if !ok {
		return nil, fmt.Errorf("kek %s unavailable", r.kid)
	}
	a := aad(r.Ref, r.Version)
	dek, err := open(kek, r.wd, r.dn, append([]byte(r.kid+"|"), a...))
	if err != nil {
		return nil, fmt.Errorf("unwrap dek: %w", err)
	}
	v, err := open(dek, r.ct, r.nonce, a)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return v, nil
}

const rowCols = `id,scope,project_id,environment_id,name,version,sensitive,build_visible,created_at,created_by,ciphertext,nonce,wrapped_dek,dek_nonce,kek_id`

func scanRow(sc interface{ Scan(...any) error }) (*row, error) {
	var r row
	err := sc.Scan(&r.ID, &r.Scope, &r.ProjectID, &r.EnvironmentID, &r.Name, &r.Version, &r.Sensitive, &r.BuildVisible, &r.CreatedAt, &r.CreatedBy, &r.ct, &r.nonce, &r.wd, &r.dn, &r.kid)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) current(ctx context.Context, where string, args ...any) ([]*row, error) {
	rows, err := s.db.R().QueryContext(ctx, `SELECT `+rowCols+` FROM secrets WHERE superseded_at='' AND deleted_at='' AND `+where+` ORDER BY name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*row
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// List returns metadata for a scope; values are never returned except the
// preview of non-sensitive values.
func (s *Store) List(ctx context.Context, scope, projectID, envID string) ([]Meta, error) {
	rs, err := s.current(ctx, `scope=? AND project_id=? AND environment_id=?`, scope, projectID, envID)
	if err != nil {
		return nil, err
	}
	out := make([]Meta, 0, len(rs))
	for _, r := range rs {
		m := r.Meta
		if !m.Sensitive {
			if v, err := s.decrypt(r); err == nil {
				m.Preview = string(v)
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// Reveal returns the current value of one secret by id.
func (s *Store) Reveal(ctx context.Context, id, projectID string) (*Meta, []byte, error) {
	rs, err := s.current(ctx, `id=?`, id)
	if err != nil {
		return nil, nil, err
	}
	if len(rs) == 0 {
		return nil, nil, ErrNotFound
	}
	r := rs[0]
	if r.ProjectID != projectID {
		// The caller asserted the wrong project: treat as not found (IDOR).
		return nil, nil, ErrNotFound
	}
	v, err := s.decrypt(r)
	if err != nil {
		return nil, nil, err
	}
	return &r.Meta, v, nil
}

// Delete marks the current version deleted.
func (s *Store) Delete(ctx context.Context, r Ref) error {
	if err := r.validate(); err != nil {
		return err
	}
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE secrets SET deleted_at=? WHERE scope=? AND project_id=? AND environment_id=? AND name=? AND superseded_at='' AND deleted_at=''`,
			state.Now(), r.Scope, r.ProjectID, r.EnvironmentID, r.Name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// DeleteProject removes all secrets of a project (project deletion).
func (s *Store) DeleteProject(ctx context.Context, projectID string) (int64, error) {
	if !ids.HasPrefix(projectID, "prj") {
		return 0, ErrInvalid
	}
	var n int64
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE secrets SET deleted_at=? WHERE project_id=? AND deleted_at=''`, state.Now(), projectID)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	return n, err
}

// ResolveReq asks for the injection material for a workload or build.
type ResolveReq struct {
	ProjectID     string `json:"project_id"`
	EnvironmentID string `json:"environment_id"`
	EnvKind       string `json:"env_kind"`    // production | staging | preview
	TrustClass    string `json:"trust_class"` // trusted | untrusted | privileged
	Purpose       string `json:"purpose"`     // runtime | build
	FromFork      bool   `json:"from_fork"`
}

// Resolved is the merged name->value map plus provenance.
type Resolved struct {
	Values  map[string]string `json:"values"`
	Sources map[string]string `json:"sources"` // name -> scope@version
}

// Resolve merges instance -> project -> environment for runtime or build.
func (s *Store) Resolve(ctx context.Context, r ResolveReq) (*Resolved, error) {
	if !ids.HasPrefix(r.ProjectID, "prj") || !ids.HasPrefix(r.EnvironmentID, "env") {
		return nil, ErrInvalid
	}
	switch r.Purpose {
	case "runtime", "build":
	default:
		return nil, ErrInvalid
	}
	if r.Purpose == "build" && (r.TrustClass == "untrusted" || r.FromFork) {
		// Untrusted/fork builds never receive secrets (PRD §7.5).
		return &Resolved{Values: map[string]string{}, Sources: map[string]string{}}, nil
	}
	layers := [][]any{{`scope='instance' AND project_id='' AND environment_id=''`}}
	switch r.EnvKind {
	case "preview":
		// No implicit production/project inheritance (SC-06/SC-09).
		layers = append(layers, []any{`scope='preview' AND project_id=? AND environment_id=''`, r.ProjectID})
	case "production", "staging":
		if r.FromFork {
			return nil, fmt.Errorf("%w: fork code cannot run in %s", ErrDenied, r.EnvKind)
		}
		layers = append(layers, []any{`scope='project' AND project_id=? AND environment_id=''`, r.ProjectID})
	default:
		return nil, ErrInvalid
	}
	layers = append(layers, []any{`scope='environment' AND project_id=? AND environment_id=?`, r.ProjectID, r.EnvironmentID})
	out := &Resolved{Values: map[string]string{}, Sources: map[string]string{}}
	for _, l := range layers {
		rs, err := s.current(ctx, l[0].(string), l[1:]...)
		if err != nil {
			return nil, err
		}
		for _, row := range rs {
			if r.Purpose == "build" && !row.BuildVisible {
				continue
			}
			if r.EnvKind == "preview" && r.TrustClass == "untrusted" && row.Scope == ScopeInstance && row.Sensitive {
				continue // untrusted previews never receive sensitive instance secrets
			}
			v, err := s.decrypt(row)
			if err != nil {
				return nil, fmt.Errorf("secret %s: %w", row.Name, err)
			}
			out.Values[row.Name] = string(v)
			out.Sources[row.Name] = fmt.Sprintf("%s@%d", row.Scope, row.Version)
		}
	}
	return out, nil
}

// RotateKEK creates a new KEK and rewraps every DEK. The old KEK is removed
// from the ring once no row references it.
func (s *Store) RotateKEK(ctx context.Context) (string, int, error) {
	s.kr.mu.Lock()
	oldID := s.kr.Current
	newID, err := s.kr.newKey()
	if err != nil {
		s.kr.mu.Unlock()
		return "", 0, err
	}
	if err := s.kr.save(); err != nil {
		s.kr.Current = oldID
		delete(s.kr.Keys, newID)
		s.kr.mu.Unlock()
		return "", 0, err
	}
	s.kr.mu.Unlock()
	n := 0
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+rowCols+` FROM secrets WHERE kek_id!=?`, newID)
		if err != nil {
			return err
		}
		var all []*row
		for rows.Next() {
			r, err := scanRow(rows)
			if err != nil {
				rows.Close()
				return err
			}
			all = append(all, r)
		}
		rows.Close()
		_, kek := s.kr.current()
		for _, r := range all {
			oldKek, ok := s.kr.get(r.kid)
			if !ok {
				return fmt.Errorf("kek %s missing", r.kid)
			}
			a := aad(r.Ref, r.Version)
			dek, err := open(oldKek, r.wd, r.dn, append([]byte(r.kid+"|"), a...))
			if err != nil {
				return err
			}
			wd, dn, err := seal(kek, dek, append([]byte(newID+"|"), a...))
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE secrets SET wrapped_dek=?, dek_nonce=?, kek_id=? WHERE id=?`, wd, dn, newID, r.ID); err != nil {
				return err
			}
			n++
		}
		now := state.Now()
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO keks(id,created_at) VALUES(?,?)`, newID, now); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE keks SET retired_at=? WHERE id!=? AND retired_at=''`, now, newID)
		return err
	})
	if err != nil {
		return "", 0, err
	}
	s.kr.mu.Lock()
	for id := range s.kr.Keys {
		if id != newID {
			delete(s.kr.Keys, id)
		}
	}
	err = s.kr.save()
	s.kr.mu.Unlock()
	return newID, n, err
}

// ExportKeyRing returns the key ring for encrypted backup export. The
// backup subsystem must wrap it with the separate backup master key.
func (s *Store) ExportKeyRing() ([]byte, error) {
	s.kr.mu.RLock()
	defer s.kr.mu.RUnlock()
	return json.Marshal(s.kr)
}

// Snapshot writes a consistent copy of the secret DB (ciphertext only).
func (s *Store) Snapshot(ctx context.Context, dir string) (string, error) {
	return s.db.Snapshot(ctx, dir, "backup")
}

// Names returns sorted keys of a resolved map (for logs).
func (r *Resolved) Names() []string {
	out := make([]string, 0, len(r.Values))
	for k := range r.Values {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// EncodeValue base64-encodes binary values for transport.
func EncodeValue(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Redact returns a safe display form of a value.
func Redact(v string) string {
	if len(v) <= 4 {
		return strings.Repeat("•", len(v))
	}
	return strings.Repeat("•", 8)
}
