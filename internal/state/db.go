// Package state owns durable SQLite metadata for OpenDeploy services
// (PRD §4.2, §16.1, SC-16).
//
// Guarantees:
//   - WAL journal, synchronous=FULL, foreign keys enforced, busy timeout.
//   - A single serialized writer connection (no SQLITE_BUSY races between
//     writers) and a separate read-only pool.
//   - Embedded, checksummed, transactional migrations. Applied migrations
//     whose checksum no longer matches, or a schema newer than this binary,
//     put the database into degraded read-only mode instead of guessing.
//   - Startup integrity checks (PRAGMA integrity_check / foreign_key_check and
//     caller-supplied invariants). Any failure enters degraded mode.
//   - Checksummed snapshots (VACUUM INTO) before risky operations.
package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// ErrDegraded is returned for writes while the database is in degraded mode.
var ErrDegraded = errors.New("state: database is in degraded read-only mode; repair or restore required")

// Invariant is an application-level consistency check. It returns a list of
// human-readable violations.
type Invariant func(ctx context.Context, q Querier) ([]string, error)

// Querier is satisfied by *sql.DB, *sql.Conn and *sql.Tx.
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// DB is a service-owned SQLite database.
type DB struct {
	Path     string
	w        *sql.DB
	r        *sql.DB
	degraded atomic.Pointer[string]
	log      *slog.Logger
}

// Options configures Open.
type Options struct {
	Migrations fs.FS // directory of NNNN_name.sql files
	Invariants []Invariant
	Logger     *slog.Logger
	// SnapshotDir, when set, receives a checksummed snapshot before any
	// pending migration is applied.
	SnapshotDir string
}

func dsn(path string, readOnly bool) string {
	v := url.Values{}
	v.Add("_pragma", "busy_timeout(10000)")
	v.Add("_pragma", "foreign_keys(1)")
	v.Add("_pragma", "synchronous(FULL)")
	if readOnly {
		v.Add("_pragma", "query_only(1)")
	} else {
		v.Add("_pragma", "journal_mode(WAL)")
		v.Add("_txlock", "immediate")
	}
	return "file:" + path + "?" + v.Encode()
}

// Open opens (creating if needed) the database at path, applies migrations
// and runs integrity checks. It returns a usable DB even when degraded so
// read-only inspection and repair tooling can work; callers must check
// Degraded().
func Open(ctx context.Context, path string, opt Options) (*DB, error) {
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	w, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	w.SetConnMaxIdleTime(0)
	if err := w.PingContext(ctx); err != nil {
		w.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	_ = os.Chmod(path, 0o600)
	r, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(4)
	db := &DB{Path: path, w: w, r: r, log: opt.Logger}

	if opt.Migrations != nil {
		if err := db.migrate(ctx, opt.Migrations, opt.SnapshotDir); err != nil {
			var de *degradedErr
			if errors.As(err, &de) {
				db.setDegraded(de.reason)
			} else {
				db.Close()
				return nil, err
			}
		}
	}
	if db.Degraded() == "" {
		if problems, err := db.Check(ctx, opt.Invariants...); err != nil {
			db.setDegraded("integrity check error: " + err.Error())
		} else if len(problems) > 0 {
			db.setDegraded("integrity violations: " + strings.Join(problems, "; "))
		}
	}
	if d := db.Degraded(); d != "" {
		opt.Logger.Error("database entered degraded read-only mode", "path", path, "reason", d)
	}
	return db, nil
}

func (db *DB) setDegraded(reason string) { db.degraded.Store(&reason) }

// Degraded returns a non-empty reason when the DB is in degraded mode.
func (db *DB) Degraded() string {
	if p := db.degraded.Load(); p != nil {
		return *p
	}
	return ""
}

// EnterDegraded is used by reconcilers that detect state that could delete,
// reattach or misroute resources (PRD §16.1).
func (db *DB) EnterDegraded(reason string) {
	db.setDegraded(reason)
	db.log.Error("database entered degraded read-only mode", "path", db.Path, "reason", reason)
}

// ClearDegraded is invoked only by explicit operator repair.
func (db *DB) ClearDegraded() { db.degraded.Store(nil) }

// Close closes both pools.
func (db *DB) Close() error {
	e1 := db.r.Close()
	e2 := db.w.Close()
	return errors.Join(e1, e2)
}

// R returns the read-only pool.
func (db *DB) R() *sql.DB { return db.r }

// Tx runs fn in a write transaction (BEGIN IMMEDIATE). It fails fast when
// the DB is degraded.
func (db *DB) Tx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	if d := db.Degraded(); d != "" {
		return ErrDegraded
	}
	tx, err := db.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Check runs SQLite and application integrity checks.
func (db *DB) Check(ctx context.Context, inv ...Invariant) ([]string, error) {
	var problems []string
	rows, err := db.w.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return nil, err
		}
		if s != "ok" {
			problems = append(problems, "sqlite: "+s)
		}
	}
	rows.Close()
	fk, err := db.w.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return nil, err
	}
	for fk.Next() {
		var table, parent string
		var rowid, idx sql.NullInt64
		if err := fk.Scan(&table, &rowid, &parent, &idx); err != nil {
			fk.Close()
			return nil, err
		}
		problems = append(problems, fmt.Sprintf("foreign key: %s row %d -> %s", table, rowid.Int64, parent))
	}
	fk.Close()
	for _, f := range inv {
		p, err := f(ctx, db.w)
		if err != nil {
			return nil, err
		}
		problems = append(problems, p...)
	}
	return problems, nil
}

type degradedErr struct{ reason string }

func (e *degradedErr) Error() string { return e.reason }

type migration struct {
	version  int
	name     string
	sql      string
	checksum string
}

func loadMigrations(fsys fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		num, _, ok := strings.Cut(e.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("migration %s: expected NNNN_name.sql", e.Name())
		}
		v, err := strconv.Atoi(num)
		if err != nil {
			return nil, fmt.Errorf("migration %s: %w", e.Name(), err)
		}
		b, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		out = append(out, migration{version: v, name: e.Name(), sql: string(b), checksum: hex.EncodeToString(sum[:])})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i := range out {
		if out[i].version != i+1 {
			return nil, fmt.Errorf("migrations must be contiguous from 1; found %d at position %d", out[i].version, i+1)
		}
	}
	return out, nil
}

func (db *DB) migrate(ctx context.Context, fsys fs.FS, snapDir string) error {
	ms, err := loadMigrations(fsys)
	if err != nil {
		return err
	}
	if _, err := db.w.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	applied := map[int]string{}
	rows, err := db.w.QueryContext(ctx, "SELECT version, checksum FROM schema_migrations")
	if err != nil {
		return err
	}
	maxApplied := 0
	for rows.Next() {
		var v int
		var c string
		if err := rows.Scan(&v, &c); err != nil {
			rows.Close()
			return err
		}
		applied[v] = c
		if v > maxApplied {
			maxApplied = v
		}
	}
	rows.Close()
	if maxApplied > len(ms) {
		return &degradedErr{fmt.Sprintf("schema version %d is newer than this binary supports (%d); refusing to write", maxApplied, len(ms))}
	}
	var pending []migration
	for _, m := range ms {
		c, ok := applied[m.version]
		if ok {
			if c != m.checksum {
				return &degradedErr{fmt.Sprintf("migration %s checksum mismatch (applied %s)", m.name, c[:12])}
			}
			continue
		}
		pending = append(pending, m)
	}
	if len(pending) == 0 {
		return nil
	}
	if snapDir != "" && maxApplied > 0 {
		if _, err := db.Snapshot(ctx, snapDir, fmt.Sprintf("pre-migrate-v%d", pending[0].version)); err != nil {
			return fmt.Errorf("pre-migration snapshot: %w", err)
		}
	}
	for _, m := range pending {
		tx, err := db.w.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply %s: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,name,checksum,applied_at) VALUES(?,?,?,?)",
			m.version, m.name, m.checksum, Now()); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		db.log.Info("applied migration", "db", filepath.Base(db.Path), "migration", m.name)
	}
	return nil
}

// SchemaVersion returns the highest applied migration version.
func (db *DB) SchemaVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	err := db.r.QueryRowContext(ctx, "SELECT MAX(version) FROM schema_migrations").Scan(&v)
	return int(v.Int64), err
}

// Snapshot writes a consistent copy of the database plus a .sha256 file and
// returns the snapshot path.
func (db *DB) Snapshot(ctx context.Context, dir, label string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s-%s-%s.db", strings.TrimSuffix(filepath.Base(db.Path), ".db"), time.Now().UTC().Format("20060102T150405.000000000Z"), label)
	p := filepath.Join(dir, name)
	if strings.ContainsAny(p, "'") {
		return "", errors.New("snapshot path must not contain quotes")
	}
	if _, err := db.w.ExecContext(ctx, "VACUUM INTO '"+p+"'"); err != nil {
		return "", err
	}
	sum, err := fileSHA256(p)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(p+".sha256", []byte(sum+"  "+name+"\n"), 0o600); err != nil {
		return "", err
	}
	_ = os.Chmod(p, 0o600)
	return p, nil
}

// VerifySnapshot checks a snapshot against its .sha256 file.
func VerifySnapshot(p string) error {
	want, err := os.ReadFile(p + ".sha256")
	if err != nil {
		return err
	}
	got, err := fileSHA256(p)
	if err != nil {
		return err
	}
	f := strings.Fields(string(want))
	if len(f) == 0 || f[0] != got {
		return fmt.Errorf("snapshot %s checksum mismatch", filepath.Base(p))
	}
	return nil
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// TimeFormat is the canonical timestamp encoding stored in the DB.
const TimeFormat = "2006-01-02T15:04:05.000000000Z"

// Now returns the current UTC time in TimeFormat.
func Now() string { return time.Now().UTC().Format(TimeFormat) }

// FormatTime encodes t in TimeFormat.
func FormatTime(t time.Time) string { return t.UTC().Format(TimeFormat) }

// ParseTime decodes TimeFormat (empty -> zero time).
func ParseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(TimeFormat, s)
	if err != nil {
		t, _ = time.Parse(time.RFC3339Nano, s)
	}
	return t
}
