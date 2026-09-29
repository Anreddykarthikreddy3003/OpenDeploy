// Package store is platformd's typed repository over the platform SQLite
// database. All SQL for platform metadata lives here.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/schema"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// SchemaVersion is the latest platform schema migration (see
// internal/schema).
const SchemaVersion = schema.Version

// Migrations returns the embedded platform migrations.
func Migrations() fs.FS {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		panic(err)
	}
	return sub
}

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned on uniqueness / compare-and-swap failures.
var ErrConflict = errors.New("conflict")

// Store wraps the platform database.
type Store struct {
	DB *state.DB
}

// Open opens the platform DB with migrations and invariants.
func Open(ctx context.Context, path, snapshotDir string, log *slog.Logger) (*Store, error) {
	db, err := state.Open(ctx, path, state.Options{
		Migrations:  Migrations(),
		Invariants:  Invariants(),
		Logger:      log,
		SnapshotDir: snapshotDir,
	})
	if err != nil {
		return nil, err
	}
	return &Store{DB: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.DB.Close() }

// Invariants are cross-row consistency checks whose violation could cause
// deletion, reattachment or misrouting of resources (PRD §16.1).
func Invariants() []state.Invariant {
	return []state.Invariant{
		queryViolations("environment current deployment belongs to another environment",
			`SELECT e.id FROM environments e JOIN deployments d ON d.id = e.current_deployment_id
			 WHERE e.current_deployment_id != '' AND d.environment_id != e.id`),
		queryViolations("environment current deployment missing",
			`SELECT e.id FROM environments e WHERE e.current_deployment_id != ''
			 AND NOT EXISTS (SELECT 1 FROM deployments d WHERE d.id = e.current_deployment_id)`),
		queryViolations("deployment project differs from its environment's project",
			`SELECT d.id FROM deployments d JOIN environments e ON e.id = d.environment_id WHERE d.project_id != e.project_id`),
		queryViolations("volume project differs from its environment's project",
			`SELECT v.id FROM volumes v JOIN environments e ON e.id = v.environment_id WHERE v.project_id != e.project_id`),
		queryViolations("service project differs from its environment's project",
			`SELECT s.id FROM services s JOIN environments e ON e.id = s.environment_id WHERE s.project_id != e.project_id`),
		queryViolations("active domain bound to environment of another project",
			`SELECT dm.id FROM domains dm JOIN environments e ON e.id = dm.environment_id
			 WHERE dm.status IN ('verified','active') AND dm.project_id != e.project_id`),
		queryViolations("artifact used by deployment of another project",
			`SELECT d.id FROM deployments d JOIN artifacts a ON a.id = d.artifact_id WHERE a.project_id != d.project_id`),
		queryViolations("workload environment differs from deployment environment",
			`SELECT w.id FROM workloads w JOIN deployments d ON d.id = w.deployment_id WHERE w.environment_id != d.environment_id`),
	}
}

func queryViolations(label, q string) state.Invariant {
	return func(ctx context.Context, db state.Querier) ([]string, error) {
		rows, err := db.QueryContext(ctx, q)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			out = append(out, fmt.Sprintf("%s: %s", label, id))
		}
		return out, rows.Err()
	}
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
