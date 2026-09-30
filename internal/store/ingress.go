package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
)

// ProjectsForEventTx returns live projects bound to repoID through a git
// connection with the given installation (SC-08: installation, repository
// and ref must all belong to the project).
func ProjectsForEventTx(ctx context.Context, tx *sql.Tx, installationID, repoID int64) ([]*Project, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+projectCols+` FROM projects WHERE deleted_at='' AND repo_id=? AND git_connection_id IN
		(SELECT id FROM git_connections WHERE provider='github' AND installation_id=? AND status='active') ORDER BY name`, repoID, installationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// EnvironmentByNameTx finds an environment inside a transaction.
func EnvironmentByNameTx(ctx context.Context, tx *sql.Tx, projectID, name string) (*Environment, error) {
	return scanEnv(tx.QueryRowContext(ctx, `SELECT `+envCols+` FROM environments WHERE project_id=? AND name=?`, projectID, name))
}

// EnsurePreviewEnvTx returns (creating or reactivating) the preview
// environment for a pull request.
func EnsurePreviewEnvTx(ctx context.Context, tx *sql.Tx, projectID string, pr int, branch string, fromFork bool, host string) (*Environment, error) {
	name := fmt.Sprintf("pr-%d", pr)
	e, err := EnvironmentByNameTx(ctx, tx, projectID, name)
	if err == nil {
		if e.Status != "active" || e.PRFromFork != fromFork || e.Branch != branch {
			if _, err := tx.ExecContext(ctx, `UPDATE environments SET status='active', pr_from_fork=?, branch=?, updated_at=? WHERE id=?`,
				b2i(fromFork), branch, state.Now(), e.ID); err != nil {
				return nil, err
			}
			e.Status, e.PRFromFork, e.Branch = "active", fromFork, branch
		}
		return e, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return insertEnvironment(ctx, tx, &Environment{ProjectID: projectID, Name: name, Kind: "preview", Branch: branch, PRNumber: pr, PRFromFork: fromFork, GeneratedHostname: host})
}

// MarkEnvDeletingTx flags an environment for teardown.
func MarkEnvDeletingTx(ctx context.Context, tx *sql.Tx, envID string) error {
	_, err := tx.ExecContext(ctx, `UPDATE environments SET status='deleting', updated_at=? WHERE id=? AND status IN ('active','stopped')`, state.Now(), envID)
	return err
}

// CountActivePreviewsTx counts a project's active previews (quota).
func CountActivePreviewsTx(ctx context.Context, tx *sql.Tx, projectID string) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM environments WHERE project_id=? AND kind='preview' AND status='active'`, projectID).Scan(&n)
	return n, err
}

// Tx exposes a write transaction to callers outside the package.
func (s *Store) Tx(ctx context.Context, fn func(tx *sql.Tx) error) error { return s.DB.Tx(ctx, fn) }
