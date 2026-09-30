package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/model"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
)

// ErrSuperseded is returned when a candidate's generation is no longer the
// environment's desired generation (PRD §11.2, SC-15).
var ErrSuperseded = errors.New("deployment superseded by a newer desired generation")

// ErrPromotionInFlight is returned when another promotion holds the
// environment's promotion lock.
var ErrPromotionInFlight = errors.New("another promotion is in flight for this environment")

type PromotionIntent struct {
	ID             string `json:"id"`
	EnvironmentID  string `json:"environment_id"`
	FromDeployment string `json:"from_deployment"`
	ToDeployment   string `json:"to_deployment"`
	Generation     int64  `json:"generation"`
	RouterDigest   string `json:"router_digest"`
	State          string `json:"state"`
	Error          string `json:"error"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

const intentCols = `id,environment_id,from_deployment,to_deployment,generation,router_digest,state,error,created_at,updated_at`

func scanIntent(r interface{ Scan(...any) error }) (*PromotionIntent, error) {
	var p PromotionIntent
	if err := r.Scan(&p.ID, &p.EnvironmentID, &p.FromDeployment, &p.ToDeployment, &p.Generation, &p.RouterDigest, &p.State, &p.Error, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, notFound(err)
	}
	return &p, nil
}

// BeginPromotion is steps 1-2 of §11.3: compare-and-swap on the desired
// generation and persist the promotion intent. The in-flight unique index is
// the per-environment promotion lock. Superseded candidates are marked
// SUPERSEDED in the same transaction.
func (s *Store) BeginPromotion(ctx context.Context, depID, routerDigest string) (*PromotionIntent, error) {
	var out *PromotionIntent
	var superseded bool
	err := s.DB.Tx(ctx, func(tx *sql.Tx) error {
		var envID string
		var gen int64
		var st model.DeploymentStatus
		if err := tx.QueryRowContext(ctx, `SELECT environment_id, generation, status FROM deployments WHERE id=?`, depID).Scan(&envID, &gen, &st); err != nil {
			return notFound(err)
		}
		var desired int64
		var current, envStatus string
		if err := tx.QueryRowContext(ctx, `SELECT desired_generation, current_deployment_id, status FROM environments WHERE id=?`, envID).
			Scan(&desired, &current, &envStatus); err != nil {
			return notFound(err)
		}
		if envStatus != "active" {
			return fmt.Errorf("%w: environment is %s", ErrConflict, envStatus)
		}
		if gen != desired {
			if model.CanTransition(st, model.StatusSuperseded) {
				if err := transitionTx(ctx, tx, depID, st, model.StatusSuperseded, fmt.Sprintf("generation %d is not desired generation %d", gen, desired), ""); err != nil {
					return err
				}
			}
			superseded = true
			return nil
		}
		if st != model.StatusHealthChecking && st != model.StatusReady {
			return fmt.Errorf("%w: deployment is %s, not promotable", ErrConflict, st)
		}
		p := &PromotionIntent{ID: ids.New("pmi"), EnvironmentID: envID, FromDeployment: current, ToDeployment: depID,
			Generation: gen, RouterDigest: routerDigest, State: "pending", CreatedAt: state.Now()}
		p.UpdatedAt = p.CreatedAt
		if _, err := tx.ExecContext(ctx, `INSERT INTO promotion_intents(`+intentCols+`) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			p.ID, p.EnvironmentID, p.FromDeployment, p.ToDeployment, p.Generation, p.RouterDigest, p.State, p.Error, p.CreatedAt, p.UpdatedAt); err != nil {
			if isUnique(err) {
				return ErrPromotionInFlight
			}
			return err
		}
		if err := transitionTx(ctx, tx, depID, st, model.StatusPromotionIntent, "promotion intent "+p.ID, ""); err != nil {
			return err
		}
		out = p
		return nil
	})
	if err == nil && superseded {
		return nil, ErrSuperseded
	}
	return out, err
}

// MarkRouterApplied records steps 3-4 (router accepted and verified).
func (s *Store) MarkRouterApplied(ctx context.Context, intentID, routerDigest string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		p, err := scanIntent(tx.QueryRowContext(ctx, `SELECT `+intentCols+` FROM promotion_intents WHERE id=?`, intentID))
		if err != nil {
			return err
		}
		if p.State != "pending" {
			return fmt.Errorf("%w: intent is %s", ErrConflict, p.State)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE promotion_intents SET state='router_applied', router_digest=?, updated_at=? WHERE id=?`, routerDigest, state.Now(), intentID); err != nil {
			return err
		}
		return transitionTx(ctx, tx, p.ToDeployment, model.StatusPromotionIntent, model.StatusRouterSwitched, "router config "+short(routerDigest), "")
	})
}

// CommitPromotion is step 5: commit current_deployment and
// observed_generation in one transaction. observed_generation never moves
// backwards.
func (s *Store) CommitPromotion(ctx context.Context, intentID string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		p, err := scanIntent(tx.QueryRowContext(ctx, `SELECT `+intentCols+` FROM promotion_intents WHERE id=?`, intentID))
		if err != nil {
			return err
		}
		if p.State != "router_applied" {
			return fmt.Errorf("%w: intent is %s", ErrConflict, p.State)
		}
		if err := transitionTx(ctx, tx, p.ToDeployment, model.StatusRouterSwitched, model.StatusCommittingPointer, "committing pointer", ""); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE environments SET current_deployment_id=?, observed_generation=?, updated_at=?
			WHERE id=? AND observed_generation<?`, p.ToDeployment, p.Generation, state.Now(), p.EnvironmentID, p.Generation)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%w: observed generation already >= %d", ErrConflict, p.Generation)
		}
		_, err = tx.ExecContext(ctx, `UPDATE promotion_intents SET state='committed', updated_at=? WHERE id=?`, state.Now(), intentID)
		return err
	})
}

// CompletePromotion is step 6: mark the intent complete and move the
// deployment through DRAINING_OLD. FinishDeployment marks SUCCEEDED after
// the old runtime is drained.
func (s *Store) CompletePromotion(ctx context.Context, intentID string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		p, err := scanIntent(tx.QueryRowContext(ctx, `SELECT `+intentCols+` FROM promotion_intents WHERE id=?`, intentID))
		if err != nil {
			return err
		}
		if p.State != "committed" {
			return fmt.Errorf("%w: intent is %s", ErrConflict, p.State)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE promotion_intents SET state='complete', updated_at=? WHERE id=?`, state.Now(), intentID); err != nil {
			return err
		}
		return transitionTx(ctx, tx, p.ToDeployment, model.StatusCommittingPointer, model.StatusDrainingOld, "draining previous deployment", "")
	})
}

// AbortPromotion marks an intent aborted and fails (or supersedes) the
// candidate. Callers must have restored the previous router configuration.
func (s *Store) AbortPromotion(ctx context.Context, intentID, reason string, superseded bool) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		p, err := scanIntent(tx.QueryRowContext(ctx, `SELECT `+intentCols+` FROM promotion_intents WHERE id=?`, intentID))
		if err != nil {
			return err
		}
		if p.State == "complete" || p.State == "aborted" {
			return nil
		}
		if p.State == "committed" {
			return fmt.Errorf("%w: committed intent cannot be aborted", ErrConflict)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE promotion_intents SET state='aborted', error=?, updated_at=? WHERE id=?`, truncate(reason, 2000), state.Now(), intentID); err != nil {
			return err
		}
		var st model.DeploymentStatus
		if err := tx.QueryRowContext(ctx, `SELECT status FROM deployments WHERE id=?`, p.ToDeployment).Scan(&st); err != nil {
			return notFound(err)
		}
		if st.Terminal() {
			return nil
		}
		to := model.StatusFailed
		if superseded && model.CanTransition(st, model.StatusSuperseded) {
			to = model.StatusSuperseded
		}
		return transitionTx(ctx, tx, p.ToDeployment, st, to, "promotion aborted: "+reason, reason)
	})
}

// InflightPromotions returns intents that are not complete/aborted.
func (s *Store) InflightPromotions(ctx context.Context) ([]*PromotionIntent, error) {
	rows, err := s.DB.R().QueryContext(ctx, `SELECT `+intentCols+` FROM promotion_intents WHERE state IN ('pending','router_applied','committed') ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*PromotionIntent
	for rows.Next() {
		p, err := scanIntent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetPromotionIntent(ctx context.Context, id string) (*PromotionIntent, error) {
	return scanIntent(s.DB.R().QueryRowContext(ctx, `SELECT `+intentCols+` FROM promotion_intents WHERE id=?`, id))
}

func short(s string) string {
	if len(s) > 19 {
		return s[:19]
	}
	return s
}
