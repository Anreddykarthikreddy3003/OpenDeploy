package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
)

type Job struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	IdempotencyKey string          `json:"idempotency_key"`
	Payload        json.RawMessage `json:"payload"`
	State          string          `json:"state"`
	Attempts       int             `json:"attempts"`
	MaxAttempts    int             `json:"max_attempts"`
	RunAfter       string          `json:"run_after"`
	LastError      string          `json:"last_error"`
	CreatedAt      string          `json:"created_at"`
}

// EnqueueTx inserts a job inside an existing transaction. Duplicate
// idempotency keys are ignored (returns existing=true).
func EnqueueTx(ctx context.Context, tx *sql.Tx, kind, key string, payload any, maxAttempts int) (string, bool, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return "", false, err
	}
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT id FROM jobs WHERE idempotency_key=?`, key).Scan(&existing)
	if err == nil {
		return existing, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", false, err
	}
	id := ids.New("job")
	now := state.Now()
	_, err = tx.ExecContext(ctx, `INSERT INTO jobs(id,kind,idempotency_key,payload,state,attempts,max_attempts,run_after,created_at,updated_at)
		VALUES(?,?,?,?, 'queued',0,?,?,?,?)`, id, kind, key, string(b), maxAttempts, now, now, now)
	return id, false, err
}

// Enqueue inserts a job in its own transaction.
func (s *Store) Enqueue(ctx context.Context, kind, key string, payload any, maxAttempts int) (string, error) {
	var id string
	err := s.DB.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		id, _, err = EnqueueTx(ctx, tx, kind, key, payload, maxAttempts)
		return err
	})
	return id, err
}

// ClaimJob leases the next ready job of the given kinds for `lease`.
// Expired leases of crashed workers become claimable again, which makes
// resumption after reboot automatic; handlers must therefore be idempotent.
func (s *Store) ClaimJob(ctx context.Context, worker string, kinds []string, lease time.Duration) (*Job, error) {
	var out *Job
	err := s.DB.Tx(ctx, func(tx *sql.Tx) error {
		now := state.Now()
		q := `SELECT id,kind,idempotency_key,payload,state,attempts,max_attempts,run_after,last_error,created_at FROM jobs
			WHERE ((state='queued' AND run_after<=?) OR (state='running' AND locked_until<=?))`
		args := []any{now, now}
		if len(kinds) > 0 {
			q += ` AND kind IN (` + quoteList(kinds) + `)`
		}
		q += ` ORDER BY run_after, created_at LIMIT 1`
		var j Job
		var payload string
		err := tx.QueryRowContext(ctx, q, args...).Scan(&j.ID, &j.Kind, &j.IdempotencyKey, &payload, &j.State, &j.Attempts, &j.MaxAttempts, &j.RunAfter, &j.LastError, &j.CreatedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		j.Payload = json.RawMessage(payload)
		j.Attempts++
		j.State = "running"
		_, err = tx.ExecContext(ctx, `UPDATE jobs SET state='running', attempts=?, locked_by=?, locked_until=?, updated_at=? WHERE id=?`,
			j.Attempts, worker, state.FormatTime(time.Now().Add(lease)), now, j.ID)
		if err != nil {
			return err
		}
		out = &j
		return nil
	})
	return out, err
}

// ExtendLease keeps a long-running job leased.
func (s *Store) ExtendLease(ctx context.Context, jobID string, lease time.Duration) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE jobs SET locked_until=?, updated_at=? WHERE id=? AND state='running'`,
			state.FormatTime(time.Now().Add(lease)), state.Now(), jobID)
		return err
	})
}

// CompleteJob marks success.
func (s *Store) CompleteJob(ctx context.Context, jobID string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE jobs SET state='succeeded', locked_by='', locked_until='', updated_at=? WHERE id=?`, state.Now(), jobID)
		return err
	})
}

// FailJob records a failure. Permanent errors or exhausted attempts move the
// job to 'dead'; otherwise it is re-queued with exponential backoff.
func (s *Store) FailJob(ctx context.Context, jobID string, errMsg string, permanent bool) (dead bool, err error) {
	err = s.DB.Tx(ctx, func(tx *sql.Tx) error {
		var attempts, max int
		if err := tx.QueryRowContext(ctx, `SELECT attempts,max_attempts FROM jobs WHERE id=?`, jobID).Scan(&attempts, &max); err != nil {
			return notFound(err)
		}
		now := state.Now()
		if permanent || attempts >= max {
			dead = true
			_, err := tx.ExecContext(ctx, `UPDATE jobs SET state='dead', last_error=?, locked_by='', locked_until='', updated_at=? WHERE id=?`, truncate(errMsg, 4000), now, jobID)
			return err
		}
		next := time.Now().Add(Backoff(attempts))
		_, err := tx.ExecContext(ctx, `UPDATE jobs SET state='queued', last_error=?, run_after=?, locked_by='', locked_until='', updated_at=? WHERE id=?`,
			truncate(errMsg, 4000), state.FormatTime(next), now, jobID)
		return err
	})
	return dead, err
}

// CancelJobsByKey cancels queued jobs whose idempotency key has prefix p.
func (s *Store) CancelJobsByKey(ctx context.Context, prefix string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE jobs SET state='cancelled', updated_at=? WHERE state='queued' AND idempotency_key LIKE ? ESCAPE '\'`,
			state.Now(), escapeLike(prefix)+"%")
		return err
	})
}

func escapeLike(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '%' || r == '_' || r == '\\' {
			out = append(out, '\\')
		}
		out = append(out, r)
	}
	return string(out)
}

// Backoff returns exponential backoff capped at 15 minutes.
func Backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := 2 * time.Second
	for i := 1; i < attempt && d < 15*time.Minute; i++ {
		d *= 2
	}
	if d > 15*time.Minute {
		d = 15 * time.Minute
	}
	return d
}

func (s *Store) ListJobs(ctx context.Context, stateFilter string, limit int) ([]Job, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id,kind,idempotency_key,payload,state,attempts,max_attempts,run_after,last_error,created_at FROM jobs`
	args := []any{}
	if stateFilter != "" {
		q += ` WHERE state=?`
		args = append(args, stateFilter)
	}
	q += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.DB.R().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		var j Job
		var p string
		if err := rows.Scan(&j.ID, &j.Kind, &j.IdempotencyKey, &p, &j.State, &j.Attempts, &j.MaxAttempts, &j.RunAfter, &j.LastError, &j.CreatedAt); err != nil {
			return nil, err
		}
		j.Payload = json.RawMessage(p)
		out = append(out, j)
	}
	return out, rows.Err()
}

// Webhook deliveries (SC-08).

type WebhookDelivery struct {
	DeliveryID     string
	Event          string
	Action         string
	InstallationID int64
	RepositoryID   int64
	Ref            string
	SHA            string
	BodySHA256     string
}

// RecordDeliveryTx inserts an append-only ingress record; it returns
// duplicate=true when the delivery ID was already seen.
func RecordDeliveryTx(ctx context.Context, tx *sql.Tx, d WebhookDelivery) (duplicate bool, err error) {
	_, err = tx.ExecContext(ctx, `INSERT INTO webhook_deliveries(delivery_id,event,action,installation_id,repository_id,ref,sha,body_sha256,received_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, d.DeliveryID, d.Event, d.Action, d.InstallationID, d.RepositoryID, d.Ref, d.SHA, d.BodySHA256, state.Now())
	if isUnique(err) {
		return true, nil
	}
	return false, err
}

func SetDeliveryOutcomeTx(ctx context.Context, tx *sql.Tx, id, outcome string) error {
	_, err := tx.ExecContext(ctx, `UPDATE webhook_deliveries SET outcome=? WHERE delivery_id=?`, truncate(outcome, 500), id)
	return err
}

// Settings

func (s *Store) GetSetting(ctx context.Context, key string, v any) (bool, error) {
	var raw string
	err := s.DB.R().QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(raw), v)
}

func (s *Store) SetSetting(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`, key, string(b), state.Now())
		return err
	})
}

// Circuit breakers (SC-16).

type Breaker struct {
	Key         string `json:"key"`
	State       string `json:"state"`
	Failures    int    `json:"failures"`
	LastError   string `json:"last_error"`
	OpenedAt    string `json:"opened_at"`
	NextAttempt string `json:"next_attempt"`
}

// BreakerThreshold is the consecutive-failure count that opens a breaker.
const BreakerThreshold = 5

// BreakerAllow reports whether an action guarded by key may run now.
func (s *Store) BreakerAllow(ctx context.Context, key string) (bool, *Breaker, error) {
	b, err := s.GetBreaker(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return true, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	if b.State == "open" && time.Now().Before(state.ParseTime(b.NextAttempt)) {
		return false, b, nil
	}
	return true, b, nil
}

func (s *Store) GetBreaker(ctx context.Context, key string) (*Breaker, error) {
	var b Breaker
	err := s.DB.R().QueryRowContext(ctx, `SELECT key,state,failures,last_error,opened_at,next_attempt FROM circuit_breakers WHERE key=?`, key).
		Scan(&b.Key, &b.State, &b.Failures, &b.LastError, &b.OpenedAt, &b.NextAttempt)
	if err != nil {
		return nil, notFound(err)
	}
	return &b, nil
}

// BreakerRecord records the outcome of a guarded action.
func (s *Store) BreakerRecord(ctx context.Context, key string, failure error) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		now := state.Now()
		if failure == nil {
			_, err := tx.ExecContext(ctx, `DELETE FROM circuit_breakers WHERE key=?`, key)
			return err
		}
		var failures int
		err := tx.QueryRowContext(ctx, `SELECT failures FROM circuit_breakers WHERE key=?`, key).Scan(&failures)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		failures++
		st, opened, next := "closed", "", ""
		if failures >= BreakerThreshold {
			st, opened = "open", now
			next = state.FormatTime(time.Now().Add(Backoff(failures - BreakerThreshold + 3)))
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO circuit_breakers(key,state,failures,last_error,opened_at,next_attempt,updated_at) VALUES(?,?,?,?,?,?,?)
			ON CONFLICT(key) DO UPDATE SET state=excluded.state, failures=excluded.failures, last_error=excluded.last_error,
			opened_at=CASE WHEN circuit_breakers.opened_at='' THEN excluded.opened_at ELSE circuit_breakers.opened_at END,
			next_attempt=excluded.next_attempt, updated_at=excluded.updated_at`, key, st, failures, truncate(failure.Error(), 2000), opened, next, now)
		return err
	})
}

func (s *Store) ListBreakers(ctx context.Context) ([]Breaker, error) {
	rows, err := s.DB.R().QueryContext(ctx, `SELECT key,state,failures,last_error,opened_at,next_attempt FROM circuit_breakers ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Breaker
	for rows.Next() {
		var b Breaker
		if err := rows.Scan(&b.Key, &b.State, &b.Failures, &b.LastError, &b.OpenedAt, &b.NextAttempt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) ResetBreaker(ctx context.Context, key string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM circuit_breakers WHERE key=?`, key)
		return err
	})
}
