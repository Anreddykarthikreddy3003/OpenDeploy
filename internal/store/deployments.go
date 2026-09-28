package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/model"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
)

type Environment struct {
	ID                  string `json:"id"`
	ProjectID           string `json:"project_id"`
	Name                string `json:"name"`
	Kind                string `json:"kind"`
	Branch              string `json:"branch"`
	PRNumber            int    `json:"pr_number,omitempty"`
	PRFromFork          bool   `json:"pr_from_fork,omitempty"`
	DesiredGeneration   int64  `json:"desired_generation"`
	ObservedGeneration  int64  `json:"observed_generation"`
	DesiredDeploymentID string `json:"desired_deployment_id"`
	CurrentDeploymentID string `json:"current_deployment_id"`
	GeneratedHostname   string `json:"generated_hostname"`
	Status              string `json:"status"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
}

const envCols = `id,project_id,name,kind,branch,pr_number,pr_from_fork,desired_generation,observed_generation,
desired_deployment_id,current_deployment_id,generated_hostname,status,created_at,updated_at`

func scanEnv(r interface{ Scan(...any) error }) (*Environment, error) {
	var e Environment
	err := r.Scan(&e.ID, &e.ProjectID, &e.Name, &e.Kind, &e.Branch, &e.PRNumber, &e.PRFromFork, &e.DesiredGeneration,
		&e.ObservedGeneration, &e.DesiredDeploymentID, &e.CurrentDeploymentID, &e.GeneratedHostname, &e.Status, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &e, nil
}

func insertEnvironment(ctx context.Context, tx *sql.Tx, e *Environment) (*Environment, error) {
	if e.ID == "" {
		e.ID = ids.New("env")
	}
	now := state.Now()
	e.CreatedAt, e.UpdatedAt = now, now
	if e.Status == "" {
		e.Status = "active"
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO environments(id,project_id,name,kind,branch,pr_number,pr_from_fork,generated_hostname,status,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`, e.ID, e.ProjectID, e.Name, e.Kind, e.Branch, e.PRNumber, b2i(e.PRFromFork), e.GeneratedHostname, e.Status, now, now)
	if isUnique(err) {
		return nil, ErrConflict
	}
	return e, err
}

// CreateEnvironment adds a staging/preview environment.
func (s *Store) CreateEnvironment(ctx context.Context, e *Environment) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := insertEnvironment(ctx, tx, e)
		return err
	})
}

func (s *Store) GetEnvironment(ctx context.Context, id string) (*Environment, error) {
	return scanEnv(s.DB.R().QueryRowContext(ctx, `SELECT `+envCols+` FROM environments WHERE id=?`, id))
}

func (s *Store) GetEnvironmentByName(ctx context.Context, projectID, name string) (*Environment, error) {
	return scanEnv(s.DB.R().QueryRowContext(ctx, `SELECT `+envCols+` FROM environments WHERE project_id=? AND name=?`, projectID, name))
}

func (s *Store) ListEnvironments(ctx context.Context, projectID string) ([]*Environment, error) {
	return s.queryEnvs(ctx, `SELECT `+envCols+` FROM environments WHERE project_id=? AND status!='deleted' ORDER BY kind DESC, name`, projectID)
}

// ActiveEnvironments returns all environments that should be reconciled.
func (s *Store) ActiveEnvironments(ctx context.Context) ([]*Environment, error) {
	return s.queryEnvs(ctx, `SELECT `+envCols+` FROM environments WHERE status IN ('active','deleting','stopped')
		ORDER BY CASE kind WHEN 'production' THEN 0 WHEN 'staging' THEN 1 ELSE 2 END, created_at`)
}

func (s *Store) queryEnvs(ctx context.Context, q string, args ...any) ([]*Environment, error) {
	rows, err := s.DB.R().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Environment
	for rows.Next() {
		e, err := scanEnv(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) SetEnvironmentStatus(ctx context.Context, id, status string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE environments SET status=?, updated_at=? WHERE id=?`, status, state.Now(), id)
		return err
	})
}

func (s *Store) SetGeneratedHostname(ctx context.Context, envID, host string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE environments SET generated_hostname=?, updated_at=? WHERE id=?`, host, state.Now(), envID)
		return err
	})
}

type Deployment struct {
	ID              string                 `json:"id"`
	ProjectID       string                 `json:"project_id"`
	EnvironmentID   string                 `json:"environment_id"`
	Generation      int64                  `json:"generation"`
	Trigger         string                 `json:"trigger"`
	CommitSHA       string                 `json:"commit_sha"`
	CommitMessage   string                 `json:"commit_message"`
	CommitAuthor    string                 `json:"commit_author"`
	Branch          string                 `json:"branch"`
	DeliveryID      string                 `json:"delivery_id,omitempty"`
	RollbackOf      string                 `json:"rollback_of,omitempty"`
	Status          model.DeploymentStatus `json:"status"`
	TrustClass      string                 `json:"trust_class"`
	RuntimeClass    string                 `json:"runtime_class"`
	BuildStrategy   string                 `json:"build_strategy"`
	BuildInputs     json.RawMessage        `json:"build_inputs"`
	ConfigSnapshot  json.RawMessage        `json:"config_snapshot"`
	ArtifactID      string                 `json:"artifact_id,omitempty"`
	DecisionReasons []string               `json:"decision_reasons"`
	Error           string                 `json:"error,omitempty"`
	CreatedBy       string                 `json:"created_by"`
	CreatedAt       string                 `json:"created_at"`
	UpdatedAt       string                 `json:"updated_at"`
	StartedAt       string                 `json:"started_at,omitempty"`
	FinishedAt      string                 `json:"finished_at,omitempty"`
}

const depCols = `id,project_id,environment_id,generation,trigger,commit_sha,commit_message,commit_author,branch,delivery_id,rollback_of,
status,trust_class,runtime_class,build_strategy,build_inputs,config_snapshot,COALESCE(artifact_id,''),decision_reasons,error,created_by,
created_at,updated_at,started_at,finished_at`

func scanDep(r interface{ Scan(...any) error }) (*Deployment, error) {
	var d Deployment
	var bi, cs, reasons string
	err := r.Scan(&d.ID, &d.ProjectID, &d.EnvironmentID, &d.Generation, &d.Trigger, &d.CommitSHA, &d.CommitMessage, &d.CommitAuthor,
		&d.Branch, &d.DeliveryID, &d.RollbackOf, &d.Status, &d.TrustClass, &d.RuntimeClass, &d.BuildStrategy, &bi, &cs, &d.ArtifactID,
		&reasons, &d.Error, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt, &d.StartedAt, &d.FinishedAt)
	if err != nil {
		return nil, notFound(err)
	}
	d.BuildInputs = json.RawMessage(bi)
	d.ConfigSnapshot = json.RawMessage(cs)
	_ = json.Unmarshal([]byte(reasons), &d.DecisionReasons)
	if d.DecisionReasons == nil {
		d.DecisionReasons = []string{}
	}
	return &d, nil
}

// NewDeployment describes a deployment request.
type NewDeployment struct {
	EnvironmentID string
	Trigger       string
	CommitSHA     string
	CommitMessage string
	CommitAuthor  string
	Branch        string
	DeliveryID    string
	RollbackOf    string
	ArtifactID    string // set for rollback/redeploy of a retained artifact
	CreatedBy     string
}

// CreateDeployment atomically increments the environment's monotonic
// desired_generation and inserts a deployment carrying that generation
// (PRD §6.2 step 5, §11.2, SC-15). Older in-flight deployments that have not
// reached the router switch are marked SUPERSEDED in the same transaction.
func (s *Store) CreateDeployment(ctx context.Context, nd NewDeployment) (*Deployment, error) {
	var out *Deployment
	err := s.DB.Tx(ctx, func(tx *sql.Tx) error {
		var projectID, envStatus string
		var gen int64
		if err := tx.QueryRowContext(ctx, `SELECT project_id, desired_generation, status FROM environments WHERE id=?`, nd.EnvironmentID).
			Scan(&projectID, &gen, &envStatus); err != nil {
			return notFound(err)
		}
		if envStatus != "active" {
			return fmt.Errorf("%w: environment is %s", ErrConflict, envStatus)
		}
		gen++
		now := state.Now()
		d := &Deployment{
			ID: ids.New("dep"), ProjectID: projectID, EnvironmentID: nd.EnvironmentID, Generation: gen, Trigger: nd.Trigger,
			CommitSHA: nd.CommitSHA, CommitMessage: truncate(nd.CommitMessage, 1000), CommitAuthor: truncate(nd.CommitAuthor, 200), Branch: nd.Branch,
			DeliveryID: nd.DeliveryID, RollbackOf: nd.RollbackOf, Status: model.StatusReceived, ArtifactID: nd.ArtifactID,
			CreatedBy: nd.CreatedBy, CreatedAt: now, UpdatedAt: now, BuildInputs: json.RawMessage("{}"), ConfigSnapshot: json.RawMessage("{}"),
			DecisionReasons: []string{},
		}
		var art any
		if d.ArtifactID != "" {
			var ap string
			if err := tx.QueryRowContext(ctx, `SELECT project_id FROM artifacts WHERE id=?`, d.ArtifactID).Scan(&ap); err != nil {
				return fmt.Errorf("artifact: %w", notFound(err))
			}
			if ap != projectID {
				return fmt.Errorf("%w: artifact belongs to another project", ErrConflict)
			}
			art = d.ArtifactID
		}
		if _, err := tx.ExecContext(ctx, `UPDATE environments SET desired_generation=?, desired_deployment_id=?, updated_at=? WHERE id=? AND desired_generation=?`,
			gen, d.ID, now, nd.EnvironmentID, gen-1); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO deployments(id,project_id,environment_id,generation,trigger,commit_sha,commit_message,commit_author,
			branch,delivery_id,rollback_of,status,artifact_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			d.ID, projectID, d.EnvironmentID, gen, d.Trigger, d.CommitSHA, d.CommitMessage, d.CommitAuthor, d.Branch, d.DeliveryID,
			d.RollbackOf, d.Status, art, d.CreatedBy, now, now); err != nil {
			return err
		}
		if err := addEvent(ctx, tx, d.ID, "", string(model.StatusReceived), "deployment requested ("+d.Trigger+")"); err != nil {
			return err
		}
		// Supersede older deployments that have not yet switched the router.
		rows, err := tx.QueryContext(ctx, `SELECT id,status FROM deployments WHERE environment_id=? AND generation<? AND status IN (`+
			quoteList(preSwitchStates())+`)`, nd.EnvironmentID, gen)
		if err != nil {
			return err
		}
		type old struct{ id, st string }
		var olds []old
		for rows.Next() {
			var o old
			if err := rows.Scan(&o.id, &o.st); err != nil {
				rows.Close()
				return err
			}
			olds = append(olds, o)
		}
		rows.Close()
		for _, o := range olds {
			if _, err := tx.ExecContext(ctx, `UPDATE deployments SET status=?, updated_at=?, finished_at=? WHERE id=?`,
				model.StatusSuperseded, now, now, o.id); err != nil {
				return err
			}
			if err := addEvent(ctx, tx, o.id, o.st, string(model.StatusSuperseded), fmt.Sprintf("superseded by generation %d", gen)); err != nil {
				return err
			}
		}
		out = d
		return nil
	})
	return out, err
}

func preSwitchStates() []string {
	var out []string
	for _, st := range model.Pipeline {
		if st == model.StatusRouterSwitched {
			break
		}
		out = append(out, string(st))
	}
	return append(out, string(model.StatusReady))
}

func quoteList(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = "'" + strings.ReplaceAll(x, "'", "") + "'"
	}
	return strings.Join(q, ",")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func addEvent(ctx context.Context, tx *sql.Tx, depID, from, to, msg string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO deployment_events(deployment_id,at,from_status,to_status,message) VALUES(?,?,?,?,?)`,
		depID, state.Now(), from, to, truncate(msg, 2000))
	return err
}

func (s *Store) GetDeployment(ctx context.Context, id string) (*Deployment, error) {
	return scanDep(s.DB.R().QueryRowContext(ctx, `SELECT `+depCols+` FROM deployments WHERE id=?`, id))
}

// ListDeployments returns deployments for a project, newest first.
func (s *Store) ListDeployments(ctx context.Context, projectID, envID string, limit int) ([]*Deployment, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `SELECT ` + depCols + ` FROM deployments WHERE project_id=?`
	args := []any{projectID}
	if envID != "" {
		q += ` AND environment_id=?`
		args = append(args, envID)
	}
	q += ` ORDER BY created_at DESC, generation DESC LIMIT ?`
	args = append(args, limit)
	return s.queryDeps(ctx, q, args...)
}

// DeploymentsInStatus returns deployments whose status is one of sts.
func (s *Store) DeploymentsInStatus(ctx context.Context, sts ...model.DeploymentStatus) ([]*Deployment, error) {
	xs := make([]string, len(sts))
	for i, st := range sts {
		xs[i] = string(st)
	}
	return s.queryDeps(ctx, `SELECT `+depCols+` FROM deployments WHERE status IN (`+quoteList(xs)+`) ORDER BY created_at`)
}

// RetainedDeployments returns successful deployments of an environment with
// artifacts, newest first (rollback candidates).
func (s *Store) RetainedDeployments(ctx context.Context, envID string, limit int) ([]*Deployment, error) {
	return s.queryDeps(ctx, `SELECT `+depCols+` FROM deployments WHERE environment_id=? AND artifact_id IS NOT NULL
		AND status IN ('SUCCEEDED','READY') ORDER BY generation DESC LIMIT ?`, envID, limit)
}

func (s *Store) queryDeps(ctx context.Context, q string, args ...any) ([]*Deployment, error) {
	rows, err := s.DB.R().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Deployment
	for rows.Next() {
		d, err := scanDep(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Transition moves a deployment from its current status to `to` using
// compare-and-swap; it fails with ErrConflict when the current status is not
// the expected one or the transition is illegal.
func (s *Store) Transition(ctx context.Context, id string, from, to model.DeploymentStatus, msg string) error {
	if !model.CanTransition(from, to) {
		return fmt.Errorf("%w: illegal transition %s -> %s", ErrConflict, from, to)
	}
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		return transitionTx(ctx, tx, id, from, to, msg, "")
	})
}

// Fail moves a non-terminal deployment to FAILED with an error message.
func (s *Store) Fail(ctx context.Context, id string, errMsg string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		var cur model.DeploymentStatus
		if err := tx.QueryRowContext(ctx, `SELECT status FROM deployments WHERE id=?`, id).Scan(&cur); err != nil {
			return notFound(err)
		}
		if cur.Terminal() {
			return nil
		}
		return transitionTx(ctx, tx, id, cur, model.StatusFailed, errMsg, errMsg)
	})
}

func transitionTx(ctx context.Context, tx *sql.Tx, id string, from, to model.DeploymentStatus, msg, errMsg string) error {
	now := state.Now()
	extra := ""
	args := []any{to, now}
	if to.Terminal() || to == model.StatusReady {
		extra += ", finished_at=?"
		args = append(args, now)
	}
	if from == model.StatusReceived {
		extra += ", started_at=?"
		args = append(args, now)
	}
	if errMsg != "" {
		extra += ", error=?"
		args = append(args, truncate(errMsg, 4000))
	}
	args = append(args, id, from)
	res, err := tx.ExecContext(ctx, `UPDATE deployments SET status=?, updated_at=?`+extra+` WHERE id=? AND status=?`, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: deployment %s not in %s", ErrConflict, id, from)
	}
	return addEvent(ctx, tx, id, string(from), string(to), msg)
}

// DeploymentPatch updates build metadata fields.
type DeploymentPatch struct {
	TrustClass      *string
	RuntimeClass    *string
	BuildStrategy   *string
	BuildInputs     any
	ConfigSnapshot  any
	ArtifactID      *string
	DecisionReasons []string
	CommitSHA       *string
	CommitMessage   *string
}

func (s *Store) PatchDeployment(ctx context.Context, id string, p DeploymentPatch) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		sets := []string{"updated_at=?"}
		args := []any{state.Now()}
		add := func(c string, v any) { sets = append(sets, c+"=?"); args = append(args, v) }
		if p.TrustClass != nil {
			add("trust_class", *p.TrustClass)
		}
		if p.RuntimeClass != nil {
			add("runtime_class", *p.RuntimeClass)
		}
		if p.BuildStrategy != nil {
			add("build_strategy", *p.BuildStrategy)
		}
		if p.BuildInputs != nil {
			b, _ := json.Marshal(p.BuildInputs)
			add("build_inputs", string(b))
		}
		if p.ConfigSnapshot != nil {
			b, _ := json.Marshal(p.ConfigSnapshot)
			add("config_snapshot", string(b))
		}
		if p.ArtifactID != nil {
			add("artifact_id", *p.ArtifactID)
		}
		if p.DecisionReasons != nil {
			b, _ := json.Marshal(p.DecisionReasons)
			add("decision_reasons", string(b))
		}
		if p.CommitSHA != nil {
			add("commit_sha", *p.CommitSHA)
		}
		if p.CommitMessage != nil {
			add("commit_message", truncate(*p.CommitMessage, 1000))
		}
		args = append(args, id)
		_, err := tx.ExecContext(ctx, `UPDATE deployments SET `+strings.Join(sets, ",")+` WHERE id=?`, args...)
		return err
	})
}

type DeploymentEvent struct {
	ID      int64  `json:"id"`
	At      string `json:"at"`
	From    string `json:"from"`
	To      string `json:"to"`
	Message string `json:"message"`
}

func (s *Store) DeploymentEvents(ctx context.Context, depID string) ([]DeploymentEvent, error) {
	rows, err := s.DB.R().QueryContext(ctx, `SELECT id,at,from_status,to_status,message FROM deployment_events WHERE deployment_id=? ORDER BY id`, depID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeploymentEvent
	for rows.Next() {
		var e DeploymentEvent
		if err := rows.Scan(&e.ID, &e.At, &e.From, &e.To, &e.Message); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Logs

type LogLine struct {
	ID     int64  `json:"id"`
	Stream string `json:"stream"`
	At     string `json:"at"`
	Line   string `json:"line"`
}

// MaxLogLinesPerDeployment bounds log storage per deployment.
const MaxLogLinesPerDeployment = 20000

func (s *Store) AppendLogs(ctx context.Context, depID, stream string, lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM deployment_logs WHERE deployment_id=?`, depID).Scan(&n); err != nil {
			return err
		}
		now := state.Now()
		for _, l := range lines {
			if n >= MaxLogLinesPerDeployment {
				_, err := tx.ExecContext(ctx, `INSERT INTO deployment_logs(deployment_id,stream,at,line) VALUES(?,?,?,?)`, depID, "system", now, "[log limit reached; further output dropped]")
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO deployment_logs(deployment_id,stream,at,line) VALUES(?,?,?,?)`, depID, stream, now, truncate(l, 8192)); err != nil {
				return err
			}
			n++
		}
		return nil
	})
}

func (s *Store) Logs(ctx context.Context, depID string, afterID int64, limit int) ([]LogLine, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	rows, err := s.DB.R().QueryContext(ctx, `SELECT id,stream,at,line FROM deployment_logs WHERE deployment_id=? AND id>? ORDER BY id LIMIT ?`, depID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogLine
	for rows.Next() {
		var l LogLine
		if err := rows.Scan(&l.ID, &l.Stream, &l.At, &l.Line); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// Artifacts

type Artifact struct {
	ID         string          `json:"id"`
	ProjectID  string          `json:"project_id"`
	Kind       string          `json:"kind"`
	Digest     string          `json:"digest"`
	ImageRef   string          `json:"image_ref"`
	SizeBytes  int64           `json:"size_bytes"`
	Config     json.RawMessage `json:"config"`
	SBOMDigest string          `json:"sbom_digest"`
	Provenance json.RawMessage `json:"provenance"`
	CreatedAt  string          `json:"created_at"`
}

// UpsertArtifact records an artifact (idempotent on project+digest).
func (s *Store) UpsertArtifact(ctx context.Context, a *Artifact) (*Artifact, error) {
	err := s.DB.Tx(ctx, func(tx *sql.Tx) error {
		var existing string
		err := tx.QueryRowContext(ctx, `SELECT id FROM artifacts WHERE project_id=? AND digest=?`, a.ProjectID, a.Digest).Scan(&existing)
		if err == nil {
			a.ID = existing
			return nil
		}
		if err != sql.ErrNoRows {
			return err
		}
		if a.ID == "" {
			a.ID = ids.New("art")
		}
		a.CreatedAt = state.Now()
		if len(a.Config) == 0 {
			a.Config = json.RawMessage("{}")
		}
		if len(a.Provenance) == 0 {
			a.Provenance = json.RawMessage("{}")
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO artifacts(id,project_id,kind,digest,image_ref,size_bytes,config,sbom_digest,provenance,created_at)
			VALUES(?,?,?,?,?,?,?,?,?,?)`, a.ID, a.ProjectID, a.Kind, a.Digest, a.ImageRef, a.SizeBytes, string(a.Config), a.SBOMDigest, string(a.Provenance), a.CreatedAt)
		return err
	})
	return a, err
}

func (s *Store) GetArtifact(ctx context.Context, id string) (*Artifact, error) {
	var a Artifact
	var cfg, prov string
	err := s.DB.R().QueryRowContext(ctx, `SELECT id,project_id,kind,digest,image_ref,size_bytes,config,sbom_digest,provenance,created_at FROM artifacts WHERE id=?`, id).
		Scan(&a.ID, &a.ProjectID, &a.Kind, &a.Digest, &a.ImageRef, &a.SizeBytes, &cfg, &a.SBOMDigest, &prov, &a.CreatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	a.Config, a.Provenance = json.RawMessage(cfg), json.RawMessage(prov)
	return &a, nil
}

// UnreferencedArtifacts returns artifacts not referenced by the newest
// `keep` successful deployments of any environment nor by any in-flight
// deployment (garbage-collection candidates).
func (s *Store) UnreferencedArtifacts(ctx context.Context, projectID string, keep int) ([]*Artifact, error) {
	rows, err := s.DB.R().QueryContext(ctx, `SELECT a.id FROM artifacts a WHERE a.project_id=? AND a.id NOT IN (
		SELECT artifact_id FROM (
			SELECT artifact_id, ROW_NUMBER() OVER (PARTITION BY environment_id ORDER BY generation DESC) rn
			FROM deployments WHERE project_id=? AND artifact_id IS NOT NULL AND status IN ('SUCCEEDED','READY')
		) WHERE rn<=?
		UNION SELECT artifact_id FROM deployments WHERE project_id=? AND artifact_id IS NOT NULL AND status NOT IN ('SUCCEEDED','READY','FAILED','SUPERSEDED','CANCELLED')
		UNION SELECT d.artifact_id FROM environments e JOIN deployments d ON d.id=e.current_deployment_id WHERE e.project_id=? AND d.artifact_id IS NOT NULL
	)`, projectID, projectID, keep, projectID, projectID)
	if err != nil {
		return nil, err
	}
	var idsOut []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		idsOut = append(idsOut, id)
	}
	rows.Close()
	var out []*Artifact
	for _, id := range idsOut {
		a, err := s.GetArtifact(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// DeleteArtifact removes an artifact row when no deployment references it.
func (s *Store) DeleteArtifact(ctx context.Context, id string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM deployments WHERE artifact_id=? AND status NOT IN ('FAILED','SUPERSEDED','CANCELLED')`, id).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			// Keep lineage; only null out references from dead deployments.
			return ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `UPDATE deployments SET artifact_id=NULL WHERE artifact_id=?`, id); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM artifacts WHERE id=?`, id)
		return err
	})
}
