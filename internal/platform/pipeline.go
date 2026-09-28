package platform

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/build/builder"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/build/detect"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/git/github"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/model"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/policy"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/secrets"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/trust"
)

// Snapshot is stored in deployments.config_snapshot: everything needed to
// (re)start this deployment without the source repository (rollback).
type Snapshot struct {
	Config   policy.Config   `json:"config"`
	Plan     detect.Plan     `json:"plan"`
	Decision *trust.Decision `json:"decision,omitempty"`
}

// BuildInputs is stored in deployments.build_inputs (provenance).
type BuildInputs struct {
	CommitSHA  string   `json:"commit_sha"`
	Executor   string   `json:"executor"`
	Strategy   string   `json:"strategy"`
	Dockerfile string   `json:"dockerfile,omitempty"`
	DurationMS int64    `json:"duration_ms"`
	Leaked     []string `json:"leaked_secrets,omitempty"`
	Source     string   `json:"source"`
}

type deployPayload struct {
	DeploymentID string `json:"deployment_id"`
}

// EnqueueDeployTx enqueues the pipeline job for a deployment.
func EnqueueDeployTx(ctx context.Context, tx *sql.Tx, depID string) error {
	_, _, err := store.EnqueueTx(ctx, tx, JobDeploy, "deploy:"+depID, deployPayload{DeploymentID: depID}, 8)
	return err
}

func (p *Platform) dispatch(ctx context.Context, job *store.Job) error {
	switch job.Kind {
	case JobDeploy, JobPromote:
		var pl deployPayload
		if err := json.Unmarshal(job.Payload, &pl); err != nil {
			return &PermanentError{err}
		}
		if job.Kind == JobPromote {
			return p.runManualPromote(ctx, pl.DeploymentID)
		}
		return p.runDeploy(ctx, pl.DeploymentID)
	case JobEnvTeardown:
		var pl struct {
			EnvironmentID string `json:"environment_id"`
		}
		if err := json.Unmarshal(job.Payload, &pl); err != nil {
			return &PermanentError{err}
		}
		return p.teardownEnvironment(ctx, pl.EnvironmentID)
	case JobProjectDelete:
		var pl struct {
			ProjectID string `json:"project_id"`
		}
		if err := json.Unmarshal(job.Payload, &pl); err != nil {
			return &PermanentError{err}
		}
		return p.deleteProjectResources(ctx, pl.ProjectID)
	case JobDomainCheck:
		var pl struct {
			DomainID string `json:"domain_id"`
		}
		if err := json.Unmarshal(job.Payload, &pl); err != nil {
			return &PermanentError{err}
		}
		return p.checkDomainTLS(ctx, pl.DomainID)
	case JobBackup:
		return p.runBackupJob(ctx, job)
	}
	return &PermanentError{fmt.Errorf("unknown job kind %q", job.Kind)}
}

func isTransient(err error) bool {
	return errors.Is(err, ErrRetry) || ipc.IsCode(err, ipc.CodeUnavailable) || errors.Is(err, store.ErrPromotionInFlight) ||
		errors.Is(err, state.ErrDegraded) || errors.Is(err, context.Canceled)
}

func (p *Platform) logf(ctx context.Context, depID, stream, f string, a ...any) {
	line := fmt.Sprintf(f, a...)
	_ = p.Store.AppendLogs(ctx, depID, stream, []string{line})
	p.Events.Publish(Event{Topic: "deployment:" + depID, Type: "log", Data: map[string]string{"stream": stream, "line": line}})
}

func (p *Platform) transition(ctx context.Context, d *store.Deployment, to model.DeploymentStatus, msg string) error {
	if err := p.Store.Transition(ctx, d.ID, d.Status, to, msg); err != nil {
		return err
	}
	p.Events.Publish(Event{Topic: "deployment:" + d.ID, Type: "status", Data: map[string]string{"from": string(d.Status), "to": string(to), "message": msg}})
	p.Events.Publish(Event{Topic: "project:" + d.ProjectID, Type: "status", Data: map[string]string{"deployment_id": d.ID, "status": string(to)}})
	d.Status = to
	return nil
}

func (p *Platform) snapshot(d *store.Deployment) (*Snapshot, error) {
	var s Snapshot
	if len(d.ConfigSnapshot) == 0 || string(d.ConfigSnapshot) == "{}" {
		return nil, errors.New("deployment has no configuration snapshot")
	}
	if err := json.Unmarshal(d.ConfigSnapshot, &s); err != nil {
		return nil, err
	}
	s.Config.ApplyDefaults()
	return &s, nil
}

// runDeploy advances a deployment through the state machine. Each step is
// idempotent; the loop re-reads state so a crash at any point resumes.
func (p *Platform) runDeploy(ctx context.Context, depID string) error {
	for step := 0; step < 64; step++ {
		d, err := p.Store.GetDeployment(ctx, depID)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.Status.Terminal() || d.Status == model.StatusReady {
			return nil
		}
		env, err := p.Store.GetEnvironment(ctx, d.EnvironmentID)
		if err != nil {
			return err
		}
		if env.DesiredGeneration != d.Generation && model.CanTransition(d.Status, model.StatusSuperseded) {
			p.supersede(ctx, d, env.DesiredGeneration)
			return nil
		}
		proj, err := p.Store.GetProject(ctx, d.ProjectID)
		if err != nil {
			_ = p.Store.Fail(ctx, d.ID, "project no longer exists")
			return nil
		}
		switch d.Status {
		case model.StatusReceived:
			err = p.transition(ctx, d, model.StatusValidating, "validating request and trust policy")
		case model.StatusValidating:
			err = p.validate(ctx, d, proj, env)
		case model.StatusFetching, model.StatusDetecting, model.StatusBuilding:
			err = p.build(ctx, d, proj, env)
		case model.StatusArtifactReady:
			err = p.prepareCandidate(ctx, d, env)
		case model.StatusStartingCandidate:
			err = p.startCandidate(ctx, d, proj, env)
		case model.StatusHealthChecking:
			err = p.checkHealth(ctx, d, env)
		case model.StatusPromotionIntent, model.StatusRouterSwitched, model.StatusCommittingPointer, model.StatusDrainingOld:
			err = p.resumePromotion(ctx, d)
		default:
			return nil
		}
		if err != nil {
			if isTransient(err) {
				return err
			}
			if errors.Is(err, store.ErrSuperseded) {
				p.cleanupCandidate(context.Background(), d.ID)
				return nil
			}
			if errors.Is(err, store.ErrConflict) {
				// Another actor moved the deployment; re-read and continue.
				continue
			}
			p.failDeployment(context.Background(), d, err)
			return nil
		}
	}
	return fmt.Errorf("%w: deployment %s did not settle", ErrRetry, depID)
}

func (p *Platform) validate(ctx context.Context, d *store.Deployment, proj *store.Project, env *store.Environment) error {
	var cfg *policy.Config
	if d.ArtifactID != "" {
		s, err := p.snapshot(d)
		if err != nil {
			return err
		}
		cfg = &s.Config
	}
	dec, err := p.decide(ctx, proj, env, cfg)
	if err != nil {
		p.auditDeploy(ctx, d, "deployment.validate", audit.Denied, map[string]string{"reason": err.Error()})
		return fmt.Errorf("trust policy: %w", err)
	}
	tc, rc := string(dec.Class), string(dec.Runtime)
	if err := p.Store.PatchDeployment(ctx, d.ID, store.DeploymentPatch{TrustClass: &tc, RuntimeClass: &rc, DecisionReasons: dec.Reasons}); err != nil {
		return err
	}
	p.logf(ctx, d.ID, "system", "trust class %s, runtime %s, build runtime %s", dec.Class, dec.Runtime, dec.BuildRuntime)
	for _, r := range dec.Reasons {
		p.logf(ctx, d.ID, "system", "policy: %s", r)
	}
	if d.ArtifactID != "" {
		return p.transition(ctx, d, model.StatusArtifactReady, "using retained artifact (no rebuild)")
	}
	return p.transition(ctx, d, model.StatusFetching, "fetching source")
}

func (p *Platform) sourceFor(ctx context.Context, d *store.Deployment, proj *store.Project) (builder.SourceSpec, error) {
	if strings.HasPrefix(d.CommitSHA, "archive-") || (proj.CloneURL == "" && proj.GitConnectionID == "") {
		return builder.SourceSpec{Kind: "archive"}, nil
	}
	src := builder.SourceSpec{Kind: "git", CloneURL: proj.CloneURL, SHA: d.CommitSHA}
	if u, err := url.Parse(proj.CloneURL); err == nil {
		src.AllowedHosts = []string{u.Hostname()}
	}
	if proj.GitConnectionID == "" {
		if src.SHA == "" {
			src.Ref = firstNonEmpty(d.Branch, proj.ProductionBranch)
		}
		return src, nil
	}
	conn, err := p.Store.GetGitConnection(ctx, proj.GitConnectionID)
	if err != nil {
		return src, err
	}
	if conn.Status != "active" {
		return src, fmt.Errorf("GitHub access for this repository is %s; new builds are blocked", conn.Status)
	}
	app, err := p.GitHub.App(ctx)
	if err != nil {
		return src, err
	}
	tok, err := app.InstallationToken(ctx, conn.InstallationID, []int64{proj.RepoID}, github.DefaultPermissions)
	if err != nil {
		if github.IsNotFound(err) {
			return src, fmt.Errorf("GitHub installation no longer grants access to %s (revoked); existing deployments keep running", proj.RepoFullName)
		}
		return src, fmt.Errorf("%w: github token: %v", ErrRetry, err)
	}
	src.Token = tok.Token
	if src.SHA == "" {
		br, err := app.GetBranch(ctx, conn.InstallationID, proj.RepoID, firstNonEmpty(d.Branch, proj.ProductionBranch))
		if err != nil {
			return src, fmt.Errorf("resolve branch head: %w", err)
		}
		src.SHA = br.Commit.SHA
		msg := br.Commit.Commit.Message
		_ = p.Store.PatchDeployment(ctx, d.ID, store.DeploymentPatch{CommitSHA: &src.SHA, CommitMessage: &msg})
	}
	return src, nil
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

func (p *Platform) build(ctx context.Context, d *store.Deployment, proj *store.Project, env *store.Environment) error {
	src, err := p.sourceFor(ctx, d, proj)
	if err != nil {
		return err
	}
	buildSecrets := map[string]string{}
	if p.Secrets != nil {
		res, err := p.Secrets.Resolve(ctx, secrets.ResolveReq{ProjectID: proj.ID, EnvironmentID: env.ID, EnvKind: env.Kind,
			TrustClass: d.TrustClass, Purpose: "build", FromFork: env.PRFromFork})
		if err != nil {
			return err
		}
		buildSecrets = res.Values
	}
	buildRuntime := "runc"
	if d.TrustClass == string(trust.Untrusted) {
		buildRuntime = d.RuntimeClass
	}
	req := builder.Req{DeploymentID: d.ID, ProjectID: proj.ID, Environment: env.Kind, Source: src, RootDir: proj.RootDir,
		ConfigOverride: proj.ConfigOverride, Class: d.TrustClass, BuildRuntime: buildRuntime, BuildSecrets: buildSecrets,
		Overrides: detect.Overrides{Strategy: proj.BuildOverrides.Strategy, BuildCommand: proj.BuildOverrides.BuildCommand,
			StartCommand: proj.BuildOverrides.StartCommand, OutputDir: proj.BuildOverrides.OutputDir, Port: proj.BuildOverrides.Port},
		BuildArgs: proj.BuildOverrides.Env}
	if _, err := p.Builder.Start(ctx, req); err != nil {
		return err
	}
	var after int64
	phaseStatus := map[string]model.DeploymentStatus{"fetching": model.StatusFetching, "detecting": model.StatusDetecting,
		"building": model.StatusBuilding, "ingesting": model.StatusBuilding}
	for {
		st, err := p.Builder.Status(ctx, d.ID, after)
		if ipc.IsCode(err, ipc.CodeNotFound) {
			// builderd restarted and lost the job: start it again (same SHA).
			if _, err := p.Builder.Start(ctx, req); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if len(st.Lines) > 0 {
			lines := make([]string, len(st.Lines))
			for i, l := range st.Lines {
				lines[i] = l.Text
				p.Events.Publish(Event{Topic: "deployment:" + d.ID, Type: "log", Data: map[string]string{"stream": "build", "line": l.Text}})
			}
			if err := p.Store.AppendLogs(ctx, d.ID, "build", lines); err != nil {
				return err
			}
			after = st.Lines[len(st.Lines)-1].Seq
		}
		if want, ok := phaseStatus[st.Phase]; ok && want != d.Status && model.CanTransition(d.Status, want) {
			if err := p.transition(ctx, d, want, st.Phase); err != nil {
				return err
			}
		}
		switch st.State {
		case "succeeded":
			if st.NextSeq > after {
				continue // drain remaining log lines first
			}
			_ = p.Builder.Forget(ctx, d.ID)
			return p.recordBuild(ctx, d, proj, env, st.Result)
		case "failed", "cancelled":
			if st.NextSeq > after {
				continue
			}
			_ = p.Builder.Forget(ctx, d.ID)
			return fmt.Errorf("build %s: %s", st.State, st.Error)
		}
		// Supersede in-flight builds promptly.
		if e, err := p.Store.GetEnvironment(ctx, env.ID); err == nil && e.DesiredGeneration != d.Generation {
			_ = p.Builder.Cancel(ctx, d.ID)
			return nil // loop in runDeploy observes supersession
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func (p *Platform) recordBuild(ctx context.Context, d *store.Deployment, proj *store.Project, env *store.Environment, res *builder.Result) error {
	if res == nil {
		return errors.New("builder returned no result")
	}
	info, _ := json.Marshal(res.Artifact.Info)
	art, err := p.Store.UpsertArtifact(ctx, &store.Artifact{ProjectID: proj.ID, Kind: res.Artifact.Kind, Digest: res.Artifact.Digest,
		ImageRef: res.Artifact.ImageRef, SizeBytes: res.Artifact.Size, Config: info,
		Provenance: mustJSON(map[string]any{"commit": res.Commit.SHA, "executor": res.Executor, "strategy": res.Plan.Strategy, "deployment": d.ID})})
	if err != nil {
		return err
	}
	// Re-decide with the repository configuration now known: the repository
	// may lower its trust, request a sandbox or request capabilities.
	cfg := res.Config
	dec, err := p.decide(ctx, proj, env, &cfg)
	if err != nil {
		return fmt.Errorf("trust policy (repository configuration): %w", err)
	}
	snap := Snapshot{Config: cfg, Plan: res.Plan, Decision: dec}
	inputs := BuildInputs{CommitSHA: res.Commit.SHA, Executor: res.Executor, Strategy: res.Plan.Strategy, Dockerfile: res.Dockerfile,
		DurationMS: res.DurationMS, Leaked: res.LeakedSecrets, Source: "git"}
	tc, rc, strat, aid := string(dec.Class), string(dec.Runtime), res.Plan.Strategy, art.ID
	patch := store.DeploymentPatch{ArtifactID: &aid, ConfigSnapshot: snap, BuildInputs: inputs, TrustClass: &tc, RuntimeClass: &rc,
		BuildStrategy: &strat, DecisionReasons: append(dec.Reasons, res.Plan.Reasons...)}
	if d.CommitSHA == "" && res.Commit.SHA != "" {
		patch.CommitSHA, patch.CommitMessage = &res.Commit.SHA, &res.Commit.Message
	}
	if err := p.Store.PatchDeployment(ctx, d.ID, patch); err != nil {
		return err
	}
	if len(res.LeakedSecrets) > 0 {
		p.logf(ctx, d.ID, "system", "WARNING: secret values %v appeared in build output; rotate them", res.LeakedSecrets)
	}
	p.auditDeploy(ctx, d, "deployment.build", audit.Success, map[string]string{"artifact_digest": res.Artifact.Digest, "commit": res.Commit.SHA, "trust_class": tc})
	return p.transition(ctx, d, model.StatusArtifactReady, "artifact "+res.Artifact.Digest)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (p *Platform) auditDeploy(ctx context.Context, d *store.Deployment, action, result string, details map[string]string) {
	if details == nil {
		details = map[string]string{}
	}
	details["deployment_id"] = d.ID
	details["generation"] = fmt.Sprint(d.Generation)
	_, _ = p.Audit.Append(ctx, audit.Event{ActorType: audit.ActorService, ActorID: identity.Platform, Action: action,
		ResourceType: "deployment", ResourceID: d.ID, ProjectID: d.ProjectID, Result: result, Details: details})
}

// prepareCandidate applies the stop-then-start policy when zero-downtime
// overlap is disabled or unaffordable (PRD §18.2), then moves on.
func (p *Platform) prepareCandidate(ctx context.Context, d *store.Deployment, env *store.Environment) error {
	s, err := p.snapshot(d)
	if err != nil {
		return err
	}
	zero := s.Config.Release.ZeroDowntime == nil || *s.Config.Release.ZeroDowntime
	if (!zero || p.Node.Profile == "tiny") && env.CurrentDeploymentID != "" && env.CurrentDeploymentID != d.ID && !s.Plan.StaticOutput {
		p.logf(ctx, d.ID, "system", "stop-then-start: stopping previous deployment before starting candidate (brief downtime)")
		p.stopDeploymentWorkloads(ctx, env.CurrentDeploymentID, false)
	}
	return p.transition(ctx, d, model.StatusStartingCandidate, "starting candidate")
}

func (p *Platform) failDeployment(ctx context.Context, d *store.Deployment, cause error) {
	msg := cause.Error()
	p.logf(ctx, d.ID, "system", "deployment failed: %s", msg)
	cur, err := p.Store.GetDeployment(ctx, d.ID)
	if err == nil && (cur.Status == model.StatusPromotionIntent) {
		if intents, err := p.Store.InflightPromotions(ctx); err == nil {
			for _, pi := range intents {
				if pi.ToDeployment == d.ID {
					_ = p.Store.AbortPromotion(ctx, pi.ID, msg, false)
				}
			}
		}
	}
	_ = p.Store.Fail(ctx, d.ID, msg)
	p.Events.Publish(Event{Topic: "deployment:" + d.ID, Type: "status", Data: map[string]string{"to": string(model.StatusFailed), "message": msg}})
	p.Events.Publish(Event{Topic: "project:" + d.ProjectID, Type: "status", Data: map[string]string{"deployment_id": d.ID, "status": string(model.StatusFailed)}})
	p.auditDeploy(ctx, d, "deployment.fail", audit.Failure, map[string]string{"reason": truncate(msg, 500)})
	env, err := p.Store.GetEnvironment(ctx, d.EnvironmentID)
	if err == nil && env.CurrentDeploymentID != d.ID {
		p.cleanupCandidate(ctx, d.ID)
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (p *Platform) supersede(ctx context.Context, d *store.Deployment, desired int64) {
	msg := fmt.Sprintf("generation %d superseded by desired generation %d", d.Generation, desired)
	if err := p.Store.Transition(ctx, d.ID, d.Status, model.StatusSuperseded, msg); err == nil {
		p.logf(ctx, d.ID, "system", "%s", msg)
		p.Events.Publish(Event{Topic: "deployment:" + d.ID, Type: "status", Data: map[string]string{"to": string(model.StatusSuperseded)}})
	}
	_ = p.Builder.Cancel(ctx, d.ID)
	p.cleanupCandidate(ctx, d.ID)
}

// CleanupCandidate stops and removes a cancelled deployment's workloads.
func (p *Platform) CleanupCandidate(depID string) { p.cleanupCandidate(context.Background(), depID) }

// cleanupCandidate stops and removes a non-current deployment's workloads.
func (p *Platform) cleanupCandidate(ctx context.Context, depID string) {
	p.stopDeploymentWorkloads(ctx, depID, true)
}

func (p *Platform) stopDeploymentWorkloads(ctx context.Context, depID string, remove bool) {
	ws, err := p.Store.WorkloadsForDeployment(ctx, depID)
	if err != nil {
		return
	}
	for _, w := range ws {
		if w.State == "stopped" && !remove {
			continue
		}
		_ = p.Runtime.Stop(ctx, w.ID, 20*time.Second)
		if remove {
			_ = p.Runtime.Remove(ctx, w.ID)
		}
		_ = p.Store.UpdateWorkload(ctx, w.ID, "stopped", "", "")
	}
}
