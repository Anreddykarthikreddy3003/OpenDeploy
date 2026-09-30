package platform

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/cronexpr"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/policy"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/runtime"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/secrets"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// RunCron launches due cron jobs for every environment's current deployment
// as one-off workloads (same image, secrets and isolation as the app) and
// cleans up finished runs. Called once per minute by the reconciler.
func (p *Platform) RunCron(ctx context.Context, now time.Time) error {
	now = now.UTC().Truncate(time.Minute)
	envs, err := p.Store.ActiveEnvironments(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, env := range envs {
		if env.Status != "active" || env.CurrentDeploymentID == "" || env.Kind == "preview" {
			continue
		}
		d, err := p.Store.GetDeployment(ctx, env.CurrentDeploymentID)
		if err != nil {
			continue
		}
		s, err := p.snapshot(d)
		if err != nil || len(s.Config.Cron) == 0 {
			p.reapCron(ctx, env.ID)
			continue
		}
		for _, job := range s.Config.Cron {
			sched, err := cronexpr.Parse(job.Schedule)
			if err != nil || !sched.Matches(now) {
				continue
			}
			if err := p.startCronRun(ctx, env, d, s, job, now); err != nil {
				errs = append(errs, fmt.Errorf("cron %s/%s: %w", env.ID, job.Name, err))
			}
		}
		p.reapCron(ctx, env.ID)
	}
	return errors.Join(errs...)
}

func (p *Platform) startCronRun(ctx context.Context, env *store.Environment, d *store.Deployment, s *Snapshot, job policy.CronJob, at time.Time) error {
	svc := "cron-" + job.Name
	// Skip if the previous run of this job is still going (no overlap).
	ws, _ := p.Store.WorkloadsForEnvironment(ctx, env.ID)
	for _, w := range ws {
		if w.ServiceName == svc && (w.State == "running" || w.State == "creating") {
			if rw, err := p.Runtime.Inspect(ctx, w.ID); err == nil && rw.State == "running" {
				p.Log.Info("cron run skipped: previous run still active", "env", env.ID, "job", job.Name)
				return nil
			}
		}
	}
	proj, err := p.Store.GetProject(ctx, env.ProjectID)
	if err != nil {
		return err
	}
	art, err := p.Store.GetArtifact(ctx, d.ArtifactID)
	if err != nil || art.Kind != "oci" {
		return errors.New("cron requires an OCI image artifact")
	}
	// Replica encodes the scheduled minute so each run has a stable identity
	// (idempotent if the reconciler runs twice in the same minute).
	w, err := p.Store.EnsureWorkload(ctx, d.ID, env.ID, svc, int(at.Unix()/60), d.RuntimeClass)
	if err != nil {
		return err
	}
	if w.State != "creating" {
		return nil // already launched for this minute
	}
	var resolved map[string]string
	if p.Secrets != nil {
		r, err := p.Secrets.Resolve(ctx, secrets.ResolveReq{ProjectID: proj.ID, EnvironmentID: env.ID, EnvKind: env.Kind, TrustClass: d.TrustClass, Purpose: "runtime"})
		if err != nil {
			return err
		}
		resolved = r.Values
	}
	mem, _ := policy.ParseMemory(s.Config.Resources.Memory)
	envVars := map[string]string{"OPENDEPLOY": "1", "OPENDEPLOY_CRON_JOB": job.Name, "OPENDEPLOY_DEPLOYMENT": d.ID}
	if s.Config.Runtime.SecretEnv == nil || *s.Config.Runtime.SecretEnv {
		for k, v := range resolved {
			if runtimeEnvNameOK(k) {
				envVars[k] = v
			}
		}
	}
	mounts, err := p.volumeMounts(ctx, proj, env, &s.Config)
	if err != nil {
		return err
	}
	spec := runtime.Spec{ID: w.ID, ProjectID: proj.ID, EnvironmentID: env.ID, DeploymentID: d.ID, Service: svc, Kind: "app", Image: p.imageRef(art),
		Runtime: d.RuntimeClass, Command: job.Command, Env: envVars, SecretFiles: resolved, MemoryBytes: mem, CPU: s.Config.Resources.CPU,
		PIDs: s.Config.Resources.PIDs, ReadOnlyRoot: s.Config.Runtime.ReadOnlyRoot == nil || *s.Config.Runtime.ReadOnlyRoot,
		Tmpfs: s.Plan.Tmpfs, Volumes: mounts, Network: env.ID, Capabilities: decisionCaps(s)}
	rw, err := p.Runtime.Start(ctx, spec)
	if err != nil {
		_ = p.Store.UpdateWorkload(ctx, w.ID, "failed", "", "")
		return err
	}
	p.Log.Info("cron run started", "env", env.ID, "job", job.Name, "workload", w.ID)
	return p.Store.UpdateWorkload(ctx, w.ID, "running", rw.RuntimeID, "")
}

// reapCron removes finished cron runs, keeping the row (and last output)
// for inspection.
func (p *Platform) reapCron(ctx context.Context, envID string) {
	ws, err := p.Store.WorkloadsForEnvironment(ctx, envID)
	if err != nil {
		return
	}
	for _, w := range ws {
		if !strings.HasPrefix(w.ServiceName, "cron-") || (w.State != "running" && w.State != "creating") {
			continue
		}
		rw, err := p.Runtime.Inspect(ctx, w.ID)
		if errors.Is(err, runtime.ErrNotFound) || (err != nil && isNotFoundIPC(err)) {
			_ = p.Store.UpdateWorkload(ctx, w.ID, "stopped", "", "")
			continue
		}
		if err != nil || rw.State == "running" {
			continue
		}
		st := "stopped"
		if rw.ExitCode != 0 {
			st = "failed"
		}
		_ = p.Store.UpdateWorkload(ctx, w.ID, st, "", "")
		_ = p.Runtime.Remove(ctx, w.ID)
	}
}

func isNotFoundIPC(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not_found")
}
