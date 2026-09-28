package platform

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/artifact"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/model"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/router"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/runtime"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

func (p *Platform) reconcileLoop(ctx context.Context) {
	// Boot: restore production first, then staging/previews (§18.1 step 5).
	if err := p.ReconcileOnce(ctx); err != nil {
		p.Log.Warn("initial reconcile", "err", err)
	}
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	gc := time.NewTicker(time.Hour)
	defer gc.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := p.ReconcileOnce(ctx); err != nil {
				p.Log.Warn("reconcile", "err", err)
			}
		case <-gc.C:
			p.garbageCollect(ctx)
			_ = p.Store.PurgeSessions(ctx)
		}
	}
}

// ReconcileOnce performs one idempotent, generation-aware pass.
func (p *Platform) ReconcileOnce(ctx context.Context) error {
	if d := p.Store.DB.Degraded(); d != "" {
		return fmt.Errorf("degraded read-only mode: %s", d)
	}
	var errs []error
	if err := p.recoverPromotions(ctx); err != nil {
		errs = append(errs, fmt.Errorf("promotions: %w", err))
	}
	if err := p.recoverDeployments(ctx); err != nil {
		errs = append(errs, fmt.Errorf("deployments: %w", err))
	}
	if err := p.restoreDesiredState(ctx); err != nil {
		errs = append(errs, fmt.Errorf("desired state: %w", err))
	}
	if err := p.syncRoutes(ctx); err != nil {
		errs = append(errs, fmt.Errorf("routes: %w", err))
	}
	if err := p.removeOrphans(ctx); err != nil {
		errs = append(errs, fmt.Errorf("orphans: %w", err))
	}
	return errors.Join(errs...)
}

// jobActive reports whether a live worker holds the job with this key.
// jobActive reports the state of the newest job whose idempotency key starts
// with prefix and whether a live worker holds it (or it is queued).
func (p *Platform) jobActive(ctx context.Context, prefix string) (st string, active bool) {
	rows, err := p.Store.DB.R().QueryContext(ctx, `SELECT state, locked_until FROM jobs WHERE idempotency_key=? OR idempotency_key LIKE ? ESCAPE '\' ORDER BY created_at DESC`,
		prefix, strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(prefix)+":%")
	if err != nil {
		return "", false
	}
	defer rows.Close()
	now := state.Now()
	first := true
	for rows.Next() {
		var s, locked string
		if rows.Scan(&s, &locked) != nil {
			continue
		}
		if first {
			st, first = s, false
		}
		if s == "queued" || (s == "running" && locked > now) {
			return s, true
		}
	}
	return st, false
}

func (p *Platform) recoverPromotions(ctx context.Context) error {
	intents, err := p.Store.InflightPromotions(ctx)
	if err != nil {
		return err
	}
	for _, pi := range intents {
		if _, active := p.jobActive(ctx, "deploy:"+pi.ToDeployment); active {
			continue
		}
		if _, active := p.jobActive(ctx, "promote:"+pi.ToDeployment); active {
			continue
		}
		p.Log.Warn("recovering interrupted promotion", "intent", pi.ID, "state", pi.State, "deployment", pi.ToDeployment)
		if err := p.recoverIntent(ctx, pi); err != nil {
			return err
		}
	}
	return nil
}

var inFlight = []model.DeploymentStatus{model.StatusReceived, model.StatusValidating, model.StatusFetching, model.StatusDetecting,
	model.StatusBuilding, model.StatusArtifactReady, model.StatusStartingCandidate, model.StatusHealthChecking}

// recoverDeployments resumes or fails deployments whose job is gone.
func (p *Platform) recoverDeployments(ctx context.Context) error {
	deps, err := p.Store.DeploymentsInStatus(ctx, inFlight...)
	if err != nil {
		return err
	}
	for _, d := range deps {
		st, active := p.jobActive(ctx, "deploy:"+d.ID)
		if active {
			continue
		}
		if st == "dead" || st == "failed" {
			p.failDeployment(ctx, d, errors.New("orchestration failed after repeated retries; see platform logs"))
			continue
		}
		if st == "" || st == "succeeded" {
			// Interrupted before completion (e.g. reboot): resumable because
			// every step is idempotent.
			if _, err := p.Store.Enqueue(ctx, JobDeploy, "deploy:"+d.ID+":resume:"+fmt.Sprint(time.Now().Unix()/60), deployPayload{DeploymentID: d.ID}, 8); err != nil {
				return err
			}
		}
	}
	return nil
}

// restoreDesiredState keeps current deployments' workloads running.
func (p *Platform) restoreDesiredState(ctx context.Context) error {
	envs, err := p.Store.ActiveEnvironments(ctx)
	if err != nil {
		return err
	}
	for _, env := range envs {
		if env.Status == "deleting" {
			_, _ = p.Store.Enqueue(ctx, JobEnvTeardown, "teardown:"+env.ID, map[string]string{"environment_id": env.ID}, 10)
			continue
		}
		if env.Status != "active" || env.CurrentDeploymentID == "" {
			continue
		}
		key := "env:" + env.ID
		ok, _, err := p.Store.BreakerAllow(ctx, key)
		if err != nil || !ok {
			continue
		}
		d, err := p.Store.GetDeployment(ctx, env.CurrentDeploymentID)
		if err != nil {
			continue
		}
		art, err := p.Store.GetArtifact(ctx, d.ArtifactID)
		if err != nil || art.Kind == "static" {
			continue
		}
		proj, err := p.Store.GetProject(ctx, env.ProjectID)
		if err != nil {
			continue
		}
		_, err = p.ensureDeploymentWorkloads(ctx, d, proj, env, false)
		_ = p.Store.BreakerRecord(ctx, key, err)
		if err != nil {
			p.Log.Warn("restore environment", "env", env.ID, "err", err)
		}
	}
	return nil
}

// syncRoutes re-applies the computed table when the edge drifted (e.g. new
// workload IPs after reboot). Only environments whose backends are running
// are changed; others keep last-known-good.
func (p *Platform) syncRoutes(ctx context.Context) error {
	want, err := p.routeTable(ctx, "", "")
	if err != nil {
		return err
	}
	cur, err := p.Router.Current(ctx)
	if err != nil {
		return err
	}
	if routeKey(want) == routeKey(cur.Table) {
		return nil
	}
	_, err = p.Router.Apply(ctx, want, nil)
	return err
}

func routeKey(t router.Table) string {
	parts := make([]string, 0, len(t.Routes))
	for _, r := range t.Routes {
		h := append([]string(nil), r.Hosts...)
		u := append([]string(nil), r.Upstreams...)
		sort.Strings(h)
		sort.Strings(u)
		auth := ""
		if r.BasicAuth != nil {
			auth = r.BasicAuth.User + ":" + r.BasicAuth.BcryptHash
		}
		parts = append(parts, strings.Join([]string{r.EnvironmentID, r.DeploymentID, r.Kind, r.TLS, r.StaticDigest, strings.Join(h, ","), strings.Join(u, ","), auth}, "|"))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

// removeOrphans stops managed workloads that no deployment wants.
func (p *Platform) removeOrphans(ctx context.Context) error {
	live, err := p.Runtime.List(ctx, runtimeListAll())
	if err != nil {
		return err
	}
	wanted := map[string]bool{}
	rows, err := p.Store.LiveWorkloads(ctx)
	if err != nil {
		return err
	}
	for _, w := range rows {
		wanted[w.ID] = true
	}
	envs, err := p.Store.ActiveEnvironments(ctx)
	if err != nil {
		return err
	}
	for _, e := range envs {
		svcs, _ := p.Store.ServicesForEnvironment(ctx, e.ID)
		for _, s := range svcs {
			wanted["wkl_"+strings.TrimPrefix(s.ID, "svc_")] = true
		}
	}
	for _, w := range live {
		if w.ID == "" || wanted[w.ID] {
			continue
		}
		// Grace period so a workload being created right now is not removed.
		if ts, err := time.Parse(time.RFC3339Nano, w.StartedAt); err == nil && time.Since(ts) < 2*time.Minute {
			continue
		}
		p.Log.Info("removing orphan workload", "workload", w.ID)
		_ = p.Runtime.Stop(ctx, w.ID, 10*time.Second)
		_ = p.Runtime.Remove(ctx, w.ID)
	}
	return nil
}

// garbageCollect removes artifacts outside retention (keep_deployments).
func (p *Platform) garbageCollect(ctx context.Context) {
	projects, err := p.Store.ListProjects(ctx)
	if err != nil {
		return
	}
	var keepImg, keepStatic []string
	for _, pr := range projects {
		keep := 5
		arts, err := p.Store.UnreferencedArtifacts(ctx, pr.ID, keep)
		if err != nil {
			continue
		}
		for _, a := range arts {
			_ = p.Store.DeleteArtifact(ctx, a.ID)
		}
	}
	rows, err := p.Store.DB.R().QueryContext(ctx, `SELECT kind, digest FROM artifacts`)
	if err != nil {
		return
	}
	for rows.Next() {
		var k, d string
		if rows.Scan(&k, &d) == nil {
			if k == "static" {
				keepStatic = append(keepStatic, d)
			} else {
				keepImg = append(keepImg, d)
			}
		}
	}
	rows.Close()
	if p.Artifacts != nil {
		res, err := p.Artifacts.GC(ctx, artifact.GCReq{KeepImages: keepImg, KeepStatic: keepStatic})
		if err == nil && (res.RemovedBlobs > 0 || res.RemovedStatic > 0) {
			p.Log.Info("artifact gc", "blobs", res.RemovedBlobs, "static", res.RemovedStatic, "freed", res.FreedBytes)
		}
	}
}

// teardownEnvironment removes a deleted environment's runtime resources.
func (p *Platform) teardownEnvironment(ctx context.Context, envID string) error {
	env, err := p.Store.GetEnvironment(ctx, envID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	ws, err := p.Store.WorkloadsForEnvironment(ctx, envID)
	if err != nil {
		return err
	}
	for _, w := range ws {
		_ = p.Runtime.Stop(ctx, w.ID, 10*time.Second)
		_ = p.Runtime.Remove(ctx, w.ID)
		_ = p.Store.UpdateWorkload(ctx, w.ID, "stopped", "", "")
	}
	svcs, _ := p.Store.ServicesForEnvironment(ctx, envID)
	for _, s := range svcs {
		wid := "wkl_" + strings.TrimPrefix(s.ID, "svc_")
		_ = p.Runtime.Stop(ctx, wid, 10*time.Second)
		_ = p.Runtime.Remove(ctx, wid)
		_ = p.Store.SetServiceDesired(ctx, s.ID, s.ProjectID, "deleted")
	}
	if err := p.Store.SetEnvironmentStatus(ctx, envID, "deleted"); err != nil {
		return err
	}
	if err := p.reapplyRoutes(ctx); err != nil {
		return err
	}
	_ = p.Egress.Remove(ctx, envID)
	if err := p.Runtime.RemoveNetwork(ctx, envID); err != nil {
		p.Log.Warn("remove network", "env", envID, "err", err)
	}
	p.Log.Info("environment torn down", "env", env.ID, "kind", env.Kind)
	return nil
}

// deleteProjectResources tears down every environment of a deleted project.
func (p *Platform) deleteProjectResources(ctx context.Context, projectID string) error {
	envs, err := p.Store.DB.R().QueryContext(ctx, `SELECT id FROM environments WHERE project_id=? AND status!='deleted'`, projectID)
	if err != nil {
		return err
	}
	var ids []string
	for envs.Next() {
		var id string
		if envs.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	envs.Close()
	for _, id := range ids {
		if err := p.teardownEnvironment(ctx, id); err != nil {
			return err
		}
	}
	_ = p.Store.TombstoneProjectDomains(ctx, projectID)
	return p.reapplyRoutes(ctx)
}

func runtimeListAll() runtime.ListReq { return runtime.ListReq{} }
