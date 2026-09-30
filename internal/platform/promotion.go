package platform

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/model"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/router"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// promote executes §11.3 steps 1-6 for a healthy candidate.
func (p *Platform) promote(ctx context.Context, d *store.Deployment) error {
	// Steps 1-2: CAS on desired generation + persist intent (promotion lock).
	pi, err := p.Store.BeginPromotion(ctx, d.ID, "")
	if err != nil {
		if errors.Is(err, store.ErrSuperseded) {
			p.logf(ctx, d.ID, "system", "not promoted: a newer desired generation exists")
			p.cleanupCandidate(ctx, d.ID)
			return nil
		}
		return err
	}
	d.Status = model.StatusPromotionIntent
	p.Events.Publish(Event{Topic: "deployment:" + d.ID, Type: "status", Data: map[string]string{"to": string(model.StatusPromotionIntent)}})
	return p.completeIntent(ctx, pi, true)
}

// completeIntent drives an intent forward from its recorded state. When
// applyRouter is false and the intent is pending, the router is re-applied
// only if the candidate is still healthy (crash recovery path).
func (p *Platform) completeIntent(ctx context.Context, pi *store.PromotionIntent, applyRouter bool) error {
	d, err := p.Store.GetDeployment(ctx, pi.ToDeployment)
	if err != nil {
		return err
	}
	if pi.State == "pending" {
		// Steps 3-4: apply router config tagged with the candidate and verify
		// that the candidate answers through the edge.
		table, err := p.routeTable(ctx, pi.EnvironmentID, d.ID)
		if err != nil {
			return p.abortIntent(ctx, pi, d, err)
		}
		var verify []string
		for _, rt := range table.Routes {
			if rt.EnvironmentID == pi.EnvironmentID && rt.DeploymentID == d.ID {
				verify = []string{pi.EnvironmentID}
			}
		}
		if verify == nil {
			p.logf(ctx, d.ID, "deploy", "environment has no hostnames yet; promoting without edge verification")
		}
		res, err := p.Router.Apply(ctx, table, verify)
		if err != nil {
			if isTransient(err) {
				return err
			}
			return p.abortIntent(ctx, pi, d, fmt.Errorf("edge verification: %w", err))
		}
		if err := p.Store.MarkRouterApplied(ctx, pi.ID, res.Digest); err != nil {
			return err
		}
		pi.State = "router_applied"
		p.logf(ctx, d.ID, "deploy", "edge switched to deployment (config %s)", shortDigest(res.Digest))
		p.Events.Publish(Event{Topic: "deployment:" + d.ID, Type: "status", Data: map[string]string{"to": string(model.StatusRouterSwitched)}})
	}
	if pi.State == "router_applied" {
		// Step 5: commit pointer + observed generation atomically.
		if err := p.Store.CommitPromotion(ctx, pi.ID); err != nil {
			if !errors.Is(err, store.ErrConflict) {
				return err
			}
			// observed_generation already >= ours: a newer generation won the
			// race after our router switch. Its own promotion re-applies routes.
			p.logf(ctx, d.ID, "system", "commit skipped: newer generation already observed")
			_ = p.Store.AbortPromotion(ctx, pi.ID, "superseded after router switch by a newer committed generation", false)
			p.cleanupCandidate(ctx, d.ID)
			return p.reapplyRoutes(ctx)
		}
		pi.State = "committed"
	}
	if pi.State == "committed" {
		// Step 6: mark complete and drain the previous deployment.
		if err := p.Store.CompletePromotion(ctx, pi.ID); err != nil {
			return err
		}
	}
	return p.finishDrain(ctx, pi)
}

func (p *Platform) finishDrain(ctx context.Context, pi *store.PromotionIntent) error {
	d, err := p.Store.GetDeployment(ctx, pi.ToDeployment)
	if err != nil {
		return err
	}
	if d.Status != model.StatusDrainingOld {
		return nil
	}
	if pi.FromDeployment != "" && pi.FromDeployment != d.ID {
		go func(from string) {
			// Allow in-flight requests to finish before stopping the old version.
			time.Sleep(10 * time.Second)
			p.stopDeploymentWorkloads(context.Background(), from, true)
		}(pi.FromDeployment)
	}
	if err := p.Store.Transition(ctx, d.ID, model.StatusDrainingOld, model.StatusSucceeded, "promoted"); err != nil {
		return err
	}
	p.Events.Publish(Event{Topic: "deployment:" + d.ID, Type: "status", Data: map[string]string{"to": string(model.StatusSucceeded)}})
	p.Events.Publish(Event{Topic: "project:" + d.ProjectID, Type: "status", Data: map[string]string{"deployment_id": d.ID, "status": string(model.StatusSucceeded)}})
	p.logf(ctx, d.ID, "deploy", "deployment is live (generation %d)", d.Generation)
	p.auditDeploy(ctx, d, "deployment.promote", audit.Success, map[string]string{"from": pi.FromDeployment, "to": d.ID})
	go p.notifyGitHub(context.Background(), d, true)
	return nil
}

func (p *Platform) abortIntent(ctx context.Context, pi *store.PromotionIntent, d *store.Deployment, cause error) error {
	_ = p.Store.AbortPromotion(ctx, pi.ID, cause.Error(), false)
	// Restore the last known-good route computed from committed DB state.
	if err := p.reapplyRoutes(ctx); err != nil {
		p.Log.Error("restore routes after aborted promotion", "err", err)
	}
	p.cleanupCandidate(ctx, d.ID)
	p.logf(ctx, d.ID, "system", "promotion aborted: %v", cause)
	p.auditDeploy(ctx, d, "deployment.promote", audit.Failure, map[string]string{"reason": truncate(cause.Error(), 500)})
	return nil
}

// resumePromotion continues a deployment found mid-promotion (job resumed
// after crash).
func (p *Platform) resumePromotion(ctx context.Context, d *store.Deployment) error {
	if d.Status == model.StatusDrainingOld {
		return p.Store.Transition(ctx, d.ID, model.StatusDrainingOld, model.StatusSucceeded, "promoted (resumed)")
	}
	intents, err := p.Store.InflightPromotions(ctx)
	if err != nil {
		return err
	}
	for _, pi := range intents {
		if pi.ToDeployment == d.ID {
			return p.recoverIntent(ctx, pi)
		}
	}
	return fmt.Errorf("deployment in %s without an in-flight promotion intent", d.Status)
}

// recoverIntent deterministically completes or restores an interrupted
// promotion (§11.3 step 7).
func (p *Platform) recoverIntent(ctx context.Context, pi *store.PromotionIntent) error {
	d, err := p.Store.GetDeployment(ctx, pi.ToDeployment)
	if err != nil {
		return err
	}
	if pi.State != "pending" {
		return p.completeIntent(ctx, pi, false)
	}
	// Pending: did the router switch before the crash? Either way, only
	// continue if the candidate is still healthy and still desired.
	env, err := p.Store.GetEnvironment(ctx, pi.EnvironmentID)
	if err != nil {
		return err
	}
	if env.DesiredGeneration != pi.Generation {
		return p.abortIntent(ctx, pi, d, errors.New("superseded while promotion was interrupted"))
	}
	if err := p.candidateStillHealthy(ctx, d); err != nil {
		return p.abortIntent(ctx, pi, d, fmt.Errorf("candidate unhealthy after restart: %w", err))
	}
	return p.completeIntent(ctx, pi, true)
}

func (p *Platform) candidateStillHealthy(ctx context.Context, d *store.Deployment) error {
	art, err := p.Store.GetArtifact(ctx, d.ArtifactID)
	if err != nil {
		return err
	}
	if art.Kind == "static" {
		return nil
	}
	ws, err := p.Store.WorkloadsForDeployment(ctx, d.ID)
	if err != nil {
		return err
	}
	if len(ws) == 0 {
		return errors.New("no workloads")
	}
	for _, w := range ws {
		if err := p.checkRunning(ctx, w.ID); err != nil {
			return err
		}
	}
	return nil
}

// runManualPromote promotes a READY deployment (auto_promote: false).
func (p *Platform) runManualPromote(ctx context.Context, depID string) error {
	d, err := p.Store.GetDeployment(ctx, depID)
	if err != nil {
		return nil
	}
	if d.Status != model.StatusReady {
		return nil
	}
	if err := p.candidateStillHealthy(ctx, d); err != nil {
		p.failDeployment(ctx, d, fmt.Errorf("cannot promote: %w", err))
		return nil
	}
	return p.promote(ctx, d)
}

// reapplyRoutes pushes the route table computed from committed state.
func (p *Platform) reapplyRoutes(ctx context.Context) error {
	t, err := p.routeTable(ctx, "", "")
	if err != nil {
		return err
	}
	_, err = p.Router.Apply(ctx, t, nil)
	return err
}

func shortDigest(d string) string {
	if len(d) > 19 {
		return d[:19]
	}
	return d
}

// spaFrameworks serve index.html for unknown paths.
var spaFrameworks = map[string]bool{"vite": true, "create-react-app": true, "angular": true, "vue-cli": true, "parcel": true, "sveltekit-static": true}

// routeTable computes the full edge table from committed state, optionally
// substituting a candidate deployment for one environment.
func (p *Platform) routeTable(ctx context.Context, overrideEnv, overrideDep string) (router.Table, error) {
	envs, err := p.Store.ActiveEnvironments(ctx)
	if err != nil {
		return router.Table{}, err
	}
	domains, err := p.Store.ActiveDomains(ctx)
	if err != nil {
		return router.Table{}, err
	}
	byEnv := map[string][]string{}
	for _, dm := range domains {
		if dm.EnvironmentID != "" {
			byEnv[dm.EnvironmentID] = append(byEnv[dm.EnvironmentID], dm.Hostname)
		}
	}
	var lkg map[string]router.Route
	if cur, err := p.Router.Current(ctx); err == nil {
		lkg = map[string]router.Route{}
		for _, r := range cur.Table.Routes {
			lkg[r.EnvironmentID] = r
		}
	}
	tlsMode := router.TLSACME
	if p.Node.Ingress.Mode == "lan" {
		tlsMode = router.TLSNone
	}
	var t router.Table
	for _, env := range envs {
		if env.Status != "active" {
			continue
		}
		depID := env.CurrentDeploymentID
		if env.ID == overrideEnv {
			depID = overrideDep
		}
		if depID == "" {
			continue
		}
		hosts := []string{}
		if env.GeneratedHostname != "" {
			hosts = append(hosts, env.GeneratedHostname)
		}
		hosts = append(hosts, byEnv[env.ID]...)
		if len(hosts) == 0 {
			continue
		}
		sort.Strings(hosts)
		d, err := p.Store.GetDeployment(ctx, depID)
		if err != nil {
			return router.Table{}, err
		}
		art, err := p.Store.GetArtifact(ctx, d.ArtifactID)
		if err != nil {
			return router.Table{}, err
		}
		r := router.Route{EnvironmentID: env.ID, ProjectID: env.ProjectID, DeploymentID: d.ID, Hosts: hosts, TLS: tlsMode,
			MaxBodyBytes: p.Node.Ingress.Limits.MaxBodyBytes, MaxConns: p.Node.Ingress.Limits.MaxConnsPerHost}
		if tlsMode == router.TLSACME {
			for _, h := range hosts {
				if strings.HasSuffix(h, ".localhost") || h == "localhost" {
					r.TLS = router.TLSInternal
				}
			}
		}
		if art.Kind == "static" {
			r.Kind, r.StaticDigest = router.KindStatic, art.Digest
			if s, err := p.snapshot(d); err == nil {
				r.SPA = spaFrameworks[s.Plan.Framework]
			}
		} else {
			ws, err := p.Store.WorkloadsForDeployment(ctx, d.ID)
			if err != nil {
				return router.Table{}, err
			}
			for _, w := range ws {
				if w.Endpoint != "" && (w.State == "running" || w.State == "healthy") && w.ServiceName == "web" {
					r.Upstreams = append(r.Upstreams, w.Endpoint)
				}
			}
			r.Kind = router.KindProxy
			if len(r.Upstreams) == 0 {
				// Keep the last-known-good route until backends are ready
				// (§18.1 step 6) rather than dropping the host.
				if prev, ok := lkg[env.ID]; ok {
					t.Routes = append(t.Routes, prev)
				}
				continue
			}
		}
		if pa := p.previewAuth(ctx, env); pa != nil {
			r.BasicAuth = pa
		}
		t.Routes = append(t.Routes, r)
	}
	return t, nil
}
