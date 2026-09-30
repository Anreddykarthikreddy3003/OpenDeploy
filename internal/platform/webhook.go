package platform

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/git/github"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// WebhookResult reports how a delivery was handled.
type WebhookResult struct {
	Status      int      `json:"-"`
	Outcome     string   `json:"outcome"`
	Deployments []string `json:"deployments,omitempty"`
}

// HandleGitHubWebhook implements PRD §6.2: verify the raw body signature
// before parsing, record an append-only ingress row, deduplicate the
// delivery ID, validate installation/repository/ref ownership, create a new
// monotonic desired_generation and durable job, and only then acknowledge.
func (p *Platform) HandleGitHubWebhook(ctx context.Context, event, delivery, signature, sourceIP string, body []byte) *WebhookResult {
	deny := func(status int, reason string) *WebhookResult {
		_, _ = p.Audit.Append(ctx, audit.Event{ActorType: audit.ActorGitHub, ActorID: "webhook", SourceIP: sourceIP, Action: "webhook.receive",
			ResourceType: "webhook", ResourceID: truncate(delivery, 64), Result: audit.Denied, Details: map[string]string{"reason": reason, "event": truncate(event, 64)}})
		return &WebhookResult{Status: status, Outcome: reason}
	}
	secret, err := p.GitHub.WebhookSecret(ctx)
	if err != nil {
		return deny(503, "github app not configured")
	}
	if len(secret) == 0 {
		// The App was registered without a webhook (F-8): nothing can be
		// verified, so nothing is accepted, whatever the signature says.
		return deny(401, "webhooks are not enabled for this GitHub App")
	}
	if err := github.VerifySignature(secret, body, signature); err != nil {
		return deny(401, "invalid signature")
	}
	if !github.SupportedEvents[event] {
		return &WebhookResult{Status: 202, Outcome: "event ignored"}
	}
	ev, err := github.ParseEvent(event, delivery, body)
	if err != nil {
		return deny(400, "malformed payload: "+truncate(err.Error(), 200))
	}
	if ev.Name == "ping" {
		return &WebhookResult{Status: 200, Outcome: "pong"}
	}
	sum := sha256.Sum256(body)
	rec := store.WebhookDelivery{DeliveryID: delivery, Event: event, InstallationID: ev.InstallationID(), RepositoryID: ev.RepositoryID(),
		BodySHA256: hex.EncodeToString(sum[:])}
	switch {
	case ev.Push != nil:
		rec.Ref, rec.SHA = ev.Push.Ref, ev.Push.After
	case ev.PullRequest != nil:
		rec.Action, rec.Ref, rec.SHA = ev.PullRequest.Action, ev.PullRequest.PullRequest.Head.Ref, ev.PullRequest.PullRequest.Head.SHA
	case ev.Installation != nil:
		rec.Action = ev.Installation.Action
	}
	res := &WebhookResult{Status: 202}
	err = p.Store.Tx(ctx, func(tx *sql.Tx) error {
		dup, err := store.RecordDeliveryTx(ctx, tx, rec)
		if err != nil {
			return err
		}
		if dup {
			res.Outcome = "duplicate delivery ignored"
			return nil
		}
		switch {
		case ev.Push != nil:
			err = p.onPush(ctx, tx, ev, res)
		case ev.PullRequest != nil:
			err = p.onPullRequest(ctx, tx, ev, res)
		case ev.Installation != nil:
			err = p.onInstallation(ctx, tx, ev, res)
		}
		if err != nil {
			return err
		}
		return store.SetDeliveryOutcomeTx(ctx, tx, delivery, res.Outcome)
	})
	if err != nil {
		p.Log.Error("webhook", "delivery", delivery, "err", err)
		// Not acknowledged: GitHub will redeliver; nothing was committed.
		return &WebhookResult{Status: 500, Outcome: "not recorded"}
	}
	_, _ = p.Audit.Append(ctx, audit.Event{ActorType: audit.ActorGitHub, ActorID: "installation:" + strconv.FormatInt(ev.InstallationID(), 10),
		SourceIP: sourceIP, Action: "webhook.receive", ResourceType: "webhook", ResourceID: delivery, Result: audit.Success,
		Details: map[string]string{"event": event, "delivery_id": delivery, "ref": truncate(rec.Ref, 200), "commit": rec.SHA, "reason": truncate(res.Outcome, 200)}})
	return res
}

func (p *Platform) onPush(ctx context.Context, tx *sql.Tx, ev *github.Event, res *WebhookResult) error {
	push := ev.Push
	branch, ok := push.Branch()
	if !ok {
		res.Outcome = "not a branch push"
		return nil
	}
	if push.Deleted {
		res.Outcome = "branch deleted; no deployment"
		return nil
	}
	projects, err := store.ProjectsForEventTx(ctx, tx, push.Installation.ID, push.Repository.ID)
	if err != nil {
		return err
	}
	if len(projects) == 0 {
		res.Outcome = "no project for this installation/repository"
		return nil
	}
	var outcomes []string
	for _, proj := range projects {
		if branch != proj.ProductionBranch {
			outcomes = append(outcomes, proj.Name+": branch "+branch+" is not the production branch")
			continue
		}
		if !proj.AutoDeploy {
			outcomes = append(outcomes, proj.Name+": auto-deploy disabled")
			continue
		}
		env, err := store.EnvironmentByNameTx(ctx, tx, proj.ID, "production")
		if err != nil {
			return err
		}
		nd := store.NewDeployment{EnvironmentID: env.ID, Trigger: "push", CommitSHA: push.After, Branch: branch, DeliveryID: ev.DeliveryID,
			CreatedBy: "github:" + push.Sender.Login}
		if push.HeadCommit != nil {
			nd.CommitMessage, nd.CommitAuthor = firstLine(push.HeadCommit.Message), push.HeadCommit.Author.Name
		}
		d, err := store.CreateDeploymentTx(ctx, tx, nd)
		if err != nil {
			return err
		}
		if err := EnqueueDeployTx(ctx, tx, d.ID); err != nil {
			return err
		}
		res.Deployments = append(res.Deployments, d.ID)
		outcomes = append(outcomes, fmt.Sprintf("%s: generation %d queued", proj.Name, d.Generation))
	}
	res.Outcome = strings.Join(outcomes, "; ")
	return nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}

func (p *Platform) onPullRequest(ctx context.Context, tx *sql.Tx, ev *github.Event, res *WebhookResult) error {
	pr := ev.PullRequest
	projects, err := store.ProjectsForEventTx(ctx, tx, pr.Installation.ID, pr.Repository.ID)
	if err != nil {
		return err
	}
	var outcomes []string
	for _, proj := range projects {
		if pr.PullRequest.Base.Ref != proj.ProductionBranch {
			outcomes = append(outcomes, proj.Name+": PR base is not the production branch")
			continue
		}
		switch pr.Action {
		case "closed":
			env, err := store.EnvironmentByNameTx(ctx, tx, proj.ID, fmt.Sprintf("pr-%d", pr.Number))
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if err := store.MarkEnvDeletingTx(ctx, tx, env.ID); err != nil {
				return err
			}
			if _, _, err := store.EnqueueTx(ctx, tx, JobEnvTeardown, "teardown:"+env.ID+":"+ev.DeliveryID, map[string]string{"environment_id": env.ID}, 10); err != nil {
				return err
			}
			outcomes = append(outcomes, proj.Name+": preview scheduled for removal")
		case "opened", "synchronize", "reopened":
			if !proj.PreviewsEnabled {
				outcomes = append(outcomes, proj.Name+": previews disabled")
				continue
			}
			fork := pr.FromFork()
			if fork && !proj.AllowPublicForks {
				// Fail closed: fork code never executes unless explicitly allowed
				// AND the untrusted sandbox exists (checked by trust.Decide).
				outcomes = append(outcomes, proj.Name+": fork PR previews disabled")
				continue
			}
			n, err := store.CountActivePreviewsTx(ctx, tx, proj.ID)
			if err != nil {
				return err
			}
			env, err := store.EnsurePreviewEnvTx(ctx, tx, proj.ID, pr.Number, pr.PullRequest.Head.Ref, fork, p.previewHostname(proj.Name, pr.Number))
			if err != nil {
				return err
			}
			if n >= maxPreviews(p.Node.Profile) && env.DesiredGeneration == 0 {
				_ = store.MarkEnvDeletingTx(ctx, tx, env.ID)
				outcomes = append(outcomes, proj.Name+": preview quota reached")
				continue
			}
			nd := store.NewDeployment{EnvironmentID: env.ID, Trigger: "pull_request", CommitSHA: pr.PullRequest.Head.SHA, Branch: pr.PullRequest.Head.Ref,
				CommitMessage: pr.PullRequest.Title, CommitAuthor: pr.PullRequest.User.Login, DeliveryID: ev.DeliveryID, CreatedBy: "github:" + pr.PullRequest.User.Login}
			d, err := store.CreateDeploymentTx(ctx, tx, nd)
			if err != nil {
				return err
			}
			if err := EnqueueDeployTx(ctx, tx, d.ID); err != nil {
				return err
			}
			res.Deployments = append(res.Deployments, d.ID)
			outcomes = append(outcomes, fmt.Sprintf("%s: preview pr-%d generation %d queued", proj.Name, pr.Number, d.Generation))
		default:
			outcomes = append(outcomes, "action "+pr.Action+" ignored")
		}
	}
	if len(outcomes) == 0 {
		outcomes = append(outcomes, "no project for this installation/repository")
	}
	res.Outcome = strings.Join(outcomes, "; ")
	return nil
}

func maxPreviews(profile string) int {
	switch profile {
	case "tiny":
		return 0
	case "performance":
		return 20
	}
	return 5
}

func (p *Platform) previewHostname(project string, pr int) string {
	return p.GeneratedHostname(project, fmt.Sprintf("pr-%d", pr))
}

// GeneratedHostname returns the generated URL host for a project
// environment: <project>.<base> for production, <project>-<env>.<base>
// otherwise.
func (p *Platform) GeneratedHostname(project, env string) string {
	if env == "" || env == "production" {
		return project + "." + p.baseDomain()
	}
	return project + "-" + env + "." + p.baseDomain()
}

// BaseDomain is the domain under which generated hostnames are allocated.
func (p *Platform) BaseDomain() string { return p.baseDomain() }

func (p *Platform) baseDomain() string {
	in := p.Node.Ingress
	if in.BaseDomain != "" {
		return in.BaseDomain
	}
	if in.Mode == "relay" && in.Relay.InstanceID != "" && in.Relay.PublicSuffix != "" {
		// The relay delegates <instance>.<suffix> to this node.
		return in.Relay.InstanceID + "." + strings.Trim(in.Relay.PublicSuffix, ".")
	}
	return "localhost"
}

func (p *Platform) onInstallation(ctx context.Context, tx *sql.Tx, ev *github.Event, res *WebhookResult) error {
	inst := ev.Installation
	id := inst.Installation.ID
	switch inst.Action {
	case "deleted", "suspend":
		st := "revoked"
		if inst.Action == "suspend" {
			st = "suspended"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE git_connections SET status=?, updated_at=? WHERE provider='github' AND installation_id=?`, st, state.Now(), id); err != nil {
			return err
		}
		if app, err := p.GitHub.App(ctx); err == nil {
			app.ForgetInstallation(id)
		}
		res.Outcome = "installation " + st + "; new builds blocked, running deployments unaffected"
	case "unsuspend", "created", "new_permissions_accepted":
		if _, err := tx.ExecContext(ctx, `UPDATE git_connections SET status='active', updated_at=? WHERE provider='github' AND installation_id=?`, state.Now(), id); err != nil {
			return err
		}
		res.Outcome = "installation active"
	default:
		if len(inst.RepositoriesRemoved) > 0 {
			if app, err := p.GitHub.App(ctx); err == nil {
				app.ForgetInstallation(id)
			}
		}
		res.Outcome = "installation " + inst.Action
	}
	return nil
}
