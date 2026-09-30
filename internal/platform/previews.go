package platform

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/git/github"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/router"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// PreviewProtection is optional access authentication for a project's
// preview URLs (PRD §12 "optional access authentication").
type PreviewProtection struct {
	Enabled    bool   `json:"enabled"`
	User       string `json:"user"`
	BcryptHash string `json:"bcrypt_hash,omitempty"`
}

func previewKey(projectID string) string { return "preview_protection:" + projectID }

// GetPreviewProtection returns the project's preview protection.
func (p *Platform) GetPreviewProtection(ctx context.Context, projectID string) (*PreviewProtection, error) {
	var pp PreviewProtection
	if _, err := p.Store.GetSetting(ctx, previewKey(projectID), &pp); err != nil {
		return nil, err
	}
	return &pp, nil
}

// SetPreviewProtection stores protection (password hashed with bcrypt, as
// Caddy's basic auth requires) and re-applies routes.
func (p *Platform) SetPreviewProtection(ctx context.Context, projectID string, enabled bool, user, password string) error {
	pp := PreviewProtection{Enabled: enabled}
	if enabled {
		if user == "" || len(password) < 8 {
			return errors.New("username and a password of at least 8 characters are required")
		}
		h, err := bcrypt.GenerateFromPassword([]byte(password), 12)
		if err != nil {
			return err
		}
		pp.User, pp.BcryptHash = user, string(h)
	}
	if err := p.Store.SetSetting(ctx, previewKey(projectID), pp); err != nil {
		return err
	}
	return p.reapplyRoutes(ctx)
}

func (p *Platform) previewAuth(ctx context.Context, env *store.Environment) *router.BasicAuth {
	if env.Kind != "preview" {
		return nil
	}
	pp, err := p.GetPreviewProtection(ctx, env.ProjectID)
	if err != nil || !pp.Enabled || pp.BcryptHash == "" {
		return nil
	}
	return &router.BasicAuth{User: pp.User, BcryptHash: pp.BcryptHash}
}

// notifyGitHub publishes a check run with the deployment URL when the
// GitHub App was granted checks:write (optional; failures are ignored).
func (p *Platform) notifyGitHub(ctx context.Context, d *store.Deployment, success bool) {
	if p.GitHub == nil || !github.ValidSHA(d.CommitSHA) {
		return
	}
	proj, err := p.Store.GetProject(ctx, d.ProjectID)
	if err != nil || proj.GitConnectionID == "" {
		return
	}
	conn, err := p.Store.GetGitConnection(ctx, proj.GitConnectionID)
	if err != nil || conn.Status != "active" {
		return
	}
	app, err := p.GitHub.App(ctx)
	if err != nil {
		return
	}
	env, err := p.Store.GetEnvironment(ctx, d.EnvironmentID)
	if err != nil {
		return
	}
	url := ""
	if env.GeneratedHostname != "" {
		url = p.PublicURL(env.GeneratedHostname)
	}
	cr := github.CheckRun{Name: "OpenDeploy (" + env.Name + ")", HeadSHA: d.CommitSHA, Status: "completed", DetailsURL: url, ExternalID: d.ID, Conclusion: "success"}
	title := fmt.Sprintf("Deployed to %s", env.Name)
	if !success {
		cr.Conclusion, title = "failure", fmt.Sprintf("Deployment to %s failed", env.Name)
	}
	cr.Output = &struct {
		Title   string `json:"title"`
		Summary string `json:"summary"`
	}{Title: title, Summary: fmt.Sprintf("Generation %d. %s", d.Generation, url)}
	if err := app.CreateCheckRun(ctx, conn.InstallationID, proj.RepoID, proj.RepoFullName, cr); err != nil {
		p.Log.Debug("github check run not published (checks:write not granted?)", "err", err)
	}
}
