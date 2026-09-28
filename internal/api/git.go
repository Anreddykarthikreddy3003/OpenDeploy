package api

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/auth"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/git/github"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/platform"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/secrets"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

func (s *Server) handleGitStatus(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.SystemRead); err != nil {
		return err
	}
	ctx := r.Context()
	_, err := s.P.GitHub.App(ctx)
	conns, _ := s.S.ListGitConnections(ctx)
	if conns == nil {
		conns = []store.GitConnection{}
	}
	slug := s.P.GitHub.Slug(ctx)
	out := map[string]any{"configured": err == nil, "connections": conns, "public_url": s.publicBase(r)}
	if slug != "" {
		out["install_url"] = "https://github.com/apps/" + url.PathEscape(slug) + "/installations/new"
	}
	if err != nil {
		out["error"] = err.Error()
	}
	writeJSON(w, 200, out)
	return nil
}

func (s *Server) publicBase(r *http.Request) string {
	if u := s.P.Node.API.PublicURL; u != "" {
		return strings.TrimRight(u, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// handleManifest returns the GitHub App manifest for one-click registration.
// The browser posts it to GitHub; GitHub redirects back with a code.
func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.GitConnect); err != nil {
		return err
	}
	var req struct {
		Organization string `json:"organization"`
		Name         string `json:"name"`
		WithChecks   bool   `json:"with_checks"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	base := s.publicBase(r)
	name := firstNonEmpty(req.Name, "OpenDeploy "+strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://"))
	if len(name) > 34 {
		name = name[:34]
	}
	manifest := github.Manifest(name, base, req.WithChecks)
	state, _ := auth.NewToken("", 24)
	s.webauthnState.Store("manifest:"+state, manifestState{user: principal(r).User.ID, exp: time.Now().Add(15 * time.Minute)})
	target := "https://github.com/settings/apps/new"
	if req.Organization != "" {
		target = "https://github.com/organizations/" + url.PathEscape(req.Organization) + "/settings/apps/new"
	}
	writeJSON(w, 200, map[string]any{"post_url": target + "?state=" + state, "manifest": manifest})
	return nil
}

type manifestState struct {
	user string
	exp  time.Time
}

// handleManifestComplete finishes registration. GitHub redirects the
// browser to the dashboard route /settings/git/callback, which posts the
// code here (same-site, CSRF-protected); the state is bound to the user who
// started the flow. Credentials go to secretd, never to disk in plaintext.
func (s *Server) handleManifestComplete(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.GitConnect); err != nil {
		return err
	}
	var req struct {
		Code  string `json:"code"`
		State string `json:"state"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	v, ok := s.webauthnState.LoadAndDelete("manifest:" + req.State)
	ms, _ := v.(manifestState)
	if !ok || time.Now().After(ms.exp) || ms.user != principal(r).User.ID {
		return errf(400, "bad_request", "registration expired or was started by another user; start again")
	}
	if req.Code == "" || len(req.Code) > 200 {
		return errf(400, "bad_request", "missing code")
	}
	conv, err := github.ConvertManifest(r.Context(), s.P.Node.GitHub.APIURL, req.Code)
	if err != nil {
		return errf(502, "github", "GitHub rejected the registration: %v", err)
	}
	actor := s.secretActor(r)
	for name, val := range map[string]string{platform.SecretGitHubAppID: strconv.FormatInt(conv.ID, 10), platform.SecretGitHubSlug: conv.Slug,
		platform.SecretGitHubPrivateKey: conv.PEM, platform.SecretGitHubWebhook: conv.WebhookSecret} {
		sensitive := name == platform.SecretGitHubPrivateKey || name == platform.SecretGitHubWebhook
		if _, err := s.P.Secrets.Set(r.Context(), secrets.SetReq{Ref: secrets.Ref{Scope: secrets.ScopeInstance, Name: name}, Value: val, Sensitive: sensitive, Actor: actor}); err != nil {
			return err
		}
	}
	s.P.GitHub.Reset()
	s.audit(r, "git.connect", "github_app", strconv.FormatInt(conv.ID, 10), "", audit.Success, map[string]string{"target": conv.Slug})
	writeJSON(w, 200, map[string]string{"name": conv.Name, "slug": conv.Slug,
		"install_url": "https://github.com/apps/" + url.PathEscape(conv.Slug) + "/installations/new"})
	return nil
}

// handleSync refreshes installations from GitHub.
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.ProjectCreate); err != nil {
		return err
	}
	conns, err := s.syncInstallations(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, 200, conns)
	return nil
}

func (s *Server) syncInstallations(ctx context.Context) ([]store.GitConnection, error) {
	app, err := s.P.GitHub.App(ctx)
	if err != nil {
		return nil, errf(409, "github_not_configured", "%v", err)
	}
	insts, err := app.ListInstallations(ctx)
	if err != nil {
		return nil, errf(502, "github", "list installations: %v", err)
	}
	seen := map[int64]bool{}
	for _, in := range insts {
		st := "active"
		if in.SuspendedAt != nil {
			st = "suspended"
		}
		g := &store.GitConnection{Provider: "github", AppID: app.ID, InstallationID: in.ID, AccountLogin: in.Account.Login, AccountType: in.Account.Type, Status: st}
		if err := s.S.UpsertGitConnection(ctx, g); err != nil {
			return nil, err
		}
		seen[in.ID] = true
	}
	existing, _ := s.S.ListGitConnections(ctx)
	for _, c := range existing {
		if !seen[c.InstallationID] && c.Status == "active" {
			_ = s.S.SetGitConnectionStatus(ctx, c.InstallationID, "revoked")
		}
	}
	return s.S.ListGitConnections(ctx)
}

func (s *Server) handleRepos(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.ProjectCreate); err != nil {
		return err
	}
	ctx := r.Context()
	app, err := s.P.GitHub.App(ctx)
	if err != nil {
		return errf(409, "github_not_configured", "%v", err)
	}
	conns, err := s.S.ListGitConnections(ctx)
	if err != nil {
		return err
	}
	if len(conns) == 0 {
		if conns, err = s.syncInstallations(ctx); err != nil {
			return err
		}
	}
	type repo struct {
		ConnectionID  string `json:"connection_id"`
		Account       string `json:"account"`
		ID            int64  `json:"id"`
		FullName      string `json:"full_name"`
		Private       bool   `json:"private"`
		DefaultBranch string `json:"default_branch"`
		HTMLURL       string `json:"html_url"`
		Imported      bool   `json:"imported"`
	}
	imported := map[int64]bool{}
	if ps, err := s.S.ListProjects(ctx); err == nil {
		for _, p := range ps {
			imported[p.RepoID] = true
		}
	}
	out := []repo{}
	for _, c := range conns {
		if c.Status != "active" {
			continue
		}
		rs, err := app.ListInstallationRepos(ctx, c.InstallationID)
		if err != nil {
			continue
		}
		for _, x := range rs {
			if x.Archived {
				continue
			}
			out = append(out, repo{ConnectionID: c.ID, Account: c.AccountLogin, ID: x.ID, FullName: x.FullName, Private: x.Private,
				DefaultBranch: x.DefaultBranch, HTMLURL: x.HTMLURL, Imported: imported[x.ID]})
		}
	}
	writeJSON(w, 200, out)
	return nil
}

func (s *Server) handleBranches(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.ProjectCreate); err != nil {
		return err
	}
	repoID, _ := strconv.ParseInt(r.PathValue("repo"), 10, 64)
	conn, repo, err := s.resolveRepo(r.Context(), r.PathValue("conn"), repoID)
	if err != nil {
		return err
	}
	app, _ := s.P.GitHub.App(r.Context())
	bs, err := app.ListBranches(r.Context(), conn.InstallationID, repo.ID)
	if err != nil {
		return errf(502, "github", "list branches failed")
	}
	writeJSON(w, 200, map[string]any{"default": repo.DefaultBranch, "branches": bs})
	return nil
}
