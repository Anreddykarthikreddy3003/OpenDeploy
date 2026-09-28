package api

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/auth"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/build/builder"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/build/detect"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/git"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/git/github"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/model"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/platform"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/policy"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/secrets"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

var projectNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)
var envNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,20}[a-z0-9])?$`)

type projectView struct {
	*store.Project
	Role       string      `json:"role"`
	URL        string      `json:"url,omitempty"`
	Production *envSummary `json:"production,omitempty"`
	SourceKind string      `json:"source_kind"`
}

type envSummary struct {
	*store.Environment
	URL     string            `json:"url,omitempty"`
	Domains []string          `json:"domains"`
	Current *store.Deployment `json:"current_deployment,omitempty"`
	Latest  *store.Deployment `json:"latest_deployment,omitempty"`
}

func sourceKind(p *store.Project) string {
	switch {
	case p.GitConnectionID != "":
		return "github"
	case p.CloneURL != "":
		return "git"
	default:
		return "upload"
	}
}

func (s *Server) envSummary(ctx context.Context, e *store.Environment, domains []*store.Domain) *envSummary {
	es := &envSummary{Environment: e, Domains: []string{}}
	if e.GeneratedHostname != "" {
		es.URL = s.P.PublicURL(e.GeneratedHostname)
	}
	for _, d := range domains {
		if d.EnvironmentID == e.ID && (d.Status == "active" || d.Status == "verified") {
			es.Domains = append(es.Domains, d.Hostname)
		}
	}
	if e.CurrentDeploymentID != "" {
		es.Current, _ = s.S.GetDeployment(ctx, e.CurrentDeploymentID)
	}
	if deps, err := s.S.ListDeployments(ctx, e.ProjectID, e.ID, 1); err == nil && len(deps) > 0 {
		es.Latest = deps[0]
	}
	return es
}

func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	var ps []*store.Project
	var err error
	if p.User.Role == model.RoleOwner {
		ps, err = s.S.ListProjects(r.Context())
	} else {
		ps, err = s.S.ListProjectsForUser(r.Context(), p.User.ID)
	}
	if err != nil {
		return err
	}
	out := make([]projectView, 0, len(ps))
	for _, pr := range ps {
		role, _ := s.S.MemberRole(r.Context(), pr.ID, p.User.ID)
		if p.User.Role == model.RoleOwner {
			role = model.RoleOwner
		}
		v := projectView{Project: pr, Role: role, SourceKind: sourceKind(pr)}
		if e, err := s.S.GetEnvironmentByName(r.Context(), pr.ID, "production"); err == nil {
			doms, _ := s.S.DomainsForProject(r.Context(), pr.ID)
			v.Production = s.envSummary(r.Context(), e, doms)
			v.URL = v.Production.URL
			if len(v.Production.Domains) > 0 {
				v.URL = s.P.PublicURL(v.Production.Domains[0])
			}
		}
		out = append(out, v)
	}
	writeJSON(w, 200, out)
	return nil
}

type createProjectReq struct {
	Name             string               `json:"name"`
	GitConnectionID  string               `json:"git_connection_id"`
	RepoID           int64                `json:"repo_id"`
	CloneURL         string               `json:"clone_url"`
	RootDir          string               `json:"root_dir"`
	ProductionBranch string               `json:"production_branch"`
	TrustClass       string               `json:"trust_class"`
	AutoDeploy       *bool                `json:"auto_deploy"`
	PreviewsEnabled  bool                 `json:"previews_enabled"`
	Build            store.BuildOverrides `json:"build"`
	ConfigOverride   string               `json:"config_override"`
	Env              map[string]string    `json:"env"` // initial production environment variables (sensitive)
	DeployNow        *bool                `json:"deploy_now"`
}

func (s *Server) resolveRepo(ctx context.Context, connID string, repoID int64) (*store.GitConnection, *github.Repository, error) {
	conn, err := s.S.GetGitConnection(ctx, connID)
	if err != nil {
		return nil, nil, errf(400, "bad_request", "unknown git connection")
	}
	if conn.Status != "active" {
		return nil, nil, errf(409, "conflict", "GitHub installation is %s", conn.Status)
	}
	app, err := s.P.GitHub.App(ctx)
	if err != nil {
		return nil, nil, errf(409, "github_not_configured", "%v", err)
	}
	repo, err := app.GetRepo(ctx, conn.InstallationID, repoID)
	if err != nil {
		return nil, nil, errf(400, "bad_request", "repository not accessible through this installation")
	}
	return conn, repo, nil
}

func validateOverrides(b store.BuildOverrides) error {
	switch b.Strategy {
	case "", "auto", "dockerfile", "static", "buildpacks", "nixpacks":
	default:
		return errf(400, "bad_request", "invalid build strategy")
	}
	if b.Port < 0 || b.Port > 65535 {
		return errf(400, "bad_request", "invalid port")
	}
	if len(b.BuildCommand) > 2000 || len(b.StartCommand) > 2000 {
		return errf(400, "bad_request", "command too long")
	}
	if b.OutputDir != "" && (strings.HasPrefix(b.OutputDir, "/") || strings.Contains(b.OutputDir, "..")) {
		return errf(400, "bad_request", "output_dir must be relative")
	}
	for k := range b.Env {
		if !policy.ValidEnvName(k) {
			return errf(400, "bad_request", "invalid build arg %q", k)
		}
	}
	return nil
}

func validRootDir(d string) bool {
	return d == "" || d == "." || (!strings.HasPrefix(d, "/") && !strings.Contains(d, "..") && len(d) < 256)
}

func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.ProjectCreate); err != nil {
		return err
	}
	var req createProjectReq
	if err := decode(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	req.Name = strings.ToLower(strings.TrimSpace(req.Name))
	if !projectNameRE.MatchString(req.Name) {
		return errf(400, "bad_request", "project name must be lowercase letters, digits and dashes (max 40)")
	}
	if !validRootDir(req.RootDir) {
		return errf(400, "bad_request", "root_dir must be a relative path")
	}
	if err := validateOverrides(req.Build); err != nil {
		return err
	}
	if req.ConfigOverride != "" {
		if _, err := policy.Parse([]byte(req.ConfigOverride)); err != nil {
			return errf(400, "bad_request", "%v", err)
		}
	}
	switch req.TrustClass {
	case "", "trusted", "untrusted":
	case "privileged":
		if err := s.requireNode(r, auth.PrivilegedCreate); err != nil {
			return err
		}
	default:
		return errf(400, "bad_request", "invalid trust_class")
	}
	proj := &store.Project{Name: req.Name, RootDir: firstNonEmpty(req.RootDir, "."), ProductionBranch: req.ProductionBranch, TrustClass: firstNonEmpty(req.TrustClass, "trusted"),
		PreviewsEnabled: req.PreviewsEnabled, AutoDeploy: req.AutoDeploy == nil || *req.AutoDeploy, BuildOverrides: req.Build, ConfigOverride: req.ConfigOverride}
	switch {
	case req.GitConnectionID != "":
		conn, repo, err := s.resolveRepo(ctx, req.GitConnectionID, req.RepoID)
		if err != nil {
			return err
		}
		proj.GitConnectionID, proj.RepoID, proj.RepoFullName, proj.CloneURL = conn.ID, repo.ID, repo.FullName, repo.CloneURL
		if proj.ProductionBranch == "" {
			proj.ProductionBranch = repo.DefaultBranch
		}
	case req.CloneURL != "":
		if _, err := git.ValidateCloneURL(ctx, req.CloneURL, nil); err != nil {
			return errf(400, "bad_request", "%v", err)
		}
		proj.CloneURL = req.CloneURL
		proj.RepoFullName = strings.TrimSuffix(strings.TrimPrefix(req.CloneURL, "https://"), ".git")
	}
	if proj.ProductionBranch == "" {
		proj.ProductionBranch = "main"
	}
	if !regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`).MatchString(proj.ProductionBranch) {
		return errf(400, "bad_request", "invalid production branch")
	}
	if err := s.S.CreateProject(ctx, proj); err != nil {
		return errf(409, "conflict", "a project named %q already exists", req.Name)
	}
	p := principal(r)
	_ = s.S.SetMember(ctx, proj.ID, p.User.ID, model.RoleAdmin)
	env, err := s.S.GetEnvironmentByName(ctx, proj.ID, "production")
	if err != nil {
		return err
	}
	_ = s.S.SetGeneratedHostname(ctx, env.ID, s.P.GeneratedHostname(proj.Name, ""))
	for k, v := range req.Env {
		if !policy.ValidEnvName(k) {
			continue
		}
		_, _ = s.P.Secrets.Set(ctx, secrets.SetReq{Ref: secrets.Ref{Scope: secrets.ScopeEnvironment, ProjectID: proj.ID, EnvironmentID: env.ID, Name: k},
			Value: v, Sensitive: true, Actor: s.secretActor(r)})
	}
	s.audit(r, "project.create", "project", proj.ID, proj.ID, audit.Success, map[string]string{"repository": proj.RepoFullName, "trust_class": proj.TrustClass})
	var dep *store.Deployment
	if (req.DeployNow == nil || *req.DeployNow) && proj.CloneURL != "" {
		dep, err = s.createDeployment(r, proj, env, "manual", "", "")
		if err != nil {
			return err
		}
	}
	proj, _ = s.S.GetProject(ctx, proj.ID)
	writeJSON(w, 201, map[string]any{"project": proj, "deployment": dep})
	return nil
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.ProjectCreate); err != nil {
		return err
	}
	var req struct {
		GitConnectionID string               `json:"git_connection_id"`
		RepoID          int64                `json:"repo_id"`
		CloneURL        string               `json:"clone_url"`
		Branch          string               `json:"branch"`
		RootDir         string               `json:"root_dir"`
		Build           store.BuildOverrides `json:"build"`
		ConfigOverride  string               `json:"config_override"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	if !validRootDir(req.RootDir) {
		return errf(400, "bad_request", "root_dir must be relative")
	}
	ctx := r.Context()
	src := builder.SourceSpec{Kind: "git"}
	switch {
	case req.GitConnectionID != "":
		conn, repo, err := s.resolveRepo(ctx, req.GitConnectionID, req.RepoID)
		if err != nil {
			return err
		}
		app, err := s.P.GitHub.App(ctx)
		if err != nil {
			return err
		}
		tok, err := app.InstallationToken(ctx, conn.InstallationID, []int64{repo.ID}, github.DefaultPermissions)
		if err != nil {
			return errf(502, "github", "could not obtain a repository token")
		}
		src.CloneURL, src.Token, src.Ref, src.AllowedHosts = repo.CloneURL, tok.Token, firstNonEmpty(req.Branch, repo.DefaultBranch), []string{hostOf(repo.CloneURL)}
	case req.CloneURL != "":
		src.CloneURL, src.Ref = req.CloneURL, firstNonEmpty(req.Branch, "main")
	default:
		return errf(400, "bad_request", "git_connection_id+repo_id or clone_url required")
	}
	plan, err := s.P.Builder.Plan(ctx, builder.PlanReq{DeploymentID: "dep_planpreviewaaaaaaaaaaaaaaaaaa", ProjectID: "prj_planpreviewaaaaaaaaaaaaaaaaaa",
		Source: src, RootDir: firstNonEmpty(req.RootDir, "."), ConfigOverride: req.ConfigOverride,
		Overrides: detect.Overrides{Strategy: req.Build.Strategy, BuildCommand: req.Build.BuildCommand, StartCommand: req.Build.StartCommand, OutputDir: req.Build.OutputDir, Port: req.Build.Port}})
	if err != nil {
		return err
	}
	writeJSON(w, 200, plan)
	return nil
}

func hostOf(u string) string {
	u = strings.TrimPrefix(u, "https://")
	h, _, _ := strings.Cut(u, "/")
	return h
}

func firstNonEmpty(a ...string) string {
	for _, x := range a {
		if x != "" {
			return x
		}
	}
	return ""
}

func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.ProjectRead)
	if err != nil {
		return err
	}
	ctx := r.Context()
	envs, err := s.S.ListEnvironments(ctx, proj.ID)
	if err != nil {
		return err
	}
	doms, _ := s.S.DomainsForProject(ctx, proj.ID)
	var out []*envSummary
	for _, e := range envs {
		out = append(out, s.envSummary(ctx, e, doms))
	}
	p := principal(r)
	role, _ := s.S.MemberRole(ctx, proj.ID, p.User.ID)
	if p.User.Role == model.RoleOwner {
		role = model.RoleOwner
	}
	writeJSON(w, 200, map[string]any{"project": projectView{Project: proj, Role: role, SourceKind: sourceKind(proj)}, "environments": out})
	return nil
}

func (s *Server) handleUpdateProject(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.ProjectSettings)
	if err != nil {
		return err
	}
	var req struct {
		ProductionBranch    *string               `json:"production_branch"`
		RootDir             *string               `json:"root_dir"`
		AutoDeploy          *bool                 `json:"auto_deploy"`
		PreviewsEnabled     *bool                 `json:"previews_enabled"`
		AllowPublicForks    *bool                 `json:"allow_public_forks"`
		TrustClass          *string               `json:"trust_class"`
		PreferGVisor        *bool                 `json:"prefer_gvisor"`
		GrantedCapabilities *[]string             `json:"granted_capabilities"`
		Build               *store.BuildOverrides `json:"build"`
		ConfigOverride      *string               `json:"config_override"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	u := store.ProjectUpdate{ProductionBranch: req.ProductionBranch, AutoDeploy: req.AutoDeploy, PreviewsEnabled: req.PreviewsEnabled, PreferGVisor: req.PreferGVisor}
	if req.RootDir != nil {
		if !validRootDir(*req.RootDir) {
			return errf(400, "bad_request", "root_dir must be relative")
		}
		u.RootDir = req.RootDir
	}
	if req.Build != nil {
		if err := validateOverrides(*req.Build); err != nil {
			return err
		}
		u.BuildOverrides = req.Build
	}
	if req.ConfigOverride != nil {
		if *req.ConfigOverride != "" {
			if _, err := policy.Parse([]byte(*req.ConfigOverride)); err != nil {
				return errf(400, "bad_request", "%v", err)
			}
		}
		u.ConfigOverride = req.ConfigOverride
	}
	details := map[string]string{}
	if req.AllowPublicForks != nil || req.TrustClass != nil {
		if _, err := s.requireProject(r, proj.ID, auth.ProjectTrust); err != nil {
			return err
		}
		u.AllowPublicForks = req.AllowPublicForks
		if req.TrustClass != nil {
			switch *req.TrustClass {
			case "trusted", "untrusted":
			case "privileged":
				if _, err := s.requireProject(r, proj.ID, auth.CapabilityGrant); err != nil {
					return err
				}
			default:
				return errf(400, "bad_request", "invalid trust class")
			}
			u.TrustClass = req.TrustClass
			details["trust_class"] = *req.TrustClass
		}
		if req.AllowPublicForks != nil {
			details["policy"] = fmt.Sprintf("allow_public_forks=%v", *req.AllowPublicForks)
		}
	}
	if req.GrantedCapabilities != nil {
		if _, err := s.requireProject(r, proj.ID, auth.CapabilityGrant); err != nil {
			return err
		}
		for _, c := range *req.GrantedCapabilities {
			if !policy.KnownCapabilities[c] {
				return errf(400, "bad_request", "unknown capability %q", c)
			}
		}
		caps := append([]string(nil), *req.GrantedCapabilities...)
		sort.Strings(caps)
		u.GrantedCapabilities = &caps
		details["capability"] = strings.Join(caps, ",")
	}
	if err := s.S.UpdateProject(r.Context(), proj.ID, u); err != nil {
		return err
	}
	action := "project.update"
	if details["capability"] != "" {
		action = "project.capability_grant"
	}
	s.audit(r, action, "project", proj.ID, proj.ID, audit.Success, details)
	proj, _ = s.S.GetProject(r.Context(), proj.ID)
	writeJSON(w, 200, proj)
	return nil
}

func (s *Server) handleDeleteProject(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.ProjectDelete)
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := s.S.SoftDeleteProject(ctx, proj.ID); err != nil {
		return err
	}
	_ = s.P.Secrets.DeleteProject(ctx, secrets.DeleteProjectReq{ProjectID: proj.ID, Actor: s.secretActor(r)})
	if _, err := s.S.Enqueue(ctx, platform.JobProjectDelete, "project.delete:"+proj.ID, map[string]string{"project_id": proj.ID}, 10); err != nil {
		return err
	}
	s.audit(r, "project.delete", "project", proj.ID, proj.ID, audit.Success, map[string]string{"repository": proj.RepoFullName})
	writeJSON(w, 202, map[string]bool{"ok": true})
	return nil
}

func (s *Server) handleCreateEnvironment(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.ProjectSettings)
	if err != nil {
		return err
	}
	var req struct {
		Name   string `json:"name"`
		Branch string `json:"branch"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	if !envNameRE.MatchString(req.Name) || req.Name == "production" || strings.HasPrefix(req.Name, "pr-") {
		return errf(400, "bad_request", "invalid environment name")
	}
	if req.Branch == "" {
		req.Branch = req.Name
	}
	e := &store.Environment{ProjectID: proj.ID, Name: req.Name, Kind: "staging", Branch: req.Branch, GeneratedHostname: s.P.GeneratedHostname(proj.Name, req.Name)}
	if err := s.S.CreateEnvironment(r.Context(), e); err != nil {
		return errf(409, "conflict", "environment exists")
	}
	s.audit(r, "environment.create", "environment", e.ID, proj.ID, audit.Success, nil)
	writeJSON(w, 201, e)
	return nil
}

func (s *Server) handleDeleteEnvironment(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.ProjectSettings)
	if err != nil {
		return err
	}
	e, err := s.S.GetEnvironment(r.Context(), r.PathValue("env"))
	if err != nil || e.ProjectID != proj.ID {
		return errNotFound
	}
	if e.Kind == "production" {
		return errf(400, "bad_request", "the production environment cannot be deleted; delete the project instead")
	}
	err = s.S.Tx(r.Context(), func(tx *sql.Tx) error {
		if err := store.MarkEnvDeletingTx(r.Context(), tx, e.ID); err != nil {
			return err
		}
		_, _, err := store.EnqueueTx(r.Context(), tx, platform.JobEnvTeardown, "teardown:"+e.ID, map[string]string{"environment_id": e.ID}, 10)
		return err
	})
	if err != nil {
		return err
	}
	s.audit(r, "environment.delete", "environment", e.ID, proj.ID, audit.Success, nil)
	writeJSON(w, 202, map[string]bool{"ok": true})
	return nil
}

func (s *Server) handleMembers(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.ProjectRead)
	if err != nil {
		return err
	}
	ms, err := s.S.ListMembers(r.Context(), proj.ID)
	if err != nil {
		return err
	}
	if ms == nil {
		ms = []store.Member{}
	}
	writeJSON(w, 200, ms)
	return nil
}

func (s *Server) handleSetMember(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.MembersManage)
	if err != nil {
		return err
	}
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Role != model.RoleAdmin && req.Role != model.RoleDeveloper && req.Role != model.RoleViewer {
		return errf(400, "bad_request", "role must be admin, developer or viewer")
	}
	u, err := s.S.GetUserByEmail(r.Context(), strings.ToLower(strings.TrimSpace(req.Email)))
	if err != nil {
		return errf(404, "not_found", "no user with that email")
	}
	if err := s.S.SetMember(r.Context(), proj.ID, u.ID, req.Role); err != nil {
		return err
	}
	s.audit(r, "project.member_set", "user", u.ID, proj.ID, audit.Success, map[string]string{"role": req.Role, "user_id": u.ID})
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.MembersManage)
	if err != nil {
		return err
	}
	uid := r.PathValue("user")
	if err := s.S.RemoveMember(r.Context(), proj.ID, uid); err != nil {
		return err
	}
	s.audit(r, "project.member_remove", "user", uid, proj.ID, audit.Success, map[string]string{"user_id": uid})
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func (s *Server) secretActor(r *http.Request) secrets.Actor {
	p := principal(r)
	a := secrets.Actor{Type: audit.ActorUser, SourceIP: s.clientIP(r)}
	if p != nil {
		a.ID, a.MFA = p.User.ID, p.mfa()
		if p.Session != nil {
			a.SessionID = p.Session.ID[:16]
		}
		if p.Token != nil {
			a.Type = audit.ActorToken
		}
	}
	return a
}
