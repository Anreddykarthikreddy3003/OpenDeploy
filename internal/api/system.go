package api

import (
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/auth"
)

func (s *Server) handleSystemStatus(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.SystemRead); err != nil {
		return err
	}
	ctx := r.Context()
	out := map[string]any{
		"version":      versionString(),
		"profile":      s.P.Node.Profile,
		"ingress_mode": s.P.Node.Ingress.Mode,
		"base_domain":  s.P.BaseDomain(),
		"degraded":     s.S.DB.Degraded(),
		"dev_mode":     s.P.Node.DevMode,
		"require_mfa":  s.RequireMFA,
	}
	if hc, err := s.P.HostCapabilities(ctx); err == nil {
		out["capabilities"] = hc
	} else {
		out["capabilities_error"] = err.Error()
	}
	if st, err := s.P.Egress.Status(ctx); err == nil {
		out["network_policy"] = st
	}
	if s.P.Node.Ingress.Mode == "relay" && s.P.Relay != nil {
		if st, err := s.P.Relay.Status(ctx); err == nil {
			out["relay"] = st
		} else {
			out["relay_error"] = "relay agent unreachable"
		}
	}
	if cur, err := s.P.Router.Current(ctx); err == nil {
		out["edge"] = map[string]any{"digest": cur.Digest, "routes": len(cur.Table.Routes)}
	} else {
		out["edge_error"] = err.Error()
	}
	if s.P.AuditReader != nil && s.requireNode(r, auth.AuditRead) == nil {
		if v, err := s.P.AuditReader.Verify(ctx); err == nil {
			out["audit"] = v
		}
	}
	breakers, _ := s.S.ListBreakers(ctx)
	out["breakers"] = breakers
	writeJSON(w, 200, out)
	return nil
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	aq := audit.Query{ActionPrefix: q.Get("action"), ActorID: q.Get("actor"), Descending: true}
	aq.Limit, _ = strconv.Atoi(q.Get("limit"))
	aq.BeforeSeq, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	if pid := q.Get("project"); pid != "" {
		proj, err := s.requireProject(r, pid, auth.ProjectAuditRead)
		if err != nil {
			return err
		}
		aq.ProjectID = proj.ID
	} else if err := s.requireNode(r, auth.AuditRead); err != nil {
		return err
	}
	if s.P.AuditReader == nil {
		return errf(503, "unavailable", "audit service unavailable")
	}
	evs, err := s.P.AuditReader.Query(r.Context(), aq)
	if err != nil {
		return err
	}
	if evs == nil {
		evs = []audit.Event{}
	}
	writeJSON(w, 200, evs)
	return nil
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.AuditRead); err != nil {
		return err
	}
	if s.P.AuditReader == nil {
		return errf(503, "unavailable", "audit service unavailable")
	}
	v, err := s.P.AuditReader.Verify(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.NodeSettings); err != nil {
		return err
	}
	jobs, err := s.S.ListJobs(r.Context(), r.URL.Query().Get("state"), 200)
	if err != nil {
		return err
	}
	writeJSON(w, 200, jobs)
	return nil
}

func (s *Server) handleResetBreaker(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.NodeSettings); err != nil {
		return err
	}
	key := r.PathValue("key")
	if err := s.S.ResetBreaker(r.Context(), key); err != nil {
		return err
	}
	s.audit(r, "system.breaker_reset", "breaker", key, "", audit.Success, nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	st := 200
	body := map[string]any{"ok": true}
	if d := s.S.DB.Degraded(); d != "" {
		st, body = 503, map[string]any{"ok": false, "degraded": d}
	}
	writeJSON(w, st, body)
}

// spa serves the embedded dashboard with index.html fallback.
func (s *Server) spa(w http.ResponseWriter, r *http.Request) {
	if s.UI == nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("OpenDeploy API is running. The dashboard was not embedded in this build.\n"))
		return
	}
	p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if p == "" {
		p = "index.html"
	}
	if fi, err := fs.Stat(s.UI, p); err != nil || fi.IsDir() {
		p = "index.html"
	}
	if strings.HasPrefix(p, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeFileFS(w, r, s.UI, p)
}

func (s *Server) routes() {
	m := s.mux
	w := s.wrap
	a := func(h handler) http.HandlerFunc { return s.authed(h, false) }
	pre := func(h handler) http.HandlerFunc { return s.authed(h, true) }

	m.HandleFunc("GET /healthz", s.handleHealthz)
	m.HandleFunc("POST /webhooks/github", s.handleWebhook)

	// auth
	m.HandleFunc("GET /api/v2/setup", w(s.handleSetupStatus))
	m.HandleFunc("POST /api/v2/auth/bootstrap", w(s.handleBootstrap))
	m.HandleFunc("POST /api/v2/auth/login", w(s.handleLogin))
	m.HandleFunc("POST /api/v2/auth/mfa", pre(s.handleMFA))
	m.HandleFunc("POST /api/v2/auth/logout", pre(s.handleLogout))
	m.HandleFunc("GET /api/v2/auth/me", pre(s.handleMe))
	m.HandleFunc("POST /api/v2/auth/reauth", a(s.handleReauth))
	m.HandleFunc("POST /api/v2/auth/totp/enroll", pre(s.handleTOTPEnroll))
	m.HandleFunc("POST /api/v2/auth/totp/confirm", pre(s.handleTOTPConfirm))
	m.HandleFunc("DELETE /api/v2/auth/totp", a(s.handleTOTPDisable))
	m.HandleFunc("GET /api/v2/auth/sessions", a(s.handleSessions))
	m.HandleFunc("DELETE /api/v2/auth/sessions/{id}", a(s.handleRevokeSession))
	m.HandleFunc("POST /api/v2/auth/sessions/revoke-others", a(s.handleRevokeOtherSessions))
	m.HandleFunc("GET /api/v2/auth/tokens", a(s.handleTokens))
	m.HandleFunc("POST /api/v2/auth/tokens", a(s.handleCreateToken))
	m.HandleFunc("DELETE /api/v2/auth/tokens/{id}", a(s.handleRevokeToken))
	s.webauthnRoutes(pre, a)

	// users
	m.HandleFunc("GET /api/v2/users", a(s.handleUsers))
	m.HandleFunc("POST /api/v2/users", a(s.handleCreateUser))
	m.HandleFunc("PATCH /api/v2/users/{id}", a(s.handleUpdateUser))

	// git
	m.HandleFunc("GET /api/v2/git", a(s.handleGitStatus))
	m.HandleFunc("POST /api/v2/git/github/manifest", a(s.handleManifest))
	m.HandleFunc("POST /api/v2/git/github/manifest/complete", a(s.handleManifestComplete))
	m.HandleFunc("POST /api/v2/git/github/sync", a(s.handleSync))
	m.HandleFunc("GET /api/v2/git/repositories", a(s.handleRepos))
	m.HandleFunc("GET /api/v2/git/repositories/{conn}/{repo}/branches", a(s.handleBranches))

	// projects & environments
	m.HandleFunc("GET /api/v2/projects", a(s.handleListProjects))
	m.HandleFunc("POST /api/v2/projects", a(s.handleCreateProject))
	m.HandleFunc("POST /api/v2/projects/plan", a(s.handlePlan))
	m.HandleFunc("GET /api/v2/projects/{id}", a(s.handleGetProject))
	m.HandleFunc("PATCH /api/v2/projects/{id}", a(s.handleUpdateProject))
	m.HandleFunc("DELETE /api/v2/projects/{id}", a(s.handleDeleteProject))
	m.HandleFunc("POST /api/v2/projects/{id}/environments", a(s.handleCreateEnvironment))
	m.HandleFunc("DELETE /api/v2/projects/{id}/environments/{env}", a(s.handleDeleteEnvironment))
	m.HandleFunc("GET /api/v2/projects/{id}/members", a(s.handleMembers))
	m.HandleFunc("PUT /api/v2/projects/{id}/members", a(s.handleSetMember))
	m.HandleFunc("DELETE /api/v2/projects/{id}/members/{user}", a(s.handleRemoveMember))

	// deployments
	m.HandleFunc("GET /api/v2/projects/{id}/deployments", a(s.handleListDeployments))
	m.HandleFunc("POST /api/v2/projects/{id}/deployments", a(s.handleDeploy))
	m.HandleFunc("POST /api/v2/projects/{id}/deployments/upload", a(s.handleUpload))
	m.HandleFunc("GET /api/v2/deployments/{id}", a(s.handleGetDeployment))
	m.HandleFunc("GET /api/v2/deployments/{id}/logs", a(s.handleLogs))
	m.HandleFunc("GET /api/v2/deployments/{id}/events", a(s.handleEvents))
	m.HandleFunc("POST /api/v2/deployments/{id}/cancel", a(s.handleCancel))
	m.HandleFunc("POST /api/v2/deployments/{id}/promote", a(s.handlePromote))
	m.HandleFunc("POST /api/v2/deployments/{id}/rollback", a(s.handleRollback))
	m.HandleFunc("POST /api/v2/deployments/{id}/redeploy", a(s.handleRollback))
	m.HandleFunc("GET /api/v2/environments/{env}/logs", a(s.handleRuntimeLogs))

	// secrets
	m.HandleFunc("GET /api/v2/projects/{id}/secrets", a(s.handleListSecrets))
	m.HandleFunc("PUT /api/v2/projects/{id}/secrets", a(s.handleSetSecret))
	m.HandleFunc("DELETE /api/v2/projects/{id}/secrets", a(s.handleDeleteSecret))
	m.HandleFunc("POST /api/v2/projects/{id}/secrets/{secret}/reveal", a(s.handleRevealSecret))
	m.HandleFunc("GET /api/v2/secrets", a(s.handleInstanceSecrets))
	m.HandleFunc("PUT /api/v2/secrets", a(s.handleSetInstanceSecret))

	s.domainRoutes(a)
	s.volumeRoutes(a)
	s.backupRoutes(a)
	s.updateRoutes(a)

	// system
	m.HandleFunc("GET /api/v2/system", a(s.handleSystemStatus))
	m.HandleFunc("GET /api/v2/system/audit", a(s.handleAudit))
	m.HandleFunc("GET /api/v2/system/audit/verify", a(s.handleAuditVerify))
	m.HandleFunc("GET /api/v2/system/jobs", a(s.handleJobs))
	m.HandleFunc("DELETE /api/v2/system/breakers/{key}", a(s.handleResetBreaker))

	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/"):
			writeJSON(w, 404, errNotFound)
		case r.Method == http.MethodGet || r.Method == http.MethodHead:
			s.spa(w, r)
		default:
			writeJSON(w, 405, errf(405, "method_not_allowed", "method not allowed"))
		}
	})
}
