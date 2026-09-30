package api

import (
	"net/http"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/auth"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/policy"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/secrets"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// secretRef resolves scope parameters against the project so a caller can
// never address another project's secrets (IDOR, Q9).
func (s *Server) secretRef(r *http.Request, proj *store.Project, scope, env, name string) (secrets.Ref, error) {
	ref := secrets.Ref{Scope: scope, ProjectID: proj.ID, Name: name}
	switch scope {
	case secrets.ScopeProject, secrets.ScopePreview:
	case secrets.ScopeEnvironment:
		e, err := s.projectEnv(r, proj, env)
		if err != nil {
			return ref, err
		}
		ref.EnvironmentID = e.ID
	default:
		return ref, errf(400, "bad_request", "scope must be project, preview or environment")
	}
	return ref, nil
}

func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.SecretsList)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	scope := firstNonEmpty(q.Get("scope"), secrets.ScopeEnvironment)
	ref, err := s.secretRef(r, proj, scope, q.Get("environment"), "X")
	if err != nil {
		return err
	}
	ms, err := s.P.Secrets.List(r.Context(), secrets.ListReq{Scope: ref.Scope, ProjectID: ref.ProjectID, EnvironmentID: ref.EnvironmentID})
	if err != nil {
		return err
	}
	if ms == nil {
		ms = []secrets.Meta{}
	}
	writeJSON(w, 200, ms)
	return nil
}

func (s *Server) handleSetSecret(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.SecretsWrite)
	if err != nil {
		return err
	}
	var req struct {
		Scope        string `json:"scope"`
		Environment  string `json:"environment"`
		Name         string `json:"name"`
		Value        string `json:"value"`
		Sensitive    *bool  `json:"sensitive"`
		BuildVisible bool   `json:"build_visible"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	if !policy.ValidEnvName(req.Name) || strings.HasPrefix(req.Name, "OPENDEPLOY_") {
		return errf(400, "bad_request", "name must be UPPER_SNAKE_CASE and not start with OPENDEPLOY_")
	}
	ref, err := s.secretRef(r, proj, firstNonEmpty(req.Scope, secrets.ScopeEnvironment), req.Environment, req.Name)
	if err != nil {
		return err
	}
	sensitive := req.Sensitive == nil || *req.Sensitive
	m, err := s.P.Secrets.Set(r.Context(), secrets.SetReq{Ref: ref, Value: req.Value, Sensitive: sensitive, BuildVisible: req.BuildVisible, Actor: s.secretActor(r)})
	if err != nil {
		return err
	}
	writeJSON(w, 200, m)
	return nil
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.SecretsWrite)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	ref, err := s.secretRef(r, proj, firstNonEmpty(q.Get("scope"), secrets.ScopeEnvironment), q.Get("environment"), q.Get("name"))
	if err != nil {
		return err
	}
	if err := s.P.Secrets.Delete(r.Context(), secrets.DeleteReq{Ref: ref, Actor: s.secretActor(r)}); err != nil {
		return err
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func (s *Server) handleRevealSecret(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.SecretsReveal)
	if err != nil {
		return err
	}
	var req struct {
		Reason string `json:"reason"`
	}
	_ = decode(r, &req)
	res, err := s.P.Secrets.Reveal(r.Context(), secrets.RevealReq{ID: r.PathValue("secret"), ProjectID: proj.ID, Actor: s.secretActor(r), Reason: req.Reason})
	if err != nil {
		return err
	}
	writeJSON(w, 200, res)
	return nil
}

// Instance-wide defaults (owner).
func (s *Server) handleInstanceSecrets(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.NodeSettings); err != nil {
		return err
	}
	ms, err := s.P.Secrets.List(r.Context(), secrets.ListReq{Scope: secrets.ScopeInstance})
	if err != nil {
		return err
	}
	out := []secrets.Meta{}
	for _, m := range ms {
		if !strings.HasPrefix(m.Name, "opendeploy.") { // internal credentials are hidden
			out = append(out, m)
		}
	}
	writeJSON(w, 200, out)
	return nil
}

func (s *Server) handleSetInstanceSecret(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.NodeSettings); err != nil {
		return err
	}
	var req struct {
		Name      string `json:"name"`
		Value     string `json:"value"`
		Sensitive *bool  `json:"sensitive"`
		Delete    bool   `json:"delete"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	if !policy.ValidEnvName(req.Name) {
		return errf(400, "bad_request", "invalid name")
	}
	ref := secrets.Ref{Scope: secrets.ScopeInstance, Name: req.Name}
	if req.Delete {
		if err := s.P.Secrets.Delete(r.Context(), secrets.DeleteReq{Ref: ref, Actor: s.secretActor(r)}); err != nil {
			return err
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
		return nil
	}
	m, err := s.P.Secrets.Set(r.Context(), secrets.SetReq{Ref: ref, Value: req.Value, Sensitive: req.Sensitive == nil || *req.Sensitive, Actor: s.secretActor(r)})
	if err != nil {
		return err
	}
	s.audit(r, "settings.instance_secret", "secret", m.ID, "", audit.Success, map[string]string{"secret_name": req.Name})
	writeJSON(w, 200, m)
	return nil
}
