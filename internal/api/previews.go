package api

import (
	"net/http"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/auth"
)

func (s *Server) handleGetPreviewProtection(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.ProjectRead)
	if err != nil {
		return err
	}
	pp, err := s.P.GetPreviewProtection(r.Context(), proj.ID)
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"enabled": pp.Enabled, "user": pp.User})
	return nil
}

func (s *Server) handleSetPreviewProtection(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.ProjectSettings)
	if err != nil {
		return err
	}
	var req struct {
		Enabled  bool   `json:"enabled"`
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	if err := s.P.SetPreviewProtection(r.Context(), proj.ID, req.Enabled, req.User, req.Password); err != nil {
		return errf(400, "bad_request", "%v", err)
	}
	s.audit(r, "project.preview_protection", "project", proj.ID, proj.ID, audit.Success, map[string]string{"policy": boolStr(req.Enabled)})
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}
