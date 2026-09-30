package api

import (
	"net/http"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/auth"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

func (s *Server) volumeRoutes(a func(handler) http.HandlerFunc) {
	s.mux.HandleFunc("GET /api/v2/projects/{id}/volumes", a(s.handleVolumes))
	s.mux.HandleFunc("PATCH /api/v2/projects/{id}/volumes/{vol}", a(s.handleVolumeProtection))
	s.mux.HandleFunc("DELETE /api/v2/projects/{id}/volumes/{vol}", a(s.handleDeleteVolume))
	s.mux.HandleFunc("GET /api/v2/projects/{id}/services", a(s.handleServices))
	s.mux.HandleFunc("GET /api/v2/projects/{id}/preview-protection", a(s.handleGetPreviewProtection))
	s.mux.HandleFunc("PUT /api/v2/projects/{id}/preview-protection", a(s.handleSetPreviewProtection))
}

func (s *Server) handleVolumes(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.ProjectRead)
	if err != nil {
		return err
	}
	vs, err := s.S.VolumesForProject(r.Context(), proj.ID)
	if err != nil {
		return err
	}
	if vs == nil {
		vs = []*store.Volume{}
	}
	writeJSON(w, 200, vs)
	return nil
}

// Volume protection changes and deletion are destructive: they need the
// volumes permission plus recent re-authentication.
func (s *Server) volumeAction(r *http.Request) (*store.Project, error) {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.VolumesManage)
	if err != nil {
		return nil, err
	}
	if err := s.requireReauth(r, auth.ProjectDelete); err != nil {
		return nil, err
	}
	return proj, nil
}

func (s *Server) handleVolumeProtection(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.volumeAction(r)
	if err != nil {
		return err
	}
	var req struct {
		DeletionProtection bool `json:"deletion_protection"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	if err := s.S.SetVolumeProtection(r.Context(), r.PathValue("vol"), proj.ID, req.DeletionProtection); err != nil {
		return err
	}
	s.audit(r, "volume.protection", "volume", r.PathValue("vol"), proj.ID, audit.Success, map[string]string{"policy": boolStr(req.DeletionProtection)})
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func (s *Server) handleDeleteVolume(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.volumeAction(r)
	if err != nil {
		return err
	}
	if err := s.S.TombstoneVolume(r.Context(), r.PathValue("vol"), proj.ID); err != nil {
		return err
	}
	s.audit(r, "volume.delete", "volume", r.PathValue("vol"), proj.ID, audit.Success, nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.ProjectRead)
	if err != nil {
		return err
	}
	env, err := s.projectEnv(r, proj, r.URL.Query().Get("environment"))
	if err != nil {
		return err
	}
	svcs, err := s.S.ServicesForEnvironment(r.Context(), env.ID)
	if err != nil {
		return err
	}
	if svcs == nil {
		svcs = []*store.ServiceRow{}
	}
	writeJSON(w, 200, svcs)
	return nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
