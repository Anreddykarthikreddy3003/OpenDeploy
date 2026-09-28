package api

import (
	"errors"
	"net/http"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/auth"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/platform"
)

func (s *Server) updateRoutes(a func(handler) http.HandlerFunc) {
	s.mux.HandleFunc("GET /api/v2/system/updates", a(s.handleUpdateStatus))
	s.mux.HandleFunc("POST /api/v2/system/updates/check", a(s.handleUpdateCheck))
	s.mux.HandleFunc("POST /api/v2/system/updates/apply", a(s.handleUpdateApply))
}

func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.UpdateManage); err != nil {
		return err
	}
	writeJSON(w, 200, s.P.UpdateStatus(r.Context()))
	return nil
}

func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.UpdateManage); err != nil {
		return err
	}
	writeJSON(w, 200, s.P.CheckUpdates(r.Context()))
	return nil
}

// Installing platform code is the most privileged action: owner, fresh
// re-authentication (and MFA), audited.
func (s *Server) handleUpdateApply(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.UpdateTrust); err != nil {
		return err
	}
	var req struct {
		Version string `json:"version"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	err := s.P.ApplyUpdate(r.Context(), req.Version)
	res := audit.Success
	det := map[string]string{"update_version": req.Version}
	if err != nil {
		res, det["reason"] = audit.Failure, truncateStr(err.Error(), 300)
	}
	s.audit(r, "update.apply", "update", req.Version, "", res, det)
	if errors.Is(err, platform.ErrNoHostAgent) {
		return errf(503, "no_host_agent", "%s", err.Error())
	}
	if err != nil {
		return errf(409, "update_refused", "%s", err.Error())
	}
	writeJSON(w, 202, map[string]string{"status": "applying"})
	return nil
}
