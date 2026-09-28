package api

import (
	"net/http"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/auth"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/platform"
)

func (s *Server) backupRoutes(a func(handler) http.HandlerFunc) {
	s.mux.HandleFunc("GET /api/v2/system/backups", a(s.handleBackups))
	s.mux.HandleFunc("POST /api/v2/system/backups", a(s.handleRunBackup))
	s.mux.HandleFunc("POST /api/v2/system/backups/master-key", a(s.handleExportMasterKey))
}

func (s *Server) handleBackups(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.BackupManage); err != nil {
		return err
	}
	out := map[string]any{"status": s.P.BackupStatus(r.Context())}
	list, err := s.P.ListBackups(r.Context(), 50)
	if err != nil {
		out["list_error"] = err.Error()
		list = []platform.BackupSummary{}
	}
	out["backups"] = list
	writeJSON(w, 200, out)
	return nil
}

func (s *Server) handleRunBackup(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.BackupManage); err != nil {
		return err
	}
	id, err := s.P.EnqueueBackup(r.Context())
	if err != nil {
		return err
	}
	s.audit(r, "backup.request", "backup", id, "", audit.Success, nil)
	writeJSON(w, 202, map[string]string{"job_id": id})
	return nil
}

// The master key decrypts every backup: owner only, fresh re-auth, audited.
func (s *Server) handleExportMasterKey(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.BackupRestore); err != nil {
		return err
	}
	k, err := s.P.ExportMasterKey()
	if err != nil {
		return err
	}
	s.audit(r, "backup.master_key_export", "backup", "master-key", "", audit.Success, nil)
	writeJSON(w, 200, map[string]string{"master_key": k})
	return nil
}
