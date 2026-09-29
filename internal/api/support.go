package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/auth"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/platform"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/secrets"
)

func (s *Server) supportRoutes(a func(handler) http.HandlerFunc) {
	s.mux.HandleFunc("POST /api/v2/system/support-bundle", a(s.handleSupportBundle))
	s.mux.HandleFunc("POST /api/v2/system/incident/revoke-credentials", a(s.handleRevokeAllCredentials))
	s.mux.HandleFunc("POST /api/v2/system/incident/rotate-kek", a(s.handleRotateKEK))
}

// handleRevokeAllCredentials signs out every user except the caller and
// revokes every API token (runbook R1).
func (s *Server) handleRevokeAllCredentials(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.IncidentResponse); err != nil {
		return err
	}
	keep := ""
	if p := principal(r); p.Session != nil {
		keep = p.Session.ID
	}
	ns, nt, err := s.S.RevokeAllCredentials(r.Context(), keep)
	if err != nil {
		return err
	}
	s.audit(r, "incident.revoke_credentials", "node", "credentials", "", audit.Success,
		map[string]string{"sessions": strconv.FormatInt(ns, 10), "tokens": strconv.FormatInt(nt, 10)})
	writeJSON(w, 200, map[string]int64{"sessions_revoked": ns, "tokens_revoked": nt})
	return nil
}

type kekRotator interface {
	RotateKEK(ctx context.Context) (*secrets.RotateResp, error)
}

// handleRotateKEK re-wraps every secret under a new key-encryption key; the
// old key is destroyed (runbook R1). Secret values themselves must still be
// rotated at their source if they may have been read.
func (s *Server) handleRotateKEK(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.IncidentResponse); err != nil {
		return err
	}
	rot, ok := s.P.Secrets.(kekRotator)
	if !ok {
		return errf(409, "unavailable", "secretd does not support key rotation on this node")
	}
	res, err := rot.RotateKEK(r.Context())
	if err != nil {
		s.audit(r, "incident.rotate_kek", "node", "kek", "", audit.Failure, map[string]string{"reason": err.Error()})
		return err
	}
	s.audit(r, "incident.rotate_kek", "node", res.KEKID, "", audit.Success, map[string]string{"rewrapped": strconv.Itoa(res.Rewrapped)})
	writeJSON(w, 200, res)
	return nil
}

// handleSupportBundle streams a redacted diagnostics archive built by hostd.
// It still reveals topology and logs: owner only, fresh re-auth, audited.
func (s *Server) handleSupportBundle(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireNode(r, auth.SupportBundle); err != nil {
		return err
	}
	b, err := s.P.SupportBundle(r.Context())
	if err == platform.ErrNoHostAgent {
		return errf(409, "unavailable", "%v", err)
	}
	if err != nil {
		return err
	}
	dir := filepath.Join(s.P.Node.DataDir, "support")
	if filepath.Dir(filepath.Clean(b.Path)) != dir || !strings.HasSuffix(b.Path, ".tar.gz") {
		return fmt.Errorf("unexpected support bundle path %q", b.Path)
	}
	f, err := os.Open(b.Path)
	if err != nil {
		return err
	}
	defer func() {
		f.Close()
		_ = os.Remove(b.Path)
	}()
	s.audit(r, "node.support_bundle", "node", filepath.Base(b.Path), "", audit.Success, map[string]string{"sha256": b.SHA256})
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(b.Path)+`"`)
	w.Header().Set("X-Content-SHA256", b.SHA256)
	w.Header().Set("Cache-Control", "no-store")
	_, err = io.Copy(w, f)
	return err
}
