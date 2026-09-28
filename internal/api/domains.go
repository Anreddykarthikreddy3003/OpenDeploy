package api

import (
	"errors"
	"net/http"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/auth"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/domains"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/platform"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// domainRoutes implements /api/v2/domains claim/verify/attach/detach
// (PRD §21, §10.2).
func (s *Server) domainRoutes(a func(handler) http.HandlerFunc) {
	s.mux.HandleFunc("GET /api/v2/projects/{id}/domains", a(s.handleListDomains))
	s.mux.HandleFunc("POST /api/v2/projects/{id}/domains", a(s.handleClaimDomain))
	s.mux.HandleFunc("GET /api/v2/domains/{dom}", a(s.handleGetDomain))
	s.mux.HandleFunc("POST /api/v2/domains/{dom}/verify", a(s.handleVerifyDomain))
	s.mux.HandleFunc("DELETE /api/v2/domains/{dom}", a(s.handleDetachDomain))
}

type domainView struct {
	*store.Domain
	Instructions *platform.DomainInstructions `json:"instructions,omitempty"`
}

func (s *Server) domainView(r *http.Request, d *store.Domain) domainView {
	v := domainView{Domain: d}
	if d.Status == "pending" {
		v.Instructions, _ = s.P.DomainInstructions(r.Context(), d)
	}
	return v
}

// domainFor loads a domain and authorises the action on its project. A
// domain of a project the caller cannot read is reported as not found.
func (s *Server) domainFor(r *http.Request, a auth.Action) (*store.Domain, *store.Project, error) {
	d, err := s.S.GetDomain(r.Context(), r.PathValue("dom"))
	if err != nil {
		return nil, nil, err
	}
	if d.ProjectID == "" {
		return nil, nil, errNotFound
	}
	proj, err := s.requireProject(r, d.ProjectID, a)
	if err != nil {
		return nil, nil, err
	}
	return d, proj, nil
}

func domainErr(err error) error {
	switch {
	case errors.Is(err, domains.ErrInvalidHostname), errors.Is(err, platform.ErrDomainReserved):
		return errf(400, "invalid_hostname", "%s", err.Error())
	case errors.Is(err, platform.ErrDomainQuota):
		return errf(409, "quota", "%s", err.Error())
	case errors.Is(err, platform.ErrClaimExpired):
		return errf(410, "claim_expired", "%s", err.Error())
	}
	return err
}

func (s *Server) handleListDomains(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.ProjectRead)
	if err != nil {
		return err
	}
	ds, err := s.S.DomainsForProject(r.Context(), proj.ID)
	if err != nil {
		return err
	}
	out := make([]domainView, 0, len(ds))
	for _, d := range ds {
		out = append(out, s.domainView(r, d))
	}
	writeJSON(w, 200, out)
	return nil
}

func (s *Server) handleClaimDomain(w http.ResponseWriter, r *http.Request) error {
	proj, err := s.requireProject(r, r.PathValue("id"), auth.DomainsManage)
	if err != nil {
		return err
	}
	var req struct {
		Hostname    string `json:"hostname"`
		Environment string `json:"environment"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	d, in, err := s.P.ClaimDomain(r.Context(), proj, req.Environment, req.Hostname)
	if err != nil {
		s.audit(r, "domain.claim", "domain", "", proj.ID, audit.Denied, map[string]string{"domain": truncateStr(req.Hostname, 253), "reason": truncateStr(err.Error(), 300)})
		return domainErr(err)
	}
	s.audit(r, "domain.claim", "domain", d.ID, proj.ID, audit.Success, map[string]string{"domain": d.Hostname})
	writeJSON(w, 201, domainView{Domain: d, Instructions: in})
	return nil
}

func (s *Server) handleGetDomain(w http.ResponseWriter, r *http.Request) error {
	d, _, err := s.domainFor(r, auth.ProjectRead)
	if err != nil {
		return err
	}
	writeJSON(w, 200, s.domainView(r, d))
	return nil
}

func (s *Server) handleVerifyDomain(w http.ResponseWriter, r *http.Request) error {
	d, proj, err := s.domainFor(r, auth.DomainsManage)
	if err != nil {
		return err
	}
	d, chk, err := s.P.VerifyDomain(r.Context(), d.ID)
	if errors.Is(err, platform.ErrNotVerified) {
		writeJSON(w, 422, map[string]any{"code": "not_verified", "message": err.Error(), "check": chk, "domain": s.domainView(r, d)})
		return nil
	}
	if err != nil {
		return domainErr(err)
	}
	s.audit(r, "domain.attach", "domain", d.ID, proj.ID, audit.Success, map[string]string{"domain": d.Hostname})
	writeJSON(w, 200, map[string]any{"domain": s.domainView(r, d), "check": chk})
	return nil
}

// Detaching takes a live site off the air, so it needs recent re-auth.
func (s *Server) handleDetachDomain(w http.ResponseWriter, r *http.Request) error {
	d, proj, err := s.domainFor(r, auth.DomainsManage)
	if err != nil {
		return err
	}
	if d.Status == "active" || d.Status == "verified" {
		if err := s.requireReauth(r, auth.ProjectDelete); err != nil {
			return err
		}
	}
	if err := s.P.DetachDomain(r.Context(), d); err != nil {
		return err
	}
	s.audit(r, "domain.detach", "domain", d.ID, proj.ID, audit.Success, map[string]string{"domain": d.Hostname})
	writeJSON(w, 200, map[string]bool{"ok": true})
	return nil
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
