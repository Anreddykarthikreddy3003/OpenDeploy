package secrets

import (
	"context"
	"errors"
	"strconv"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

// IPC operations.
const (
	OpSet           = "secret.set"
	OpList          = "secret.list"
	OpDelete        = "secret.delete"
	OpDeleteProject = "secret.delete_project"
	OpReveal        = "secret.reveal"
	OpResolve       = "secret.resolve"
	OpRotateKEK     = "secret.rotate_kek"
)

// Actor is the human/API identity on whose behalf platformd acts; secretd
// records it in its own audit events.
type Actor struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	SessionID string `json:"session_id,omitempty"`
	MFA       bool   `json:"mfa"`
	SourceIP  string `json:"source_ip,omitempty"`
}

type SetReq struct {
	Ref
	Value        string `json:"value"`
	Sensitive    bool   `json:"sensitive"`
	BuildVisible bool   `json:"build_visible"`
	Actor        Actor  `json:"actor"`
}

type ListReq struct {
	Scope         string `json:"scope"`
	ProjectID     string `json:"project_id,omitempty"`
	EnvironmentID string `json:"environment_id,omitempty"`
}

type DeleteReq struct {
	Ref
	Actor Actor `json:"actor"`
}

type DeleteProjectReq struct {
	ProjectID string `json:"project_id"`
	Actor     Actor  `json:"actor"`
}

type RevealReq struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Actor     Actor  `json:"actor"`
	// Justification is recorded in the audit event.
	Reason string `json:"reason,omitempty"`
}

type RevealResp struct {
	Meta  Meta   `json:"meta"`
	Value string `json:"value"`
}

type RotateResp struct {
	KEKID     string `json:"kek_id"`
	Rewrapped int    `json:"rewrapped"`
}

type Empty struct{}

// Service wires the Store to IPC with auditing.
type Service struct {
	Store *Store
	Audit audit.Sink
}

func (s *Service) audit(ctx context.Context, a Actor, action, projectID, resourceID, result string, d map[string]string) {
	if s.Audit == nil {
		return
	}
	at := a.Type
	if at == "" {
		at = audit.ActorService
	}
	_, _ = s.Audit.Append(ctx, audit.Event{ActorType: at, ActorID: a.ID, SessionID: a.SessionID, MFA: a.MFA, SourceIP: a.SourceIP,
		Action: action, ResourceType: "secret", ResourceID: resourceID, ProjectID: projectID, Result: result, Details: d})
}

func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNotFound):
		return ipc.Errorf(ipc.CodeNotFound, "secret not found")
	case errors.Is(err, ErrInvalid):
		return ipc.Errorf(ipc.CodeBadRequest, "%v", err)
	case errors.Is(err, ErrDenied):
		return ipc.Errorf(ipc.CodeForbidden, "%v", err)
	}
	return err
}

// Register exposes secretd. Only platformd may manage or resolve secrets;
// builderd and runtimed receive injection material via platformd, which is
// scoped per request. hostd may rotate the KEK.
func Register(srv *ipc.Server, s *Service) {
	p := []string{identity.Platform}
	ipc.Handle(srv, OpSet, p, func(ctx context.Context, _ ipc.Caller, r SetReq) (*Meta, error) {
		m, err := s.Store.Set(ctx, r.Ref, []byte(r.Value), r.Sensitive, r.BuildVisible, r.Actor.ID)
		res := audit.Success
		d := map[string]string{"secret_name": r.Name, "secret_scope": r.Scope}
		if err != nil {
			res = audit.Failure
		} else {
			d["secret_version"] = strconv.FormatInt(m.Version, 10)
		}
		s.audit(ctx, r.Actor, "secret.set", r.ProjectID, r.EnvironmentID, res, d)
		return m, mapErr(err)
	})
	ipc.Handle(srv, OpList, p, func(ctx context.Context, _ ipc.Caller, r ListReq) ([]Meta, error) {
		m, err := s.Store.List(ctx, r.Scope, r.ProjectID, r.EnvironmentID)
		return m, mapErr(err)
	})
	ipc.Handle(srv, OpDelete, p, func(ctx context.Context, _ ipc.Caller, r DeleteReq) (Empty, error) {
		err := s.Store.Delete(ctx, r.Ref)
		res := audit.Success
		if err != nil {
			res = audit.Failure
		}
		s.audit(ctx, r.Actor, "secret.delete", r.ProjectID, r.EnvironmentID, res, map[string]string{"secret_name": r.Name, "secret_scope": r.Scope})
		return Empty{}, mapErr(err)
	})
	ipc.Handle(srv, OpDeleteProject, p, func(ctx context.Context, _ ipc.Caller, r DeleteProjectReq) (Empty, error) {
		n, err := s.Store.DeleteProject(ctx, r.ProjectID)
		s.audit(ctx, r.Actor, "secret.delete_project", r.ProjectID, r.ProjectID, audit.Success, map[string]string{"count": strconv.FormatInt(n, 10)})
		return Empty{}, mapErr(err)
	})
	ipc.Handle(srv, OpReveal, p, func(ctx context.Context, _ ipc.Caller, r RevealReq) (*RevealResp, error) {
		m, v, err := s.Store.Reveal(ctx, r.ID, r.ProjectID)
		d := map[string]string{"reason": trunc(r.Reason, 200)}
		if err != nil {
			s.audit(ctx, r.Actor, "secret.reveal", r.ProjectID, r.ID, audit.Denied, d)
			return nil, mapErr(err)
		}
		d["secret_name"], d["secret_scope"], d["secret_version"] = m.Name, m.Scope, strconv.FormatInt(m.Version, 10)
		s.audit(ctx, r.Actor, "secret.reveal", r.ProjectID, r.ID, audit.Success, d)
		return &RevealResp{Meta: *m, Value: string(v)}, nil
	})
	ipc.Handle(srv, OpResolve, p, func(ctx context.Context, _ ipc.Caller, r ResolveReq) (*Resolved, error) {
		out, err := s.Store.Resolve(ctx, r)
		if err != nil {
			s.audit(ctx, Actor{Type: audit.ActorService, ID: identity.Platform}, "secret.resolve", r.ProjectID, r.EnvironmentID, audit.Denied,
				map[string]string{"reason": trunc(err.Error(), 200), "trust_class": r.TrustClass})
		}
		return out, mapErr(err)
	})
	ipc.Handle(srv, OpRotateKEK, []string{identity.Platform, identity.Host}, func(ctx context.Context, c ipc.Caller, _ Empty) (*RotateResp, error) {
		id, n, err := s.Store.RotateKEK(ctx)
		res := audit.Success
		if err != nil {
			res = audit.Failure
		}
		s.audit(ctx, Actor{Type: audit.ActorService, ID: c.Identity}, "secret.rotate_kek", "", id, res, map[string]string{"count": strconv.Itoa(n)})
		if err != nil {
			return nil, err
		}
		return &RotateResp{KEKID: id, Rewrapped: n}, nil
	})
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Client is the typed secretd client.
type Client struct{ C *ipc.Client }

func (c *Client) Set(ctx context.Context, r SetReq) (*Meta, error) {
	return ipc.Call[SetReq, *Meta](ctx, c.C, OpSet, r)
}
func (c *Client) List(ctx context.Context, r ListReq) ([]Meta, error) {
	return ipc.Call[ListReq, []Meta](ctx, c.C, OpList, r)
}
func (c *Client) Delete(ctx context.Context, r DeleteReq) error {
	_, err := ipc.Call[DeleteReq, Empty](ctx, c.C, OpDelete, r)
	return err
}
func (c *Client) DeleteProject(ctx context.Context, r DeleteProjectReq) error {
	_, err := ipc.Call[DeleteProjectReq, Empty](ctx, c.C, OpDeleteProject, r)
	return err
}
func (c *Client) Reveal(ctx context.Context, r RevealReq) (*RevealResp, error) {
	return ipc.Call[RevealReq, *RevealResp](ctx, c.C, OpReveal, r)
}
func (c *Client) Resolve(ctx context.Context, r ResolveReq) (*Resolved, error) {
	return ipc.Call[ResolveReq, *Resolved](ctx, c.C, OpResolve, r)
}
func (c *Client) RotateKEK(ctx context.Context) (*RotateResp, error) {
	return ipc.Call[Empty, *RotateResp](ctx, c.C, OpRotateKEK, Empty{})
}

// Broker is the interface platformd uses (IPC client or in-process).
type Broker interface {
	Set(ctx context.Context, r SetReq) (*Meta, error)
	List(ctx context.Context, r ListReq) ([]Meta, error)
	Delete(ctx context.Context, r DeleteReq) error
	DeleteProject(ctx context.Context, r DeleteProjectReq) error
	Reveal(ctx context.Context, r RevealReq) (*RevealResp, error)
	Resolve(ctx context.Context, r ResolveReq) (*Resolved, error)
}
