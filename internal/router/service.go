package router

import (
	"context"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

// IPC operations.
const (
	OpApply   = "route.apply"
	OpCurrent = "route.current"
	OpRestore = "route.restore"
)

type ApplyReq struct {
	Table      Table    `json:"table"`
	VerifyEnvs []string `json:"verify_envs,omitempty"`
}

type CurrentResp struct {
	Table  Table  `json:"table"`
	Digest string `json:"digest"`
}

type Empty struct{}

// StaticResolver maps a static artifact digest to its directory (artifactd).
type StaticResolver func(ctx context.Context, digest string) (string, error)

// Service exposes the Manager over IPC.
type Service struct {
	M       *Manager
	Resolve StaticResolver
	Audit   audit.Sink
}

func (s *Service) Apply(ctx context.Context, r ApplyReq) (*ApplyResult, error) {
	for i := range r.Table.Routes {
		rt := &r.Table.Routes[i]
		if rt.Kind == KindStatic {
			if s.Resolve == nil {
				return nil, ipc.Errorf(ipc.CodeUnavailable, "static resolver unavailable")
			}
			dir, err := s.Resolve(ctx, rt.StaticDigest)
			if err != nil {
				return nil, ipc.Errorf(ipc.CodeBadRequest, "static artifact %s: %v", rt.StaticDigest, err)
			}
			rt.StaticDir = dir
		}
	}
	res, err := s.M.Apply(ctx, r.Table, r.VerifyEnvs)
	result := audit.Success
	details := map[string]string{"count": itoa(len(r.Table.Routes))}
	if err != nil {
		result, details["error"] = audit.Failure, trunc(err.Error(), 500)
	} else {
		details["target"] = res.Digest
	}
	if s.Audit != nil {
		_, _ = s.Audit.Append(ctx, audit.Event{ActorType: audit.ActorService, ActorID: identity.Router, Action: "route.apply",
			ResourceType: "edge", Result: result, Details: details})
	}
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeConflict, "%v", err)
	}
	return res, nil
}

func itoa(n int) string {
	return PortString(n)
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Register exposes routemgr; only platformd may change routes.
func Register(srv *ipc.Server, s *Service) {
	ipc.Handle(srv, OpApply, []string{identity.Platform}, func(ctx context.Context, _ ipc.Caller, r ApplyReq) (*ApplyResult, error) {
		return s.Apply(ctx, r)
	})
	ipc.Handle(srv, OpCurrent, []string{identity.Platform, identity.RelayAgent}, func(_ context.Context, _ ipc.Caller, _ Empty) (*CurrentResp, error) {
		t, d := s.M.Current()
		return &CurrentResp{Table: t, Digest: d}, nil
	})
	ipc.Handle(srv, OpRestore, []string{identity.Platform, identity.Host}, func(ctx context.Context, _ ipc.Caller, _ Empty) (Empty, error) {
		return Empty{}, s.M.Restore(ctx)
	})
}

// Client is the typed routemgr client.
type Client struct{ C *ipc.Client }

func (c *Client) Apply(ctx context.Context, t Table, verify []string) (*ApplyResult, error) {
	return ipc.Call[ApplyReq, *ApplyResult](ctx, c.C, OpApply, ApplyReq{Table: t, VerifyEnvs: verify})
}
func (c *Client) Current(ctx context.Context) (*CurrentResp, error) {
	return ipc.Call[Empty, *CurrentResp](ctx, c.C, OpCurrent, Empty{})
}
func (c *Client) Restore(ctx context.Context) error {
	_, err := ipc.Call[Empty, Empty](ctx, c.C, OpRestore, Empty{})
	return err
}
