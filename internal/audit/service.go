package audit

import (
	"context"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

// IPC operation names.
const (
	OpAppend        = "audit.append"
	OpQuery         = "audit.query"
	OpVerify        = "audit.verify"
	OpCheckpoints   = "audit.checkpoints"
	OpForwardStatus = "audit.forward_status"
)

type Empty struct{}

type CheckpointsReq struct {
	AfterSeq int64 `json:"after_seq"`
}

// Register exposes the store on an IPC server. Appends are accepted only from
// control-plane identities; the recorded service is the verified caller.
func Register(s *ipc.Server, st *Store) {
	ipc.Handle(s, OpAppend, identity.ControlPlane, func(ctx context.Context, c ipc.Caller, e Event) (Event, error) {
		if d := st.Degraded(); d != "" {
			return Event{}, ipc.Errorf(ipc.CodeDegraded, "%s", d)
		}
		if err := e.Validate(); err != nil {
			return Event{}, ipc.Errorf(ipc.CodeBadRequest, "%v", err)
		}
		return st.Append(ctx, c.Identity, e)
	})
	ipc.Handle(s, OpQuery, []string{identity.Platform, identity.Host}, func(ctx context.Context, _ ipc.Caller, q Query) ([]Event, error) {
		return st.Query(ctx, q)
	})
	ipc.Handle(s, OpVerify, []string{identity.Platform, identity.Host}, func(ctx context.Context, _ ipc.Caller, _ Empty) (VerifyResult, error) {
		return st.Verify(ctx)
	})
	ipc.Handle(s, OpCheckpoints, []string{identity.Platform, identity.Host}, func(ctx context.Context, _ ipc.Caller, r CheckpointsReq) ([]Checkpoint, error) {
		return st.Checkpoints(ctx, r.AfterSeq)
	})
	ipc.Handle(s, OpForwardStatus, []string{identity.Platform, identity.Host}, func(ctx context.Context, _ ipc.Caller, _ Empty) ([]ForwardStatus, error) {
		return st.ForwardStatuses(ctx)
	})
}

// Client is an IPC Sink for control-plane services.
type Client struct{ C *ipc.Client }

func (c *Client) Append(ctx context.Context, e Event) (Event, error) {
	return ipc.Call[Event, Event](ctx, c.C, OpAppend, e)
}

func (c *Client) Query(ctx context.Context, q Query) ([]Event, error) {
	return ipc.Call[Query, []Event](ctx, c.C, OpQuery, q)
}

func (c *Client) Verify(ctx context.Context) (VerifyResult, error) {
	return ipc.Call[Empty, VerifyResult](ctx, c.C, OpVerify, Empty{})
}

func (c *Client) Checkpoints(ctx context.Context, after int64) ([]Checkpoint, error) {
	return ipc.Call[CheckpointsReq, []Checkpoint](ctx, c.C, OpCheckpoints, CheckpointsReq{AfterSeq: after})
}

func (c *Client) ForwardStatus(ctx context.Context) ([]ForwardStatus, error) {
	return ipc.Call[Empty, []ForwardStatus](ctx, c.C, OpForwardStatus, Empty{})
}

// Local adapts a Store as an in-process Sink for a given service identity
// (all-in-one development mode and tests).
type Local struct {
	Store   *Store
	Service string
}

func (l *Local) Append(ctx context.Context, e Event) (Event, error) {
	return l.Store.Append(ctx, l.Service, e)
}
