package relay

import (
	"context"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

// OpStatus reports the agent's tunnel state to platformd.
const OpStatus = "relay.status"

type empty struct{}

// Register exposes the agent's read-only status over IPC.
func Register(srv *ipc.Server, a *Agent) {
	ipc.Handle(srv, OpStatus, []string{identity.Platform}, func(context.Context, ipc.Caller, empty) (*Status, error) {
		st := a.Status()
		return &st, nil
	})
}

// Client calls the relay agent.
type Client struct{ C *ipc.Client }

// Status returns the tunnel status.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	return ipc.Call[empty, *Status](ctx, c.C, OpStatus, empty{})
}
