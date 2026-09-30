package network

import (
	"context"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

// IPC operations exposed by egressd.
const (
	OpApply  = "egress.apply"
	OpRemove = "egress.remove"
	OpStatus = "egress.status"
)

type RemoveReq struct {
	EnvironmentID string `json:"environment_id"`
}

type Empty struct{}

// Client is the typed egressd client (implements Enforcer). If egressd is
// unreachable, Status returns an error and trust decisions fail closed.
type Client struct{ C *ipc.Client }

func NewClient(c *ipc.Client) *Client { return &Client{C: c} }

func (c *Client) Apply(ctx context.Context, p EnvPolicy) error {
	_, err := ipc.Call[EnvPolicy, Empty](ctx, c.C, OpApply, p)
	return err
}

func (c *Client) Remove(ctx context.Context, envID string) error {
	_, err := ipc.Call[RemoveReq, Empty](ctx, c.C, OpRemove, RemoveReq{EnvironmentID: envID})
	return err
}

func (c *Client) Status(ctx context.Context) (*Status, error) {
	return ipc.Call[Empty, *Status](ctx, c.C, OpStatus, Empty{})
}
