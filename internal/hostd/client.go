package hostd

import (
	"context"
	"fmt"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/hostops"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

// Client is platformd's typed hostd client.
type Client struct{ C *ipc.Client }

func (c *Client) Info(ctx context.Context) (*hostops.Info, error) {
	return ipc.Call[hostops.Empty, *hostops.Info](ctx, c.C, hostops.OpInfo, hostops.Empty{})
}

func (c *Client) SupportBundle(ctx context.Context) (*hostops.SupportBundle, error) {
	return ipc.Call[hostops.Empty, *hostops.SupportBundle](ctx, c.C, hostops.OpSupportBundle, hostops.Empty{})
}

func (c *Client) ApplyFirewall(ctx context.Context, r hostops.FirewallReq) error {
	_, err := ipc.Call[hostops.FirewallReq, hostops.Empty](ctx, c.C, hostops.OpFirewallApply, r)
	return err
}

// ApplyUpdate stages (hostd verifies through its own TUF root) and commits.
func (c *Client) ApplyUpdate(ctx context.Context, channel, version string) error {
	sctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	if _, err := ipc.Call[hostops.UpdateStageReq, *hostops.UpdateState](sctx, c.C, hostops.OpUpdateStage, hostops.UpdateStageReq{Channel: channel, Version: version}); err != nil {
		return fmt.Errorf("stage: %w", err)
	}
	if _, err := ipc.Call[hostops.UpdateCommitReq, *hostops.UpdateState](ctx, c.C, hostops.OpUpdateCommit, hostops.UpdateCommitReq{Version: version}); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}
