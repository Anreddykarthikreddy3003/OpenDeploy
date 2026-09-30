// Command egressd owns network segmentation (nftables) and the egress
// policy proxy (PRD §9, SC-05, SC-12). It needs CAP_NET_ADMIN.
package main

import (
	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/daemon"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/services"
)

func main() {
	env, err := daemon.Init(identity.Egress)
	if err != nil {
		daemon.Fatal(nil, err)
	}
	defer env.Cancel()
	sink := &audit.Client{C: env.Node.IPCClient(identity.Audit, identity.Egress)}
	srv, _, proxy, err := services.Egressd(env.Ctx, env.Node, env.IDs, env.Log, sink)
	if err != nil {
		daemon.Fatal(env.Log, err)
	}
	go func() {
		if err := services.ServeProxy(env.Ctx, proxy); err != nil {
			env.Log.Error("egress proxy stopped", "err", err)
		}
	}()
	if err := env.Serve(srv, 0o660); err != nil {
		daemon.Fatal(env.Log, err)
	}
}
