// Command opendeploy-hostd is the privileged host agent: it performs the
// closed set of host operations (service restarts, host firewall, verified
// A/B updates, support bundles) on behalf of platformd (PRD §4.1, SC-10).
package main

import (
	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/daemon"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/hostd"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

func main() {
	env, err := daemon.Init(identity.Host)
	if err != nil {
		daemon.Fatal(nil, err)
	}
	defer env.Cancel()
	sink := &audit.Client{C: env.Node.IPCClient(identity.Audit, identity.Host)}
	h := hostd.New(env.Node, daemon.Version, env.Log, sink)
	if err := h.Init(); err != nil {
		env.Log.Warn("update slots not initialised", "err", err)
	}
	srv := ipc.NewServer(identity.Host, env.IDs, env.Log)
	hostd.Register(srv, h)
	if err := env.Serve(srv, 0o660); err != nil {
		daemon.Fatal(env.Log, err)
	}
}
