// Command secretd is the separate high-sensitivity secret broker (PRD §13).
package main

import (
	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/daemon"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/services"
)

func main() {
	env, err := daemon.Init(identity.Secret)
	if err != nil {
		daemon.Fatal(nil, err)
	}
	defer env.Cancel()
	sink := &audit.Client{C: env.Node.IPCClient(identity.Audit, identity.Secret)}
	srv, st, err := services.Secretd(env.Ctx, env.Node, env.IDs, env.Log, sink)
	if err != nil {
		daemon.Fatal(env.Log, err)
	}
	defer st.Close()
	if err := env.Serve(srv, 0o660); err != nil {
		daemon.Fatal(env.Log, err)
	}
}
