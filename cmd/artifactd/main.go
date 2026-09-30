// Command artifactd validates and stores build artifacts and serves them to
// the runtime through an authenticated loopback registry (PRD §4.1).
package main

import (
	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/daemon"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/services"
)

func main() {
	env, err := daemon.Init(identity.Artifact)
	if err != nil {
		daemon.Fatal(nil, err)
	}
	defer env.Cancel()
	sink := &audit.Client{C: env.Node.IPCClient(identity.Audit, identity.Artifact)}
	srv, reg, err := services.Artifactd(env.Node, env.IDs, env.Log, sink)
	if err != nil {
		daemon.Fatal(env.Log, err)
	}
	go func() {
		if err := services.ServeRegistry(env.Ctx, reg); err != nil {
			daemon.Fatal(env.Log, err)
		}
	}()
	if err := env.Serve(srv, 0o660); err != nil {
		daemon.Fatal(env.Log, err)
	}
}
