// Command routemgr owns edge policy and drives Caddy through its admin
// Unix socket (PRD §9, §11.3).
package main

import (
	"github.com/anreddykarthikreddy3003/opendeploy/internal/artifact"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/daemon"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/services"
)

func main() {
	env, err := daemon.Init(identity.Router)
	if err != nil {
		daemon.Fatal(nil, err)
	}
	defer env.Cancel()
	sink := &audit.Client{C: env.Node.IPCClient(identity.Audit, identity.Router)}
	art := &artifact.Client{C: env.Node.IPCClient(identity.Artifact, identity.Router)}
	srv, m, err := services.Routemgr(env.Node, env.IDs, env.Log, sink, art)
	if err != nil {
		daemon.Fatal(env.Log, err)
	}
	go services.RestoreEdge(env.Ctx, m, env.Log)
	if err := env.Serve(srv, 0o660); err != nil {
		daemon.Fatal(env.Log, err)
	}
}
