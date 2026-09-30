// Command runtimed creates OCI workloads through a typed API (PRD §8).
package main

import (
	"github.com/anreddykarthikreddy3003/opendeploy/internal/artifact"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/daemon"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/services"
)

func main() {
	env, err := daemon.Init(identity.Runtime)
	if err != nil {
		daemon.Fatal(nil, err)
	}
	defer env.Cancel()
	sink := &audit.Client{C: env.Node.IPCClient(identity.Audit, identity.Runtime)}
	art := &artifact.Client{C: env.Node.IPCClient(identity.Artifact, identity.Runtime)}
	srv, _, err := services.Runtimed(env.Node, env.IDs, env.Log, sink, art)
	if err != nil {
		daemon.Fatal(env.Log, err)
	}
	if err := env.Serve(srv, 0o660); err != nil {
		daemon.Fatal(env.Log, err)
	}
}
