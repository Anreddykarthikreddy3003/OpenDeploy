// Command relay-agent keeps the outbound mTLS tunnel to an OpenDeploy relay
// and splices relayed connections to the local Caddy edge (PRD §10.3). It
// runs as its own identity and can only read the edge's route table.
package main

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/daemon"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/relay"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/router"
)

func main() {
	env, err := daemon.Init(identity.RelayAgent)
	if err != nil {
		daemon.Fatal(nil, err)
	}
	defer env.Cancel()
	n := env.Node
	if n.Ingress.Mode != "relay" {
		daemon.Fatal(env.Log, errors.New("ingress.mode is not relay; relay-agent has nothing to do"))
	}
	token := ""
	if p := n.Ingress.Relay.EnrollToken; p != "" {
		if b, err := os.ReadFile(p); err == nil {
			token = strings.TrimSpace(string(b))
		}
	}
	rc := &router.Client{C: n.IPCClient(identity.Router, identity.RelayAgent)}
	a := relay.NewAgent(relay.AgentConfig{
		ServerAddr: n.Ingress.Relay.ServerAddr, ServerName: n.Ingress.Relay.ServerName, StateDir: n.ServiceDir(identity.RelayAgent),
		EnrollToken: token,
		LocalHTTPS:  net.JoinHostPort("127.0.0.1", strconv.Itoa(n.Ingress.HTTPSPort)),
		LocalHTTP:   net.JoinHostPort("127.0.0.1", strconv.Itoa(n.Ingress.HTTPPort)),
		Log:         env.Log,
		Hosts: func(ctx context.Context) ([]string, error) {
			cur, err := rc.Current(ctx)
			if err != nil {
				return nil, err
			}
			var hosts []string
			for _, r := range cur.Table.Routes {
				hosts = append(hosts, r.Hosts...)
			}
			return hosts, nil
		},
	})
	srv := ipc.NewServer(identity.RelayAgent, env.IDs, env.Log)
	relay.Register(srv, a)
	go func() {
		if err := a.Run(env.Ctx); err != nil {
			daemon.Fatal(env.Log, err)
		}
	}()
	if err := env.Serve(srv, 0o660); err != nil {
		daemon.Fatal(env.Log, err)
	}
}
