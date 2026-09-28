// Command auditd is the write-only typed security audit sink (PRD §16.2).
package main

import (
	"path/filepath"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/daemon"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

func main() {
	env, err := daemon.Init(identity.Audit)
	if err != nil {
		daemon.Fatal(nil, err)
	}
	defer env.Cancel()
	dir := env.Node.ServiceDir(identity.Audit)
	key, err := daemon.LoadOrCreateEd25519(filepath.Join(dir, "checkpoint.key"))
	if err != nil {
		daemon.Fatal(env.Log, err)
	}
	st, err := audit.OpenStore(env.Ctx, filepath.Join(dir, "audit.db"), key, env.Log)
	if err != nil {
		daemon.Fatal(env.Log, err)
	}
	defer st.Close()
	for _, f := range env.Node.Audit.Forward {
		tok := ""
		if f.TokenFile != "" {
			b, err := config.ReadSecretFile(f.TokenFile)
			if err != nil {
				daemon.Fatal(env.Log, err)
			}
			tok = string(b)
		}
		go st.Forward(env.Ctx, audit.ForwarderConfig{Name: f.Name, URL: f.URL, Token: tok})
	}
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-env.Ctx.Done():
				return
			case <-t.C:
				if _, err := st.Checkpoint(env.Ctx); err != nil {
					env.Log.Warn("checkpoint failed", "err", err)
				}
			}
		}
	}()
	srv := ipc.NewServer(identity.Audit, env.IDs, env.Log)
	audit.Register(srv, st)
	// Socket is group-accessible so control-plane users in group od-audit can append.
	if err := env.Serve(srv, 0o660); err != nil {
		daemon.Fatal(env.Log, err)
	}
}
