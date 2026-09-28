// Command platformd is the unprivileged Tier-0 orchestrator and admin API
// (PRD §4.1, §15).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/daemon"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/network"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/services"
	"github.com/anreddykarthikreddy3003/opendeploy/web"
)

func main() {
	env, err := daemon.Init(identity.Platform)
	if err != nil {
		daemon.Fatal(nil, err)
	}
	defer env.Cancel()
	c := services.NewClients(env.Node, identity.Platform)
	eg := network.NewClient(env.Node.IPCClient(identity.Egress, identity.Platform))
	pd, err := services.NewPlatformd(env.Ctx, env.Node, env.Log, c, services.PlatformOptions{UI: web.FS(), Egress: eg})
	if err != nil {
		daemon.Fatal(env.Log, err)
	}
	defer pd.Store.Close()
	go pd.Platform.Run(env.Ctx)
	hs := &http.Server{Addr: env.Node.API.Listen, Handler: pd.API.Handler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 10 * time.Minute, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	go func() {
		<-env.Ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sc)
	}()
	env.Log.Info("api listening", "addr", hs.Addr)
	ra := env.Node.API.RemoteAdmin
	if ra.Enabled {
		hs.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		err = hs.ListenAndServeTLS(ra.TLSCert, ra.TLSKey)
	} else {
		err = hs.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		daemon.Fatal(env.Log, err)
	}
}
