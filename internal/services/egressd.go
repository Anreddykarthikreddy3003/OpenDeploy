package services

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/network"
)

// Egressd builds the network policy service and its proxy.
func Egressd(ctx context.Context, n *config.Node, ids *ipc.IdentityMap, log *slog.Logger, sink audit.Sink) (*ipc.Server, *network.Service, *http.Server, error) {
	_, portStr, err := net.SplitHostPort(n.Egress.ProxyListen)
	if err != nil {
		return nil, nil, nil, err
	}
	port, _ := strconv.Atoi(portStr)
	var uids []int
	for _, name := range n.Egress.BuildUsers {
		if u, err := user.Lookup(name); err == nil {
			if id, err := strconv.Atoi(u.Uid); err == nil {
				uids = append(uids, id)
			}
		}
	}
	svc := &network.Service{NftBin: n.Egress.NftBin, StateFile: filepath.Join(n.ServiceDir(identity.Egress), "policies.json"),
		BuildBridges: n.Egress.BuildBridges, BuildUIDs: uids, ProxyPort: port, DNS: n.Egress.DNS, BuildAllow: n.Egress.AllowedHosts, Audit: sink, Log: log}
	if err := svc.Init(ctx); err != nil {
		// Keep serving so status reports the failure; trust decisions fail closed.
		log.Error("network policy enforcement unavailable", "err", err)
	}
	srv := ipc.NewServer(identity.Egress, ids, log)
	network.Register(srv, svc)
	proxy := &network.Proxy{Log: log, Policy: svc.ProxyPolicy}
	hs := &http.Server{Addr: n.Egress.ProxyListen, Handler: proxy, ReadHeaderTimeout: 10 * time.Second}
	return srv, svc, hs, nil
}

// ServeProxy runs the egress proxy until ctx ends.
func ServeProxy(ctx context.Context, hs *http.Server) error {
	go func() {
		<-ctx.Done()
		_ = hs.Close()
	}()
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
