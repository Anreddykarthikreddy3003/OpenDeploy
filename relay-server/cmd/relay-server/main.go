// Command relay-server is the optional public OpenDeploy relay (PRD §10.3,
// SC-13). It forwards raw TLS by SNI (and plain HTTP by Host) to
// authenticated instance tunnels; it never terminates application TLS.
//
//	relay-server serve  --data /var/lib/opendeploy-relay --suffix relay.example.net --tunnel-name tunnel.relay.example.net
//	relay-server enroll --data ... --tenant acme --instance home-1 [--ttl 24h]
//	relay-server revoke --data ... --instance home-1
//	relay-server list   --data ...
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/domains"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/relay"
)

var version = "dev"

func usage() {
	fmt.Fprintln(os.Stderr, "usage: relay-server serve|enroll|revoke|list [flags]  (relay-server <cmd> -h for flags)")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	data := fs.String("data", envOr("OPENDEPLOY_RELAY_DATA", "/var/lib/opendeploy-relay"), "state directory (CA, registry, audit log)")
	suffix := fs.String("suffix", os.Getenv("OPENDEPLOY_RELAY_SUFFIX"), "public suffix; instances own <instance>.<suffix> (wildcard DNS must point here)")
	tunnelNames := fs.String("tunnel-name", os.Getenv("OPENDEPLOY_RELAY_TUNNEL_NAME"), "comma-separated DNS names agents dial for the tunnel endpoint")
	tunnelListen := fs.String("tunnel-listen", ":8443", "agent tunnel listener")
	httpsListen := fs.String("https-listen", ":443", "public TLS listener (SNI pass-through)")
	httpListen := fs.String("http-listen", ":80", "public HTTP listener (Host routing; empty disables)")
	dnsServers := fs.String("dns", "1.1.1.1:53,8.8.8.8:53", "recursive resolvers used to locate authoritative servers for custom-domain proofs")
	tenant := fs.String("tenant", "", "tenant id (enroll)")
	instance := fs.String("instance", "", "instance id (enroll, revoke)")
	ttl := fs.Duration("ttl", 24*time.Hour, "enrollment token lifetime (enroll)")
	logJSON := fs.Bool("log-json", os.Getenv("INVOCATION_ID") != "", "JSON logs")
	_ = fs.Parse(args)

	var h slog.Handler = slog.NewTextHandler(os.Stderr, nil)
	if *logJSON {
		h = slog.NewJSONHandler(os.Stderr, nil)
	}
	log := slog.New(h).With("service", "relay-server")

	switch cmd {
	case "enroll", "revoke", "list":
		ca, err := relay.LoadOrCreateCA(*data + "/ca")
		must(log, err)
		reg, err := relay.OpenRegistry(*data + "/registry.json")
		must(log, err)
		switch cmd {
		case "enroll":
			tok, err := reg.CreateToken(ca, *tenant, *instance, *ttl)
			must(log, err)
			fmt.Println(tok.String())
			fmt.Fprintf(os.Stderr, "one-time token for %s/%s, valid %s. Re-enrolling an existing instance rotates its credential.\n", *tenant, *instance, *ttl)
		case "revoke":
			must(log, reg.Revoke(*instance))
			fmt.Fprintf(os.Stderr, "revoked %s; live tunnels close within seconds\n", *instance)
		case "list":
			ins, err := reg.Instances()
			must(log, err)
			_ = json.NewEncoder(os.Stdout).Encode(ins)
		}
	case "serve":
		if *suffix == "" || *tunnelNames == "" {
			must(log, fmt.Errorf("--suffix and --tunnel-name are required"))
		}
		var names []string
		for _, n := range strings.Split(*tunnelNames, ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
		srv, err := relay.NewServer(relay.ServerConfig{DataDir: *data, TunnelNames: names, PublicSuffix: *suffix, DNS: domains.NewResolver(*dnsServers), Log: log})
		must(log, err)
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		errc := make(chan error, 3)
		listen := func(addr string, serve func(net.Listener) error) {
			if addr == "" {
				return
			}
			ln, err := net.Listen("tcp", addr)
			must(log, err)
			log.Info("listening", "addr", ln.Addr().String())
			go func() { errc <- serve(ln) }()
		}
		listen(*tunnelListen, srv.ServeTunnel)
		listen(*httpsListen, srv.ServeHTTPS)
		listen(*httpListen, srv.ServeHTTP)
		go srv.Run(ctx)
		log.Info("relay started", "version", version, "suffix", *suffix, "ca_fingerprint", srv.CA.Fingerprint())
		select {
		case <-ctx.Done():
		case err := <-errc:
			log.Error("listener failed", "err", err)
		}
		_ = srv.Close()
	default:
		usage()
	}
}

func must(log *slog.Logger, err error) {
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
