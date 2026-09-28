package cli

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/allinone"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/services"
	"github.com/anreddykarthikreddy3003/opendeploy/web"
)

// cmdDev runs every OpenDeploy service in one process against the local
// Docker engine: the fastest way to try the product or develop the UI. It is
// explicitly INSECURE (self-declared IPC identities, no egress policy).
func cmdDev(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("dev", flag.ContinueOnError)
	port := fs.Int("port", 8080, "dashboard/API port (loopback)")
	httpPort := fs.Int("http-port", 8000, "edge HTTP port for deployed apps (*.localhost)")
	home, _ := os.UserHomeDir()
	data := fs.String("data", filepath.Join(home, ".local", "share", "opendeploy-dev"), "data directory")
	caddy := fs.String("caddy", "", "caddy binary (default: from PATH; without it apps are not proxied)")
	verbose := fs.Bool("v", false, "verbose logs")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *caddy == "" {
		if p, err := exec.LookPath("caddy"); err == nil {
			*caddy = p
		}
	}
	if err := os.MkdirAll(*data, 0o700); err != nil {
		return err
	}
	lvl := slog.LevelWarn
	if *verbose {
		lvl = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	st, err := allinone.Start(ctx, allinone.Options{DataDir: *data, Log: log, CaddyBin: *caddy, HTTPPort: *httpPort, UI: web.FS(),
		Mutate: func(n *config.Node) {
			n.API.Listen = fmt.Sprintf("127.0.0.1:%d", *port)
			n.Ingress.BaseDomain = "localhost"
		}})
	if err != nil {
		return err
	}
	defer st.Close()
	fmt.Printf("\nOpenDeploy dev node (INSECURE development mode)\n\n  Dashboard: http://localhost:%d\n", *port)
	if b, err := os.ReadFile(services.BootstrapTokenPath(st.Node)); err == nil {
		fmt.Printf("  Bootstrap token: %s\n", strings.TrimSpace(string(b)))
	}
	if *caddy != "" {
		fmt.Printf("  Apps: http://<project>.localhost:%d\n", *httpPort)
	} else {
		fmt.Println("  Apps: caddy not found — deployments run but are not proxied")
	}
	if web.FS() == nil {
		fmt.Println("  (dashboard not embedded: run `make web` before building)")
	}
	fmt.Println("\nPress Ctrl+C to stop.")
	<-ctx.Done()
	return nil
}
