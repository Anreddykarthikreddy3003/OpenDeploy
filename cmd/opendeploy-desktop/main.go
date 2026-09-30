// Command opendeploy-desktop is the Windows/macOS host service. It runs the
// OpenDeploy Linux node in a managed guest (a WSL2 distro on Windows, a
// Virtualization.framework VM on macOS), starts it at boot without a user
// login, keeps it healthy, and exposes the dashboard on 127.0.0.1:8080 and
// the app edge on ports 80/443 of the host loopback.
//
//	opendeploy-desktop install     register and start the system service (admin) [--data DIR on Windows]
//	opendeploy-desktop uninstall   stop and remove the service [--purge: delete the node's data]
//	opendeploy-desktop start|stop  control the service
//	opendeploy-desktop status      data plane state and, before the owner exists, the bootstrap token
//	opendeploy-desktop run         run in the foreground (what the service manager executes)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/desktop"
)

var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `usage: opendeploy-desktop <command>

  install     register and start the OpenDeploy system service (run as administrator)
  uninstall   stop and remove the service; --purge also deletes the node and all its data
  start       start the service
  stop        stop the service (and the data plane)
  status      show the data folder and the data plane state
  run         run the supervisor in the foreground
  version     print the version
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	cfg := defaultConfig()
	fs, purge := flagSet(cmd, &cfg, flag.ExitOnError)
	_ = fs.Parse(args)
	dataSet := false
	fs.Visit(func(f *flag.Flag) { dataSet = dataSet || f.Name == "data" })

	var err error
	switch cmd {
	case "install", "uninstall", "status":
		// The service runs with an explicit --data; the commands that manage
		// it follow the data folder chosen at install time.
		err = resolveDataDir(cmd, &cfg, dataSet)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	cfg.Defaults()

	switch cmd {
	case "run":
		err = run(cfg)
	case "install":
		err = installService(cfg)
	case "uninstall":
		err = uninstallService(cfg, *purge)
	case "start":
		err = startService()
	case "stop":
		err = stopService()
	case "status":
		err = status(cfg)
	case "version":
		fmt.Println("opendeploy-desktop", version)
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// flagSet defines the command-line flags, writing into cfg. The Windows host
// also parses the installed service's own arguments with it, so the data
// folder is read exactly as the service's `run` reads it.
func flagSet(cmd string, cfg *desktop.Config, onError flag.ErrorHandling) (*flag.FlagSet, *bool) {
	fs := flag.NewFlagSet(cmd, onError)
	fs.StringVar(&cfg.ImageDir, "images", cfg.ImageDir, "guest image directory")
	fs.StringVar(&cfg.DataDir, "data", cfg.DataDir, "host data directory (install: where the node's data lives)")
	fs.IntVar(&cfg.CPUs, "cpus", 0, "guest CPUs (VM only; default 4)")
	fs.IntVar(&cfg.MemoryMiB, "memory", 0, "guest memory in MiB (VM only; default 6144)")
	fs.IntVar(&cfg.DiskGiB, "disk", 0, "guest disk size in GiB (VM only, first start; default 64)")
	purge := fs.Bool("purge", false, "uninstall: also delete the node and all of its data")
	return fs, purge
}

// logger writes to <data>/desktop.log (and stderr when interactive).
func logger(cfg desktop.Config, interactive bool) (*slog.Logger, func()) {
	_ = os.MkdirAll(cfg.DataDir, 0o755)
	f, err := os.OpenFile(filepath.Join(cfg.DataDir, "desktop.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	var w io.Writer = os.Stderr
	closer := func() {}
	if err == nil {
		closer = func() { f.Close() }
		if interactive {
			w = io.MultiWriter(f, os.Stderr)
		} else {
			w = f
		}
	}
	return slog.New(slog.NewTextHandler(w, nil)), closer
}

// supervise runs the data plane until ctx is cancelled.
func supervise(ctx context.Context, cfg desktop.Config, log *slog.Logger) error {
	g, err := newGuest(cfg, log)
	if err != nil {
		return err
	}
	log.Info("opendeploy-desktop starting", "version", version, "guest", g.Kind(), "data", cfg.DataDir)
	s := &desktop.Supervisor{Guest: g, Config: cfg, Log: log}
	return s.Run(ctx)
}

// runForeground is `run` outside a service manager (and under launchd).
func runForeground(cfg desktop.Config, interactive bool) error {
	log, closeLog := logger(cfg, interactive)
	defer closeLog()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return supervise(ctx, cfg, log)
}

func status(cfg desktop.Config) error {
	fmt.Printf("Data folder: %s\n", cfg.DataDir)
	st, err := desktop.ReadStatus(cfg.DataDir)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("OpenDeploy is not running (no status yet). Start it with: opendeploy-desktop start")
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w (run as administrator)", err)
	}
	fmt.Printf("Data plane:  %s (%s)\n", st.State, st.Guest)
	if st.Message != "" {
		fmt.Printf("Detail:      %s\n", st.Message)
	}
	fmt.Printf("Restarts:    %d\nUpdated:     %s\n", st.Restart, st.Updated.Local().Format(time.RFC1123))
	fmt.Printf("Dashboard:   http://127.0.0.1:%d\n", cfg.APIPort)
	if err := desktop.HealthCheck(cfg.APIPort)(context.Background()); err != nil {
		fmt.Printf("API:         not reachable (%v)\n", err)
	} else {
		fmt.Println("API:         healthy")
	}
	if b, err := os.ReadFile(desktop.TokenPath(cfg.DataDir)); err == nil {
		fmt.Printf("\nCreate the owner account in the dashboard with this one-time bootstrap token:\n\n    %s\n\n", strings.TrimSpace(string(b)))
	}
	return nil
}
