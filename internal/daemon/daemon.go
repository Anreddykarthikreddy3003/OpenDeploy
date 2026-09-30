// Package daemon holds the common bootstrap for OpenDeploy services: flag
// parsing, node config, structured logging, IPC server setup and signal
// handling.
package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

// Version is set at link time.
var Version = "dev"

// Env is the initialised service environment.
type Env struct {
	Name   string
	Node   *config.Node
	Log    *slog.Logger
	IDs    *ipc.IdentityMap
	Ctx    context.Context
	Cancel context.CancelFunc
}

// Init parses flags, loads node config and sets up logging and signals.
func Init(name string) (*Env, error) {
	cfgPath := flag.String("config", envOr("OPENDEPLOY_CONFIG", config.DefaultPath), "node configuration file")
	logJSON := flag.Bool("log-json", os.Getenv("INVOCATION_ID") != "", "log as JSON (default under systemd)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(name, Version)
		os.Exit(0)
	}
	var h slog.Handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	if *logJSON {
		h = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	log := slog.New(h).With("service", name)
	slog.SetDefault(log)
	node, err := config.Load(*cfgPath)
	if err != nil {
		return nil, err
	}
	if node.DevMode {
		log.Warn("INSECURE DEV MODE: IPC identities are self-declared; never use in production")
	}
	ids, err := node.IdentityMap()
	if err != nil {
		return nil, err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	return &Env{Name: name, Node: node, Log: log, IDs: ids, Ctx: ctx, Cancel: cancel}, nil
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// Serve listens on the service socket and blocks until shutdown.
func (e *Env) Serve(s *ipc.Server, mode os.FileMode) error {
	sock := e.Node.Socket(e.Name)
	if err := s.Listen(sock, mode); err != nil {
		return fmt.Errorf("listen %s: %w", sock, err)
	}
	e.Log.Info("listening", "socket", sock, "version", Version)
	return s.Serve(e.Ctx)
}

// Fatal logs and exits.
func Fatal(log *slog.Logger, err error) {
	if log == nil {
		log = slog.Default()
	}
	log.Error("fatal", "err", err)
	os.Exit(1)
}

// LoadOrCreateEd25519 loads a PEM-encoded Ed25519 private key, creating it
// with 0600 permissions when absent.
func LoadOrCreateEd25519(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil || blk.Type != "OPENDEPLOY ED25519 PRIVATE KEY" || len(blk.Bytes) != ed25519.SeedSize {
			return nil, errors.New("invalid key file " + path)
		}
		return ed25519.NewKeyFromSeed(blk.Bytes), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "OPENDEPLOY ED25519 PRIVATE KEY", Bytes: priv.Seed()})
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}
