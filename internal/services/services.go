// Package services constructs each OpenDeploy Tier-0 service from the node
// configuration. The per-service binaries in cmd/ and the all-in-one
// development/e2e harness share these constructors, so both exercise the
// same typed IPC surface and identity checks.
package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/artifact"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/build/builder"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/daemon"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/router"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/runtime"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/secrets"
)

// Clients returns typed IPC clients for every service, declaring `self` as
// the caller identity in dev mode (ignored otherwise; peer credentials win).
type Clients struct {
	Audit    *audit.Client
	Secrets  *secrets.Client
	Artifact *artifact.Client
	Builder  *builder.Client
	Runtime  *runtime.Client
	Router   *router.Client
}

func NewClients(n *config.Node, self string) *Clients {
	return &Clients{
		Audit:    &audit.Client{C: n.IPCClient(identity.Audit, self)},
		Secrets:  &secrets.Client{C: n.IPCClient(identity.Secret, self)},
		Artifact: &artifact.Client{C: n.IPCClient(identity.Artifact, self)},
		Builder:  &builder.Client{C: n.IPCClient(identity.Builder, self)},
		Runtime:  &runtime.Client{C: n.IPCClient(identity.Runtime, self)},
		Router:   &router.Client{C: n.IPCClient(identity.Router, self)},
	}
}

// Auditd builds the audit service.
func Auditd(ctx context.Context, n *config.Node, ids *ipc.IdentityMap, log *slog.Logger) (*ipc.Server, *audit.Store, error) {
	dir := n.ServiceDir(identity.Audit)
	key, err := daemon.LoadOrCreateEd25519(filepath.Join(dir, "checkpoint.key"))
	if err != nil {
		return nil, nil, err
	}
	st, err := audit.OpenStore(ctx, filepath.Join(dir, "audit.db"), key, log)
	if err != nil {
		return nil, nil, err
	}
	srv := ipc.NewServer(identity.Audit, ids, log)
	audit.Register(srv, st)
	audit.RegisterBackup(srv, st, n.BackupStagingDir())
	return srv, st, nil
}

// Secretd builds the secret broker.
func Secretd(ctx context.Context, n *config.Node, ids *ipc.IdentityMap, log *slog.Logger, sink audit.Sink) (*ipc.Server, *secrets.Store, error) {
	kr, err := secrets.LoadOrCreateKeyRing(n.Secrets.KEKFile)
	if err != nil {
		return nil, nil, err
	}
	st, err := secrets.Open(ctx, filepath.Join(n.ServiceDir(identity.Secret), "secrets.db"), kr, log)
	if err != nil {
		return nil, nil, err
	}
	srv := ipc.NewServer(identity.Secret, ids, log)
	ssvc := &secrets.Service{Store: st, Audit: sink}
	secrets.Register(srv, ssvc)
	secrets.RegisterBackup(srv, ssvc, n.BackupStagingDir())
	return srv, st, nil
}

// loadOrCreateToken persists a random token with 0600 permissions.
func loadOrCreateToken(p string) (string, error) {
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) >= 32 {
		return strings.TrimSpace(string(b)), nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	return tok, os.WriteFile(p, []byte(tok+"\n"), 0o600)
}

// Artifactd builds the artifact service and its registry HTTP server.
func Artifactd(n *config.Node, ids *ipc.IdentityMap, log *slog.Logger, sink audit.Sink) (*ipc.Server, *http.Server, error) {
	dir := n.ServiceDir(identity.Artifact)
	lim := artifact.DefaultLimits
	lim.MaxTotalBytes = n.Artifact.MaxImageBytes
	st, err := artifact.NewStore(filepath.Join(dir, "store"), lim)
	if err != nil {
		return nil, nil, err
	}
	tok, err := loadOrCreateToken(filepath.Join(dir, "pull-token"))
	if err != nil {
		return nil, nil, err
	}
	reg := artifact.NewRegistry(st, tok, log)
	if err := os.MkdirAll(n.HandoffDir(), 0o770); err != nil {
		return nil, nil, err
	}
	svc := &artifact.Service{Store: st, Registry: reg, RegistryURL: n.Artifact.RegistryListen, HandoffDir: n.HandoffDir(), Audit: sink}
	srv := ipc.NewServer(identity.Artifact, ids, log)
	artifact.Register(srv, svc)
	artifact.RegisterBackup(srv, st, n.BackupStagingDir())
	hs := &http.Server{Addr: n.Artifact.RegistryListen, Handler: reg, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	return srv, hs, nil
}

// ServeRegistry runs the registry listener (loopback only).
func ServeRegistry(ctx context.Context, hs *http.Server) error {
	host, _, err := net.SplitHostPort(hs.Addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("artifact registry must listen on loopback, not %s", hs.Addr)
	}
	ln, err := net.Listen("tcp", hs.Addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(sc)
	}()
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Builderd builds the build service.
func Builderd(n *config.Node, ids *ipc.IdentityMap, log *slog.Logger, sink audit.Sink, art builder.ArtifactClient) (*ipc.Server, *builder.Service, error) {
	var trusted builder.Executor
	switch n.Build.Executor {
	case "docker":
		trusted = &builder.DockerBuildx{Host: n.Runtime.DockerHost, CABundle: n.Build.CABundle, Mirrors: engineMirrors()}
	default:
		trusted = &builder.Buildctl{Addr: n.Build.BuildKitAddr}
	}
	var untrusted builder.Executor
	switch {
	case n.Build.UntrustedBuildKit != "":
		untrusted = &builder.Buildctl{Addr: n.Build.UntrustedBuildKit}
	case n.Build.UntrustedRuntime != "" && n.Runtime.Backend == "docker":
		untrusted = &builder.SandboxedBuildKit{Host: n.Runtime.DockerHost, Image: n.Build.UntrustedImage, Runtime: n.Build.UntrustedRuntime,
			Network: n.Build.UntrustedNetwork}
	}
	for _, d := range []string{n.Build.WorkDir, filepath.Join(n.DataDir, "sources")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, nil, err
		}
	}
	proxy := ""
	if n.Egress.Enforce {
		proxy = "http://" + n.Egress.ProxyListen
	}
	svc := builder.New(builder.Config{WorkDir: n.Build.WorkDir, HandoffDir: n.HandoffDir(), SourcesDir: filepath.Join(n.DataDir, "sources"),
		MaxConcurrent: n.Build.MaxConcurrent, Trusted: trusted, Untrusted: untrusted, Artifacts: art, Audit: sink, Log: log, EgressProxy: proxy, BuildCABundle: buildCABundle(n)})
	srv := ipc.NewServer(identity.Builder, ids, log)
	builder.Register(srv, svc)
	return srv, svc, nil
}

// Runtimed builds the runtime broker.
func Runtimed(n *config.Node, ids *ipc.IdentityMap, log *slog.Logger, sink audit.Sink, art *artifact.Client) (*ipc.Server, *runtime.Service, error) {
	secretsDir := filepath.Join(n.RunDir, "secrets")
	if err := os.MkdirAll(secretsDir, 0o711); err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(n.Runtime.VolumesDir, 0o711); err != nil {
		return nil, nil, err
	}
	var be runtime.Backend
	switch n.Runtime.Backend {
	case "docker":
		d, err := runtime.NewDocker(n.Runtime.DockerHost, secretsDir, n.Runtime.VolumesDir)
		if err != nil {
			return nil, nil, err
		}
		be = d
	default:
		c, err := runtime.NewContainerd(n.Runtime, secretsDir)
		if err != nil {
			return nil, nil, err
		}
		be = c
	}
	var mu sync.Mutex
	var cached *runtime.RegistryAuth
	authFn := func(ctx context.Context) (runtime.RegistryAuth, error) {
		mu.Lock()
		defer mu.Unlock()
		if cached != nil {
			return *cached, nil
		}
		pc, err := art.PullCredentials(ctx)
		if err != nil {
			return runtime.RegistryAuth{}, err
		}
		cached = &runtime.RegistryAuth{Server: pc.Registry, User: pc.User, Password: pc.Token}
		return *cached, nil
	}
	svc := &runtime.Service{Backend: be, Registry: n.Artifact.RegistryListen, Auth: authFn, Audit: sink}
	srv := ipc.NewServer(identity.Runtime, ids, log)
	runtime.Register(srv, svc)
	runtime.RegisterBackup(srv, n.Runtime.VolumesDir, n.BackupStagingDir())
	return srv, svc, nil
}

// Routemgr builds the edge route manager.
func Routemgr(n *config.Node, ids *ipc.IdentityMap, log *slog.Logger, sink audit.Sink, art *artifact.Client) (*ipc.Server, *router.Manager, error) {
	o := router.Options{AdminSocket: n.Ingress.CaddyAdmin, HTTPPort: n.Ingress.HTTPPort, HTTPSPort: n.Ingress.HTTPSPort,
		VerifyListen: "127.0.0.1:18080", ACMEEmail: n.Ingress.ACMEEmail, ACMECA: n.Ingress.ACMECA,
		MaxBodyBytes: n.Ingress.Limits.MaxBodyBytes, MaxConns: n.Ingress.Limits.MaxConnsPerHost,
		StateDir: n.ServiceDir(identity.Router), LANOnly: n.Ingress.Mode == "lan"}
	m := router.NewManager(router.NewCaddy(o.AdminSocket), o)
	srv := ipc.NewServer(identity.Router, ids, log)
	router.Register(srv, &router.Service{M: m, Audit: sink, Resolve: art.StaticDir})
	return srv, m, nil
}

// RestoreEdge reloads last-known-good routes once Caddy is reachable.
func RestoreEdge(ctx context.Context, m *router.Manager, log *slog.Logger) {
	for i := 0; ; i++ {
		if err := m.Restore(ctx); err == nil {
			log.Info("edge restored from last-known-good configuration")
			return
		} else if i%10 == 0 {
			log.Warn("waiting for caddy admin socket", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// engineMirrors returns the Docker engine's registry mirrors so a dedicated
// buildx builder pulls through the same mirrors as the engine.
func engineMirrors() []string {
	b, err := os.ReadFile("/etc/docker/daemon.json")
	if err != nil {
		return nil
	}
	var cfg struct {
		Mirrors []string `json:"registry-mirrors"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return nil
	}
	return cfg.Mirrors
}

// buildCABundle is the extra CA bundle build steps trust (node config, or
// OPENDEPLOY_BUILD_CA_BUNDLE for development hosts).
func buildCABundle(n *config.Node) string {
	if n.Build.CABundle != "" {
		return n.Build.CABundle
	}
	return os.Getenv("OPENDEPLOY_BUILD_CA_BUNDLE")
}
