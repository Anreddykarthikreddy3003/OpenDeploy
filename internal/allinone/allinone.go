// Package allinone runs every OpenDeploy service in one process, each on
// its own IPC socket with a declared identity (insecure dev mode). It backs
// integration/e2e tests and `opendeployctl dev`. Production always runs the
// services as separate binaries and Unix users.
package allinone

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/artifact"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/build/builder"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/git"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/network"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/router"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/runtime"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/services"
)

// Options configure the stack.
type Options struct {
	DataDir  string
	Log      *slog.Logger
	Backend  runtime.Backend  // nil = Docker Engine at /var/run/docker.sock
	Executor builder.Executor // nil = docker buildx
	Fetch    func(ctx context.Context, dir string, s git.Source) (*git.Result, error)
	Egress   network.Enforcer // nil = insecure no-enforcement (dev)
	CaddyBin string           // "" = fake edge (no real proxying)
	HTTPPort int
	UI       fs.FS
	Profile  string
	Mutate   func(n *config.Node)
}

// Stack is a running all-in-one deployment.
type Stack struct {
	Node     *config.Node
	P        *services.Platformd
	API      *http.Server
	APIAddr  string
	Registry string
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	caddy    *exec.Cmd
	closers  []func()
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func freePort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// Start launches the stack.
func Start(ctx context.Context, o Options) (*Stack, error) {
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	os.Setenv("OPENDEPLOY_INSECURE_DEV", "1")
	run := filepath.Join(os.TempDir(), "od-"+randHex(4)) // short path for unix sockets
	if err := os.MkdirAll(run, 0o700); err != nil {
		return nil, err
	}
	n := &config.Node{DataDir: o.DataDir, RunDir: run, DevMode: true, Profile: o.Profile}
	n.Runtime.Backend = "docker"
	n.Build.Executor = "docker"
	n.Ingress.Mode = "lan"
	n.Ingress.BaseDomain = "od.test"
	if o.HTTPPort == 0 {
		o.HTTPPort = freePort()
	}
	n.Ingress.HTTPPort = o.HTTPPort
	n.Ingress.HTTPSPort = freePort()
	n.Artifact.RegistryListen = fmt.Sprintf("127.0.0.1:%d", freePort())
	n.API.Listen = fmt.Sprintf("127.0.0.1:%d", freePort())
	n.ApplyDefaults()
	if o.Mutate != nil {
		o.Mutate(n)
	}
	if err := n.Validate(); err != nil {
		return nil, err
	}
	ids, _ := n.IdentityMap()
	sctx, cancel := context.WithCancel(ctx)
	s := &Stack{Node: n, cancel: cancel, Registry: n.Artifact.RegistryListen}
	s.closers = append(s.closers, func() { os.RemoveAll(run) })
	serve := func(srv *ipc.Server, id string) error {
		if err := srv.Listen(n.Socket(id), 0o600); err != nil {
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_ = srv.Serve(sctx)
		}()
		return nil
	}
	fail := func(err error) (*Stack, error) {
		s.Close()
		return nil, err
	}
	sink := func(self string) audit.Sink { return &audit.Client{C: n.IPCClient(identity.Audit, self)} }

	// auditd
	asrv, ast, err := services.Auditd(sctx, n, ids, o.Log)
	if err != nil {
		return fail(err)
	}
	s.closers = append(s.closers, func() { ast.Close() })
	if err := serve(asrv, identity.Audit); err != nil {
		return fail(err)
	}
	// secretd
	ssrv, sst, err := services.Secretd(sctx, n, ids, o.Log, sink(identity.Secret))
	if err != nil {
		return fail(err)
	}
	s.closers = append(s.closers, func() { sst.Close() })
	if err := serve(ssrv, identity.Secret); err != nil {
		return fail(err)
	}
	// artifactd + registry
	arsrv, reg, err := services.Artifactd(n, ids, o.Log, sink(identity.Artifact))
	if err != nil {
		return fail(err)
	}
	if err := serve(arsrv, identity.Artifact); err != nil {
		return fail(err)
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = services.ServeRegistry(sctx, reg)
	}()
	// builderd
	artForBuilder := &artifact.Client{C: n.IPCClient(identity.Artifact, identity.Builder)}
	bsrv, bsvc, err := services.Builderd(n, ids, o.Log, sink(identity.Builder), artForBuilder)
	if err != nil {
		return fail(err)
	}
	_ = bsvc
	if o.Executor != nil || o.Fetch != nil {
		// Rebuild with injected executor/fetch for tests.
		ex := o.Executor
		if ex == nil {
			ex = &builder.DockerBuildx{}
		}
		svc := builder.New(builder.Config{WorkDir: n.Build.WorkDir, HandoffDir: n.HandoffDir(), SourcesDir: filepath.Join(n.DataDir, "sources"),
			MaxConcurrent: n.Build.MaxConcurrent, Trusted: ex, Artifacts: artForBuilder, Audit: sink(identity.Builder), Log: o.Log, Fetch: o.Fetch})
		bsrv = ipc.NewServer(identity.Builder, ids, o.Log)
		builder.Register(bsrv, svc)
	}
	if err := serve(bsrv, identity.Builder); err != nil {
		return fail(err)
	}
	// runtimed
	artForRuntime := &artifact.Client{C: n.IPCClient(identity.Artifact, identity.Runtime)}
	var rsrv *ipc.Server
	if o.Backend != nil {
		rsvc := &runtime.Service{Backend: o.Backend, Registry: n.Artifact.RegistryListen, Audit: sink(identity.Runtime),
			Auth: func(ctx context.Context) (runtime.RegistryAuth, error) {
				pc, err := artForRuntime.PullCredentials(ctx)
				if err != nil {
					return runtime.RegistryAuth{}, err
				}
				return runtime.RegistryAuth{Server: pc.Registry, User: pc.User, Password: pc.Token}, nil
			}}
		rsrv = ipc.NewServer(identity.Runtime, ids, o.Log)
		runtime.Register(rsrv, rsvc)
	} else {
		rsrv, _, err = services.Runtimed(n, ids, o.Log, sink(identity.Runtime), artForRuntime)
		if err != nil {
			return fail(err)
		}
	}
	if err := serve(rsrv, identity.Runtime); err != nil {
		return fail(err)
	}
	// edge: real Caddy or a fake admin API
	if o.CaddyBin != "" {
		if err := s.startCaddy(o.CaddyBin); err != nil {
			return fail(err)
		}
	} else {
		if err := s.fakeCaddy(sctx); err != nil {
			return fail(err)
		}
	}
	artForRouter := &artifact.Client{C: n.IPCClient(identity.Artifact, identity.Router)}
	rtsrv, mgr, err := services.Routemgr(n, ids, o.Log, sink(identity.Router), artForRouter)
	if err != nil {
		return fail(err)
	}
	if o.CaddyBin == "" {
		mgr.Opt.VerifyListen = ""
	}
	if err := serve(rtsrv, identity.Router); err != nil {
		return fail(err)
	}
	// platformd
	eg := o.Egress
	insecure := false
	if eg == nil {
		eg, insecure = network.Nop{}, true
	}
	mfa := false
	pd, err := services.NewPlatformd(sctx, n, o.Log, services.NewClients(n, identity.Platform),
		services.PlatformOptions{UI: o.UI, Egress: eg, InsecureNoNetworkPolicy: insecure, RequireMFA: &mfa})
	if err != nil {
		return fail(err)
	}
	s.P = pd
	s.closers = append(s.closers, func() { pd.Store.Close() })
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		pd.Platform.Run(sctx)
	}()
	ln, err := net.Listen("tcp", n.API.Listen)
	if err != nil {
		return fail(err)
	}
	s.APIAddr = ln.Addr().String()
	s.API = &http.Server{Handler: pd.API.Handler(), ReadHeaderTimeout: 10 * time.Second}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = s.API.Serve(ln)
	}()
	return s, nil
}

func (s *Stack) startCaddy(bin string) error {
	boot := filepath.Join(s.Node.RunDir, "caddy-boot.json")
	if err := os.WriteFile(boot, router.BootstrapConfig(s.Node.Ingress.CaddyAdmin), 0o600); err != nil {
		return err
	}
	cmd := exec.Command(bin, "run", "--config", boot)
	home := filepath.Join(s.Node.DataDir, "caddy")
	_ = os.MkdirAll(home, 0o700)
	cmd.Env = append(os.Environ(), "HOME="+home, "XDG_DATA_HOME="+home, "XDG_CONFIG_HOME="+home)
	if err := cmd.Start(); err != nil {
		return err
	}
	s.caddy = cmd
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(s.Node.Ingress.CaddyAdmin); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("caddy admin socket did not appear")
}

// fakeCaddy serves a minimal admin API that accepts and records configs.
func (s *Stack) fakeCaddy(ctx context.Context) error {
	ln, err := net.Listen("unix", s.Node.Ingress.CaddyAdmin)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	var servers json.RawMessage = []byte(`{}`)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /load", func(w http.ResponseWriter, r *http.Request) {
		var cfg struct {
			Apps struct {
				HTTP struct {
					Servers json.RawMessage `json:"servers"`
				} `json:"http"`
			} `json:"apps"`
		}
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		mu.Lock()
		servers = cfg.Apps.HTTP.Servers
		mu.Unlock()
	})
	mux.HandleFunc("GET /config/apps/http/servers", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = w.Write(servers)
	})
	hs := &http.Server{Handler: mux}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		go func() { <-ctx.Done(); hs.Close() }()
		_ = hs.Serve(ln)
	}()
	return nil
}

// Close stops everything.
func (s *Stack) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.API != nil {
		_ = s.API.Close()
	}
	if s.caddy != nil && s.caddy.Process != nil {
		_ = s.caddy.Process.Kill()
		_, _ = s.caddy.Process.Wait()
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
	}
	for i := len(s.closers) - 1; i >= 0; i-- {
		s.closers[i]()
	}
}
