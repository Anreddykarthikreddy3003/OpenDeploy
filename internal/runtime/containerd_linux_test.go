//go:build linux

package runtime

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/artifact"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/build/builder"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
)

// TestContainerdIntegration runs a real workload through containerd when
// OPENDEPLOY_CONTAINERD_TESTS=1 (root, containerd socket, docker for the
// test image build).
func TestContainerdIntegration(t *testing.T) {
	sock := os.Getenv("OPENDEPLOY_CONTAINERD_SOCKET")
	if os.Getenv("OPENDEPLOY_CONTAINERD_TESTS") != "1" || sock == "" {
		t.Skip("set OPENDEPLOY_CONTAINERD_TESTS=1 and OPENDEPLOY_CONTAINERD_SOCKET")
	}
	ctx := context.Background()
	dir := t.TempDir()
	// 1. Build a tiny web image with BuildKit and import it via artifactd.
	src := filepath.Join(dir, "src")
	_ = os.MkdirAll(src, 0o755)
	_ = os.WriteFile(filepath.Join(src, "Dockerfile"), []byte("FROM alpine:3.20\nUSER 10001\nCMD [\"sh\",\"-c\",\"echo started; while true; do printf 'HTTP/1.1 200 OK\\\\r\\\\nContent-Length: 14\\\\r\\\\nConnection: close\\\\r\\\\n\\\\r\\\\ncontainerd-ok\\\\n' | nc -l -p $PORT; done\"]\n"), 0o644)
	tarPath := filepath.Join(dir, "image.tar")
	var blog strings.Builder
	if err := (&builder.DockerBuildx{}).Build(ctx, builder.Spec{ContextDir: src, DockerfileDir: src, Dockerfile: "Dockerfile", Output: builder.OutputOCI, Dest: tarPath}, &blog); err != nil {
		t.Fatalf("build: %v %s", err, blog.String())
	}
	st, _ := artifact.NewStore(filepath.Join(dir, "store"), artifact.DefaultLimits)
	f, _ := os.Open(tarPath)
	info, err := st.IngestOCILayout(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	reg := artifact.NewRegistry(st, "pulltoken", nil)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go http.Serve(ln, reg)
	registry := ln.Addr().String()
	image := registry + "/od/prj-test@" + info.Digest

	// 2. containerd backend in an isolated namespace.
	cfg := config.RuntimeConfig{ContainerdSocket: sock, ContainerdNS: "opendeploy-test-" + ids.Token(3), RuncHandler: "io.containerd.runc.v2",
		RunscHandler: "io.containerd.runsc.v1", VolumesDir: filepath.Join(dir, "volumes")}
	b, err := newContainerd(cfg, filepath.Join(dir, "secrets"), filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	caps, err := b.Capabilities(ctx)
	if err != nil || !caps.Runtimes[RuntimeRunc] {
		t.Fatalf("%+v %v", caps, err)
	}
	env, prj := ids.New("env"), ids.New("prj")
	ni, err := b.EnsureNetwork(ctx, NetworkSpec{EnvironmentID: env, ProjectID: prj, Kind: "production"})
	if err != nil {
		t.Fatal(err)
	}
	defer b.RemoveNetwork(ctx, env)
	s := &Spec{ID: ids.New("wkl"), ProjectID: prj, EnvironmentID: env, DeploymentID: ids.New("dep"), Service: "web", Kind: "app", Image: image,
		Runtime: RuntimeRunc, Port: 8080, MemoryBytes: 128 << 20, CPU: 0.5, PIDs: 64, ReadOnlyRoot: true, Network: env,
		SecretFiles: map[string]string{"TOKEN": "abc"}, Env: map[string]string{"HELLO": "world"}}
	if err := s.Validate(registry, caps.Runtimes); err != nil {
		t.Fatal(err)
	}
	w, err := b.Start(ctx, s, RegistryAuth{Server: registry, User: "runtime", Password: "pulltoken"})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Remove(ctx, s.ID)
	if w.State != "running" || !strings.HasPrefix(w.Endpoint, strings.TrimSuffix(ni.Gateway, ".1")) {
		t.Fatalf("%+v (gw %s)", w, ni.Gateway)
	}
	// 3. Reachable from the host over the env bridge.
	var body string
	for i := 0; i < 50; i++ {
		res, err := http.Get("http://" + w.Endpoint + "/")
		if err == nil {
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			body = string(b)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(body, "containerd-ok") {
		logs, _ := b.Logs(ctx, s.ID, 20, time.Time{})
		wi, _ := b.Inspect(ctx, s.ID)
		out, _ := exec.Command("ip", "netns", "exec", nsName(s.ID), "ip", "addr").CombinedOutput()
		t.Fatalf("workload not serving: %q logs=%v state=%+v\n%s", body, logs, wi, out)
	}
	// 4. Hardening present in the OCI spec.
	c, _ := b.c.LoadContainer(b.ctx(ctx), s.ID)
	sp, _ := c.Spec(b.ctx(ctx))
	p := sp.Process
	if !p.NoNewPrivileges || len(p.Capabilities.Bounding) != 0 || !sp.Root.Readonly || sp.Linux.Seccomp == nil || *sp.Linux.Resources.Memory.Limit != 128<<20 {
		t.Fatalf("hardening missing: nnp=%v caps=%v ro=%v seccomp=%v", p.NoNewPrivileges, p.Capabilities.Bounding, sp.Root.Readonly, sp.Linux.Seccomp != nil)
	}
	if p.User.UID != 10001 {
		t.Fatalf("image user not honoured: %d", p.User.UID)
	}
	// 5. Logs, list, idempotent start, stop, restart.
	logs, err := b.Logs(ctx, s.ID, 10, time.Time{})
	if err != nil || len(logs) == 0 || logs[0].Text != "started" {
		t.Fatalf("logs %v %v", logs, err)
	}
	if l, _ := b.List(ctx, map[string]string{"environment": env}); len(l) != 1 {
		t.Fatalf("list %d", len(l))
	}
	if w2, err := b.Start(ctx, s, RegistryAuth{}); err != nil || w2.Endpoint != w.Endpoint {
		t.Fatalf("idempotent start: %v %+v", err, w2)
	}
	if err := b.Stop(ctx, s.ID, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if w3, _ := b.Inspect(ctx, s.ID); w3.State != "exited" {
		t.Fatalf("after stop: %s", w3.State)
	}
	if w4, err := b.Start(ctx, s, RegistryAuth{}); err != nil || w4.State != "running" || w4.Endpoint != w.Endpoint {
		t.Fatalf("restart keeps identity: %v %+v", err, w4)
	}
	if err := b.Remove(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Inspect(ctx, s.ID); err != ErrNotFound {
		t.Fatalf("after remove: %v", err)
	}
	if _, err := os.Stat("/run/netns/" + nsName(s.ID)); err == nil {
		t.Fatal("netns leaked")
	}
}
