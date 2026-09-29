//go:build linux

package runtime

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/contrib/seccomp"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	cerrdefs "github.com/containerd/errdefs"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
)

// Containerd is the primary runtime backend (ADR-003).
type Containerd struct {
	c          *containerd.Client
	ns         string
	cfg        config.RuntimeConfig
	secretsDir string
	stateDir   string
	net        *netPlumber
}

func init() {
	NewContainerd = func(c config.RuntimeConfig, secretsDir string) (Backend, error) {
		return newContainerd(c, secretsDir, filepath.Join(filepath.Dir(c.VolumesDir), "runtimed"))
	}
}

func newContainerd(c config.RuntimeConfig, secretsDir, stateDir string) (*Containerd, error) {
	cl, err := containerd.New(c.ContainerdSocket, containerd.WithTimeout(10*time.Second))
	if err != nil {
		return nil, fmt.Errorf("containerd: %w", err)
	}
	np, err := newNetPlumber(filepath.Join(stateDir, "net"))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(stateDir, "workloads"), 0o711); err != nil {
		return nil, err
	}
	return &Containerd{c: cl, ns: c.ContainerdNS, cfg: c, secretsDir: secretsDir, stateDir: stateDir, net: np}, nil
}

func (b *Containerd) Name() string { return "containerd" }

func (b *Containerd) ctx(ctx context.Context) context.Context {
	return namespaces.WithNamespace(ctx, b.ns)
}

func shimAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Capabilities probes the daemon and installed shims.
func (b *Containerd) Capabilities(ctx context.Context) (*Capabilities, error) {
	v, err := b.c.Version(b.ctx(ctx))
	if err != nil {
		return nil, err
	}
	c := &Capabilities{Backend: "containerd", Version: v.Version, Runtimes: map[string]bool{RuntimeRunc: true}, Devices: map[string]bool{}}
	if shimAvailable("containerd-shim-runsc-v1") {
		c.Runtimes[RuntimeRunsc] = true
	}
	if shimAvailable("containerd-shim-kata-v2") {
		if _, err := os.Stat("/dev/kvm"); err == nil {
			c.Runtimes[RuntimeVM] = true
		}
	}
	for dev, path := range map[string]string{"kvm": "/dev/kvm", "fuse": "/dev/fuse", "gpu": "/dev/nvidiactl"} {
		if _, err := os.Stat(path); err == nil {
			c.Devices[dev] = true
		}
	}
	return c, nil
}

func (b *Containerd) EnsureNetwork(ctx context.Context, n NetworkSpec) (*NetworkInfo, error) {
	e, err := b.net.ensureEnv(n.EnvironmentID)
	if err != nil {
		return nil, err
	}
	return &NetworkInfo{ID: n.EnvironmentID, Name: NetworkName(n.EnvironmentID), Subnet: e.Subnet, Gateway: e.Gateway, Bridge: e.Bridge}, nil
}

func (b *Containerd) RemoveNetwork(ctx context.Context, envID string) error {
	return b.net.removeEnv(envID)
}

func (b *Containerd) resolver(auth RegistryAuth) remotes.Resolver {
	return docker.NewResolver(docker.ResolverOptions{Hosts: docker.ConfigureDefaultRegistries(
		docker.WithPlainHTTP(docker.MatchLocalhost),
		docker.WithAuthorizer(docker.NewDockerAuthorizer(docker.WithAuthCreds(func(host string) (string, string, error) {
			if auth.Server != "" && host == auth.Server {
				return auth.User, auth.Password, nil
			}
			return "", "", nil
		}))),
	)})
}

func (b *Containerd) runtimeHandler(rt string) string {
	switch rt {
	case RuntimeRunsc:
		return b.cfg.RunscHandler
	case RuntimeVM:
		return b.cfg.VMHandler
	}
	return b.cfg.RuncHandler
}

func (b *Containerd) workloadDir(id string) string { return filepath.Join(b.stateDir, "workloads", id) }

// Start creates (or restarts) a hardened workload.
func (b *Containerd) Start(ctx context.Context, s *Spec, auth RegistryAuth) (*Workload, error) {
	cctx := b.ctx(ctx)
	if w, err := b.Inspect(ctx, s.ID); err == nil && w.State == "running" {
		return w, nil
	}
	nsPath, ip, err := b.net.setupWorkload(s.EnvironmentID, s.ID, s.Service)
	if err != nil {
		return nil, fmt.Errorf("network: %w", err)
	}
	if c, err := b.c.LoadContainer(cctx, s.ID); err == nil {
		// Existing container whose task stopped: start a fresh task.
		return b.startTask(ctx, c, s, ip.String())
	}
	sn := b.cfg.ContainerdSnapshotter
	img, err := b.c.GetImage(cctx, s.Image)
	if err != nil {
		popts := []containerd.RemoteOpt{containerd.WithPullUnpack, containerd.WithResolver(b.resolver(auth))}
		if sn != "" {
			popts = append(popts, containerd.WithPullSnapshotter(sn))
		}
		img, err = b.c.Pull(cctx, s.Image, popts...)
		if err != nil {
			return nil, fmt.Errorf("pull %s: %w", s.Image, err)
		}
	} else if ok, _ := img.IsUnpacked(cctx, sn); !ok {
		if err := img.Unpack(cctx, sn); err != nil {
			return nil, fmt.Errorf("unpack %s: %w", s.Image, err)
		}
	}
	wdir := b.workloadDir(s.ID)
	if err := os.MkdirAll(wdir, 0o755); err != nil {
		return nil, err
	}
	for name, content := range map[string]string{"resolv.conf": resolvConf(), "hosts": b.net.hostsFile(s.EnvironmentID, s.ID), "hostname": s.Service + "\n"} {
		if err := os.WriteFile(filepath.Join(wdir, name), []byte(content), 0o644); err != nil {
			return nil, err
		}
	}
	mounts := []specs.Mount{
		{Destination: "/etc/resolv.conf", Type: "bind", Source: filepath.Join(wdir, "resolv.conf"), Options: []string{"rbind", "ro"}},
		{Destination: "/etc/hosts", Type: "bind", Source: filepath.Join(wdir, "hosts"), Options: []string{"rbind", "ro"}},
		{Destination: "/etc/hostname", Type: "bind", Source: filepath.Join(wdir, "hostname"), Options: []string{"rbind", "ro"}},
		{Destination: "/tmp", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "nodev", "noexec", "mode=1777", "size=256m"}},
	}
	for _, t := range s.Tmpfs {
		mounts = append(mounts, specs.Mount{Destination: t, Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "nodev", "mode=1777", "size=256m"}})
	}
	if len(s.SecretFiles) > 0 {
		dir := filepath.Join(b.secretsDir, s.ID)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		for name, val := range s.SecretFiles {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(val), 0o444); err != nil {
				return nil, err
			}
		}
		mounts = append(mounts, specs.Mount{Destination: "/run/secrets", Type: "bind", Source: dir, Options: []string{"rbind", "ro", "nosuid", "nodev", "noexec"}})
	}
	for _, v := range s.Volumes {
		src := filepath.Join(b.cfg.VolumesDir, v.VolumeID)
		if filepath.Dir(src) != filepath.Clean(b.cfg.VolumesDir) {
			return nil, errors.New("invalid volume id")
		}
		if err := os.MkdirAll(src, 0o750); err != nil {
			return nil, err
		}
		uid := v.OwnerUID
		if uid == 0 {
			uid = 10001
		}
		_ = os.Chown(src, uid, uid)
		opts := []string{"rbind", "nosuid", "nodev"}
		if v.ReadOnly {
			opts = append(opts, "ro")
		}
		mounts = append(mounts, specs.Mount{Destination: v.Target, Type: "bind", Source: src, Options: opts})
	}
	env := make([]string, 0, len(s.Env)+1)
	for k, v := range s.Env {
		env = append(env, k+"="+v)
	}
	if s.Port > 0 {
		env = append(env, fmt.Sprintf("PORT=%d", s.Port))
	}
	caps := []string{}
	if s.Kind == "backing" {
		caps = []string{"CAP_CHOWN", "CAP_SETUID", "CAP_SETGID", "CAP_DAC_OVERRIDE", "CAP_FOWNER"}
	}
	opts := []oci.SpecOpts{
		oci.WithImageConfig(img),
		oci.WithEnv(env),
		oci.WithHostname(s.Service),
		oci.WithMounts(mounts),
		oci.WithCapabilities(caps),
		oci.WithNoNewPrivileges,
		seccomp.WithDefaultProfile(),
		oci.WithMemoryLimit(uint64(s.MemoryBytes)),
		oci.WithCPUCFS(int64(s.CPU*100000), 100000),
		oci.WithPidsLimit(int64(s.PIDs)),
		oci.WithLinuxNamespace(specs.LinuxNamespace{Type: specs.NetworkNamespace, Path: nsPath}),
		withNofile(uint64(hostNoFile())),
	}
	if s.ReadOnlyRoot {
		opts = append(opts, oci.WithRootFSReadonly())
	}
	if len(s.Command) > 0 {
		opts = append(opts, oci.WithProcessArgs(s.Command...))
	}
	if s.User != "" {
		opts = append(opts, oci.WithUser(s.User))
	}
	for _, c := range s.Capabilities {
		switch c {
		case "kvm", "fuse":
			opts = append(opts, oci.WithDevices("/dev/"+c, "", "rwm"))
			if c == "fuse" {
				opts = append(opts, oci.WithAddedCapabilities([]string{"CAP_SYS_ADMIN"}))
			}
		case "host-network":
			opts = append(opts, oci.WithHostNamespace(specs.NetworkNamespace))
		default:
			return nil, fmt.Errorf("capability %q is not supported by the containerd backend", c)
		}
	}
	var snap []containerd.NewContainerOpts
	if sn != "" {
		snap = append(snap, containerd.WithSnapshotter(sn))
	}
	c, err := b.c.NewContainer(cctx, s.ID, append(snap,
		containerd.WithImage(img),
		containerd.WithNewSnapshot(s.ID+"-rootfs", img),
		containerd.WithRuntime(b.runtimeHandler(s.Runtime), nil),
		containerd.WithContainerLabels(s.Labels()),
		containerd.WithNewSpec(opts...),
	)...)
	if err != nil {
		return nil, fmt.Errorf("create container: %w", err)
	}
	return b.startTask(ctx, c, s, ip.String())
}

func withNofile(n uint64) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, sp *oci.Spec) error {
		if sp.Process == nil {
			sp.Process = &specs.Process{}
		}
		var out []specs.POSIXRlimit
		for _, r := range sp.Process.Rlimits {
			if r.Type != "RLIMIT_NOFILE" {
				out = append(out, r)
			}
		}
		sp.Process.Rlimits = append(out, specs.POSIXRlimit{Type: "RLIMIT_NOFILE", Hard: n, Soft: n})
		return nil
	}
}

func (b *Containerd) startTask(ctx context.Context, c containerd.Container, s *Spec, ip string) (*Workload, error) {
	cctx := b.ctx(ctx)
	if t, err := c.Task(cctx, nil); err == nil {
		st, _ := t.Status(cctx)
		if st.Status == containerd.Running {
			return b.Inspect(ctx, s.ID)
		}
		_, _ = t.Delete(cctx, containerd.WithProcessKill)
	}
	logPath := filepath.Join(b.workloadDir(s.ID), "output.log")
	rotateLog(logPath, 10<<20)
	t, err := c.NewTask(cctx, cio.LogFile(logPath))
	if err != nil {
		return nil, fmt.Errorf("create task: %w", err)
	}
	if err := t.Start(cctx); err != nil {
		_, _ = t.Delete(cctx, containerd.WithProcessKill)
		return nil, fmt.Errorf("start task: %w", err)
	}
	return b.Inspect(ctx, s.ID)
}

func rotateLog(p string, max int64) {
	if fi, err := os.Stat(p); err == nil && fi.Size() > max {
		_ = os.Rename(p, p+".1")
	}
}

func (b *Containerd) Inspect(ctx context.Context, id string) (*Workload, error) {
	cctx := b.ctx(ctx)
	c, err := b.c.LoadContainer(cctx, id)
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	labels, _ := c.Labels(cctx)
	if labels["org.opendeploy.managed"] != "true" {
		return nil, ErrNotFound
	}
	w := &Workload{ID: id, RuntimeID: c.ID(), State: "created", Labels: labels}
	if t, err := c.Task(cctx, nil); err == nil {
		st, err := t.Status(cctx)
		if err == nil {
			switch st.Status {
			case containerd.Running:
				w.State = "running"
			case containerd.Stopped:
				w.State, w.ExitCode = "exited", int(st.ExitStatus)
				w.OOMKilled = st.ExitStatus == 137
			default:
				w.State = string(st.Status)
			}
		}
	} else {
		w.State = "exited"
	}
	env := labels["org.opendeploy.environment"]
	if ip := b.net.lookup(env, id); ip != "" {
		w.IP = ip
		if spec, err := c.Spec(cctx); err == nil && spec.Process != nil {
			for _, e := range spec.Process.Env {
				if strings.HasPrefix(e, "PORT=") {
					w.Endpoint = ip + ":" + strings.TrimPrefix(e, "PORT=")
				}
			}
		}
	}
	if info, err := c.Info(cctx); err == nil {
		w.StartedAt = info.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return w, nil
}

func (b *Containerd) Stop(ctx context.Context, id string, timeout time.Duration) error {
	cctx := b.ctx(ctx)
	c, err := b.c.LoadContainer(cctx, id)
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return nil
		}
		return err
	}
	t, err := c.Task(cctx, nil)
	if err != nil {
		return nil
	}
	exitCh, err := t.Wait(cctx)
	if err != nil {
		return err
	}
	_ = t.Kill(cctx, syscall.SIGTERM)
	select {
	case <-exitCh:
	case <-time.After(timeout):
		_ = t.Kill(cctx, syscall.SIGKILL)
		<-exitCh
	}
	_, err = t.Delete(cctx)
	return err
}

func (b *Containerd) Remove(ctx context.Context, id string) error {
	cctx := b.ctx(ctx)
	c, err := b.c.LoadContainer(cctx, id)
	env := ""
	if err == nil {
		labels, _ := c.Labels(cctx)
		env = labels["org.opendeploy.environment"]
		if t, err := c.Task(cctx, nil); err == nil {
			_, _ = t.Delete(cctx, containerd.WithProcessKill)
		}
		if err := c.Delete(cctx, containerd.WithSnapshotCleanup); err != nil && !cerrdefs.IsNotFound(err) {
			return err
		}
	} else if !cerrdefs.IsNotFound(err) {
		return err
	}
	if env != "" {
		b.net.teardownWorkload(env, id)
	}
	_ = os.RemoveAll(filepath.Join(b.secretsDir, id))
	_ = os.RemoveAll(b.workloadDir(id))
	return nil
}

func (b *Containerd) List(ctx context.Context, filter map[string]string) ([]Workload, error) {
	cctx := b.ctx(ctx)
	fs := []string{`labels."org.opendeploy.managed"==true`}
	for k, v := range filter {
		fs = append(fs, fmt.Sprintf(`labels."org.opendeploy.%s"==%s`, k, v))
	}
	cs, err := b.c.Containers(cctx, strings.Join(fs, ","))
	if err != nil {
		return nil, err
	}
	out := make([]Workload, 0, len(cs))
	for _, c := range cs {
		if w, err := b.Inspect(ctx, c.ID()); err == nil {
			out = append(out, *w)
		}
	}
	return out, nil
}

// Logs returns the tail of the workload's combined output.
func (b *Containerd) Logs(ctx context.Context, id string, tail int, since time.Time) ([]LogLine, error) {
	if tail <= 0 || tail > 5000 {
		tail = 500
	}
	f, err := os.Open(filepath.Join(b.workloadDir(id), "output.log"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > 4<<20 {
		_, _ = f.Seek(fi.Size()-4<<20, io.SeekStart)
	}
	var lines []LogLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		lines = append(lines, LogLine{Stream: "stdout", Text: sc.Text()})
		if len(lines) > tail {
			lines = lines[1:]
		}
	}
	return lines, nil
}
