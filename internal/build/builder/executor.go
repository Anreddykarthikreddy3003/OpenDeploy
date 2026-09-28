// Package builder implements builderd: it fetches source at an exact SHA,
// detects the build plan, runs an isolated BuildKit build, and hands the
// output to artifactd (PRD §7, SC-03, SC-04). builderd never has access to
// the runtime socket or the platform database.
package builder

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Output kinds.
const (
	OutputOCI = "oci"
	OutputTar = "tar"
)

// Spec is one BuildKit invocation.
type Spec struct {
	ContextDir    string
	DockerfileDir string
	Dockerfile    string // file name inside DockerfileDir
	Target        string
	Output        string // oci | tar
	Dest          string
	BuildArgs     map[string]string
	Secrets       map[string]string // id -> file path (mounted via RUN --mount=type=secret)
	NetworkNone   bool
	Platform      string
}

// Executor runs a build.
type Executor interface {
	Name() string
	Build(ctx context.Context, s Spec, log io.Writer) error
}

// Buildctl drives a rootless buildkitd (OCI worker) through buildctl. The
// daemon is started without any insecure entitlements, so network.host and
// security.insecure requests are refused by BuildKit itself.
type Buildctl struct {
	Bin  string
	Addr string
}

func (b *Buildctl) Name() string { return "buildkit" }

func (b *Buildctl) Build(ctx context.Context, s Spec, log io.Writer) error {
	bin := b.Bin
	if bin == "" {
		bin = "buildctl"
	}
	args := []string{"--addr", b.Addr, "build", "--progress", "plain",
		"--frontend", "dockerfile.v0",
		"--local", "context=" + s.ContextDir,
		"--local", "dockerfile=" + s.DockerfileDir,
		"--opt", "filename=" + s.Dockerfile,
	}
	if s.Target != "" {
		args = append(args, "--opt", "target="+s.Target)
	}
	if s.Platform != "" {
		args = append(args, "--opt", "platform="+s.Platform)
	}
	if s.NetworkNone {
		args = append(args, "--opt", "force-network-mode=none")
	}
	for _, k := range sortedKeys(s.BuildArgs) {
		args = append(args, "--opt", "build-arg:"+k+"="+s.BuildArgs[k])
	}
	for _, k := range sortedKeys(s.Secrets) {
		args = append(args, "--secret", "id="+k+","+csvField("src="+s.Secrets[k]))
	}
	switch s.Output {
	case OutputOCI:
		args = append(args, "--output", "type=oci,"+csvField("dest="+s.Dest))
	case OutputTar:
		args = append(args, "--output", "type=tar,"+csvField("dest="+s.Dest))
	default:
		return fmt.Errorf("unknown output %q", s.Output)
	}
	return run(ctx, bin, args, minimalEnv(nil), log)
}

// DockerBuildx builds with a Docker Engine's embedded BuildKit (the
// optional Docker backend adapter, ADR-003). It is used for Trusted builds
// on hosts that run Docker instead of containerd.
type DockerBuildx struct {
	Bin  string
	Host string // DOCKER_HOST
	// Builder names the buildx builder; empty selects automatically: the
	// engine's embedded BuildKit when it uses the containerd image store
	// (which can export OCI/tar), otherwise a dedicated docker-container
	// builder named "opendeploy" (created on first use).
	Builder string
	// CABundle is an extra PEM bundle the dedicated builder trusts for
	// registries (TLS-inspecting enterprise proxies).
	CABundle string
	// Mirrors are registry mirrors for docker.io (mirroring the engine's).
	Mirrors []string

	mu       sync.Mutex
	resolved string
}

func (d *DockerBuildx) Name() string { return "docker-buildx" }

// dedicatedBuilder is the buildx builder OpenDeploy manages on engines
// whose embedded BuildKit cannot export OCI layouts.
const dedicatedBuilder = "opendeploy"

func (d *DockerBuildx) env() []string {
	if d.Host != "" {
		return minimalEnv([]string{"DOCKER_HOST=" + d.Host})
	}
	return minimalEnv(nil)
}

func (d *DockerBuildx) builder(ctx context.Context, bin string, log io.Writer) (string, error) {
	if d.Builder != "" {
		return d.Builder, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.resolved != "" {
		return d.resolved, nil
	}
	info := exec.CommandContext(ctx, bin, "info", "--format", "{{json .DriverStatus}}")
	info.Env = d.env()
	out, err := info.Output()
	if os.Getenv("OPENDEPLOY_BUILDX_DEDICATED") == "1" {
		err = errors.New("dedicated builder forced")
	}
	if err == nil && strings.Contains(string(out), "io.containerd.snapshotter") {
		d.resolved = "default"
		return d.resolved, nil
	}
	chk := exec.CommandContext(ctx, bin, "buildx", "inspect", dedicatedBuilder)
	chk.Env = d.env()
	if chk.Run() != nil {
		fmt.Fprintln(log, "==> creating dedicated buildx builder (engine image store cannot export OCI layouts)")
		args := []string{"buildx", "create", "--name", dedicatedBuilder, "--driver", "docker-container", "--bootstrap"}
		if cfg, err := d.buildkitdConfig(); err != nil {
			return "", err
		} else if cfg != "" {
			defer os.Remove(cfg)
			args = append(args, "--buildkitd-config", cfg)
		}
		if err := run(ctx, bin, args, d.env(), log); err != nil {
			return "", fmt.Errorf("create buildx builder: %w", err)
		}
	}
	d.resolved = dedicatedBuilder
	return d.resolved, nil
}

// commonRegistries receive the extra CA bundle (BuildKit trust is scoped
// per registry host).
var commonRegistries = []string{"docker.io", "registry-1.docker.io", "ghcr.io", "gcr.io", "mirror.gcr.io", "quay.io", "registry.k8s.io",
	"public.ecr.aws", "mcr.microsoft.com", "registry.gitlab.com"}

// buildkitdConfig renders a buildkitd.toml for the dedicated builder, or ""
// when no customisation is needed. buildx copies referenced CA files into
// the builder container.
func (d *DockerBuildx) buildkitdConfig() (string, error) {
	if d.CABundle == "" {
		d.CABundle = os.Getenv("OPENDEPLOY_BUILD_CA_BUNDLE")
	}
	if d.CABundle == "" && len(d.Mirrors) == 0 {
		return "", nil
	}
	var b strings.Builder
	hosts := append([]string{}, commonRegistries...)
	for _, m := range d.Mirrors {
		if u, err := url.Parse(m); err == nil && u.Host != "" {
			hosts = append(hosts, u.Host)
		}
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		if seen[h] {
			continue
		}
		seen[h] = true
		fmt.Fprintf(&b, "[registry.%q]\n", h)
		if h == "docker.io" && len(d.Mirrors) > 0 {
			var ms []string
			for _, m := range d.Mirrors {
				if u, err := url.Parse(m); err == nil && u.Host != "" {
					ms = append(ms, strconv.Quote(u.Host))
				}
			}
			fmt.Fprintf(&b, "  mirrors = [%s]\n", strings.Join(ms, ", "))
		}
		if d.CABundle != "" {
			fmt.Fprintf(&b, "  ca = [%q]\n", d.CABundle)
		}
	}
	f, err := os.CreateTemp("", "buildkitd-*.toml")
	if err != nil {
		return "", err
	}
	defer f.Close()
	_, err = f.WriteString(b.String())
	return f.Name(), err
}

func (d *DockerBuildx) Build(ctx context.Context, s Spec, log io.Writer) error {
	bin := d.Bin
	if bin == "" {
		bin = "docker"
	}
	bld, err := d.builder(ctx, bin, log)
	if err != nil {
		return err
	}
	args := []string{"buildx", "--builder", bld, "build", "--progress", "plain", "--pull=false",
		"-f", s.DockerfileDir + "/" + s.Dockerfile}
	if s.Target != "" {
		args = append(args, "--target", s.Target)
	}
	if s.Platform != "" {
		args = append(args, "--platform", s.Platform)
	}
	if s.NetworkNone {
		args = append(args, "--network", "none")
	}
	for _, k := range sortedKeys(s.BuildArgs) {
		args = append(args, "--build-arg", k+"="+s.BuildArgs[k])
	}
	for _, k := range sortedKeys(s.Secrets) {
		args = append(args, "--secret", "id="+k+","+csvField("src="+s.Secrets[k]))
	}
	switch s.Output {
	case OutputOCI:
		args = append(args, "--output", "type=oci,"+csvField("dest="+s.Dest))
	case OutputTar:
		args = append(args, "--output", "type=tar,"+csvField("dest="+s.Dest))
	default:
		return fmt.Errorf("unknown output %q", s.Output)
	}
	args = append(args, s.ContextDir)
	return run(ctx, bin, args, d.env(), log)
}

// csvField quotes a key=value pair for BuildKit's CSV-parsed flags
// (--output, --secret) so paths containing commas or quotes stay intact.
func csvField(kv string) string {
	if !strings.ContainsAny(kv, ",\"\r\n") {
		return kv
	}
	return `"` + strings.ReplaceAll(kv, `"`, `""`) + `"`
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// minimalEnv avoids leaking builderd's environment into tools.
func minimalEnv(extra []string) []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.TempDir(), "LANG=C.UTF-8"}
	for _, k := range []string{"BUILDKIT_HOST", "DOCKER_CONFIG", "XDG_RUNTIME_DIR", "SSL_CERT_FILE"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return append(env, extra...)
}

func run(ctx context.Context, bin string, args, env []string, log io.Writer) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			fmt.Fprintln(log, sc.Text())
		}
		_, _ = io.Copy(io.Discard, pr)
	}()
	err := cmd.Start()
	if err != nil {
		pw.Close()
		wg.Wait()
		return fmt.Errorf("start %s: %w", bin, err)
	}
	err = cmd.Wait()
	pw.Close()
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return fmt.Errorf("build failed (exit %d)", ee.ExitCode())
	}
	return err
}

// LineWriter splits writes into lines and passes each to fn after masking.
type LineWriter struct {
	mu   sync.Mutex
	buf  []byte
	fn   func(string)
	mask *Masker
}

func NewLineWriter(fn func(string), m *Masker) *LineWriter { return &LineWriter{fn: fn, mask: m} }

func (w *LineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := strings.IndexByte(string(w.buf), '\n')
		if i < 0 {
			break
		}
		line := string(w.buf[:i])
		w.buf = w.buf[i+1:]
		w.fn(w.mask.Mask(strings.TrimRight(line, "\r")))
	}
	if len(w.buf) > 64*1024 {
		w.fn(w.mask.Mask(string(w.buf)))
		w.buf = nil
	}
	return len(p), nil
}

// Flush emits any trailing partial line.
func (w *LineWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) > 0 {
		w.fn(w.mask.Mask(string(w.buf)))
		w.buf = nil
	}
}

// Masker replaces exact secret values in log output. This is log hygiene,
// not a security boundary (PRD §7.5, §13.1, Q11): transformed or split
// secrets are not detected. Leak detection reports matches separately.
type Masker struct {
	mu      sync.Mutex
	values  []string
	Leaked  map[string]bool // secret ids whose exact value appeared
	idByVal map[string]string
}

func NewMasker() *Masker { return &Masker{Leaked: map[string]bool{}, idByVal: map[string]string{}} }

// Add registers a secret value (values shorter than 6 bytes are ignored to
// avoid masking common substrings).
func (m *Masker) Add(id, v string) {
	if m == nil || len(v) < 6 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values = append(m.values, v)
	m.idByVal[v] = id
	sort.Slice(m.values, func(i, j int) bool { return len(m.values[i]) > len(m.values[j]) })
}

func (m *Masker) Mask(s string) string {
	if m == nil {
		return s
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.values {
		if strings.Contains(s, v) {
			m.Leaked[m.idByVal[v]] = true
			s = strings.ReplaceAll(s, v, "[MASKED]")
		}
	}
	return s
}

// LeakedIDs returns secret ids seen in output.
func (m *Masker) LeakedIDs() []string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.Leaked {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
