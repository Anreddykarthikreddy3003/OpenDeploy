package builder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SandboxedBuildKit runs each untrusted build in a disposable rootless
// BuildKit container under a stronger runtime (gVisor runsc) through the
// Docker Engine (PRD §7.4, SC-02, ADR-005). Nothing is shared between
// builds: no cache, no secrets, no host mounts; the container is removed
// when the build ends. Network egress is the untrusted build network, which
// egressd polices like any build bridge.
type SandboxedBuildKit struct {
	Docker  string // docker CLI (default "docker")
	Host    string // DOCKER_HOST
	Image   string // pinned rootless BuildKit image
	Runtime string // docker runtime name, e.g. "runsc"
	Network string // docker network for build egress
	Memory  string // e.g. "4g"
	CPUs    string // e.g. "2"
}

func (s *SandboxedBuildKit) Name() string { return "sandboxed-buildkit(" + s.Runtime + ")" }

func (s *SandboxedBuildKit) docker(ctx context.Context, log io.Writer, stdout io.Writer, args ...string) error {
	bin := s.Docker
	if bin == "" {
		bin = "docker"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	env := []string{}
	if s.Host != "" {
		env = append(env, "DOCKER_HOST="+s.Host)
	}
	cmd.Env = minimalEnv(env)
	if stdout != nil {
		cmd.Stdout = stdout
	} else {
		cmd.Stdout = log
	}
	cmd.Stderr = log
	return cmd.Run()
}

// Build implements Executor.
func (s *SandboxedBuildKit) Build(ctx context.Context, sp Spec, log io.Writer) error {
	if s.Runtime == "" || s.Image == "" {
		return errors.New("sandboxed build executor not configured (fail closed)")
	}
	if len(sp.Secrets) > 0 {
		return errors.New("untrusted builds never receive secrets")
	}
	name := "od-ubk-" + strings.ToLower(filepath.Base(filepath.Dir(sp.Dest)))
	netArg := "none"
	if !sp.NetworkNone && s.Network != "" {
		netArg = s.Network
	}
	mem, cpus := firstNonEmpty(s.Memory, "4g"), firstNonEmpty(s.CPUs, "2")
	run := []string{"run", "-d", "--rm", "--name", name, "--runtime", s.Runtime, "--network", netArg,
		"--memory", mem, "--memory-swap", mem, "--cpus", cpus, "--pids-limit", "4096",
		"--security-opt", "no-new-privileges=false", // rootless BuildKit needs newuidmap inside the gVisor sandbox
		"--label", "org.opendeploy.managed=untrusted-build",
		"--entrypoint", "sleep", s.Image, "infinity"}
	fmt.Fprintf(log, "==> starting disposable sandboxed BuildKit (%s runtime, network %s)\n", s.Runtime, netArg)
	if err := s.docker(ctx, log, nil, run...); err != nil {
		return fmt.Errorf("start sandbox: %w", err)
	}
	defer func() {
		_ = s.docker(context.Background(), io.Discard, io.Discard, "rm", "-f", name)
	}()
	if err := s.docker(ctx, log, nil, "exec", name, "mkdir", "-p", "/home/user/ctx", "/home/user/df"); err != nil {
		return err
	}
	if err := s.docker(ctx, log, nil, "cp", sp.ContextDir+"/.", name+":/home/user/ctx"); err != nil {
		return fmt.Errorf("copy context: %w", err)
	}
	if err := s.docker(ctx, log, nil, "cp", filepath.Join(sp.DockerfileDir, sp.Dockerfile), name+":/home/user/df/Dockerfile"); err != nil {
		return fmt.Errorf("copy dockerfile: %w", err)
	}
	args := []string{"exec", "-e", "BUILDKITD_FLAGS=--oci-worker-no-process-sandbox", name, "buildctl-daemonless.sh", "build",
		"--progress", "plain", "--frontend", "dockerfile.v0",
		"--local", "context=/home/user/ctx", "--local", "dockerfile=/home/user/df"}
	if sp.Target != "" {
		args = append(args, "--opt", "target="+sp.Target)
	}
	if sp.NetworkNone {
		args = append(args, "--opt", "force-network-mode=none")
	}
	for _, k := range sortedKeys(sp.BuildArgs) {
		args = append(args, "--opt", "build-arg:"+k+"="+sp.BuildArgs[k])
	}
	switch sp.Output {
	case OutputOCI:
		args = append(args, "--output", "type=oci,dest=-")
	case OutputTar:
		args = append(args, "--output", "type=tar,dest=-")
	default:
		return fmt.Errorf("unknown output %q", sp.Output)
	}
	out, err := os.OpenFile(sp.Dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer out.Close()
	lw := &limitedWriter{w: out, n: 10 << 30}
	if err := s.docker(ctx, log, lw, args...); err != nil {
		return fmt.Errorf("sandboxed build failed: %w", err)
	}
	if lw.over {
		return errors.New("build output exceeds size limit")
	}
	return nil
}

type limitedWriter struct {
	w    io.Writer
	n    int64
	over bool
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.n {
		l.over = true
		return 0, errors.New("output limit exceeded")
	}
	l.n -= int64(len(p))
	return l.w.Write(p)
}
