package builder

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/build/detect"
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
	// Untrusted builds never receive secrets. The node's build CA bundle is
	// the one exception: it is public trust material builderd attaches to
	// every build, not a user secret.
	for id := range sp.Secrets {
		if !publicBuildSecret(id) {
			return errors.New("untrusted builds never receive secrets")
		}
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
	// Stream the context in as a tar over exec stdin: works for every
	// runtime (gVisor keeps its rootfs overlay inside the sandbox, so
	// host-side `docker cp` cannot see it) and never follows symlinks.
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(writeBuildTar(pw, sp)) }()
	if err := s.dockerIn(ctx, log, pr, "exec", "-i", name, "tar", "-x", "-f", "-", "-C", "/home/user"); err != nil {
		pr.CloseWithError(err)
		return fmt.Errorf("copy build context: %w", err)
	}
	args := []string{"exec", "-e", "BUILDKITD_FLAGS=--oci-worker-no-process-sandbox"}
	if _, ok := sp.Secrets[detect.BuildCASecretID]; ok {
		// The sandboxed BuildKit pulls base images itself: behind a
		// TLS-inspecting proxy it must trust the node's CA bundle too.
		args = append(args, "-e", "SSL_CERT_FILE=/home/user/ca/"+detect.BuildCASecretID)
	}
	args = append(args, name, "buildctl-daemonless.sh", "build",
		"--progress", "plain", "--frontend", "dockerfile.v0",
		"--local", "context=/home/user/ctx", "--local", "dockerfile=/home/user/df")
	for _, id := range sortedKeys(sp.Secrets) {
		args = append(args, "--secret", "id="+id+",src=/home/user/ca/"+id)
	}
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

// dockerIn runs docker with stdin.
func (s *SandboxedBuildKit) dockerIn(ctx context.Context, log io.Writer, stdin io.Reader, args ...string) error {
	bin := firstNonEmpty(s.Docker, "docker")
	cmd := exec.CommandContext(ctx, bin, args...)
	var env []string
	if s.Host != "" {
		env = append(env, "DOCKER_HOST="+s.Host)
	}
	cmd.Env = minimalEnv(env)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, log, log
	return cmd.Run()
}

// writeBuildTar writes ctx/... (the build context, symlinks preserved as
// links, special files skipped) and df/Dockerfile.
func writeBuildTar(w io.Writer, sp Spec) error {
	tw := tar.NewWriter(w)
	err := filepath.Walk(sp.ContextDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(sp.ContextDir, p)
		if err != nil {
			return err
		}
		link := ""
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			if link, err = os.Readlink(p); err != nil {
				return err
			}
		case fi.IsDir(), fi.Mode().IsRegular():
		default:
			return nil // devices, sockets, fifos
		}
		h, err := tar.FileInfoHeader(fi, link)
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(filepath.Join("ctx", rel))
		if fi.IsDir() {
			h.Name += "/"
		}
		h.Uid, h.Gid, h.Uname, h.Gname = 1000, 1000, "", ""
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, f)
			f.Close()
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	df, err := os.ReadFile(filepath.Join(sp.DockerfileDir, sp.Dockerfile))
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: "df/", Typeflag: tar.TypeDir, Mode: 0o755, Uid: 1000, Gid: 1000}); err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: "df/Dockerfile", Mode: 0o644, Size: int64(len(df)), Uid: 1000, Gid: 1000}); err != nil {
		return err
	}
	if _, err := tw.Write(df); err != nil {
		return err
	}
	if len(sp.Secrets) > 0 {
		if err := tw.WriteHeader(&tar.Header{Name: "ca/", Typeflag: tar.TypeDir, Mode: 0o755, Uid: 1000, Gid: 1000}); err != nil {
			return err
		}
		for _, id := range sortedKeys(sp.Secrets) {
			if !publicBuildSecret(id) {
				return fmt.Errorf("secret %q cannot enter a sandboxed build", id)
			}
			b, err := os.ReadFile(sp.Secrets[id])
			if err != nil {
				return err
			}
			if err := tw.WriteHeader(&tar.Header{Name: "ca/" + id, Mode: 0o644, Size: int64(len(b)), Uid: 1000, Gid: 1000}); err != nil {
				return err
			}
			if _, err := tw.Write(b); err != nil {
				return err
			}
		}
	}
	return tw.Close()
}

// publicBuildSecret reports the build "secrets" that are public trust
// material (the node's CA bundle), allowed into untrusted builds.
func publicBuildSecret(id string) bool {
	return id == detect.BuildCASecretID || id == detect.BuildCAExtraSecretID
}
