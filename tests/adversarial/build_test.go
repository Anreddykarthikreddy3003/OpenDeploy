//go:build adversarial

package adversarial

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/build/builder"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/network"
)

func buildWith(t *testing.T, ex builder.Executor, dockerfile string, files map[string]string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	ctxDir := filepath.Join(dir, "ctx")
	_ = os.MkdirAll(ctxDir, 0o755)
	for n, c := range files {
		if strings.HasPrefix(c, "symlink:") {
			_ = os.Symlink(strings.TrimPrefix(c, "symlink:"), filepath.Join(ctxDir, n))
			continue
		}
		_ = os.WriteFile(filepath.Join(ctxDir, n), []byte(c), 0o644)
	}
	dfDir := filepath.Join(dir, "df")
	_ = os.MkdirAll(dfDir, 0o755)
	_ = os.WriteFile(filepath.Join(dfDir, "Dockerfile"), []byte(dockerfile), 0o644)
	dest := filepath.Join(dir, ids.New("dep"), "out.tar")
	_ = os.MkdirAll(filepath.Dir(dest), 0o755)
	var log bytes.Buffer
	err := ex.Build(context.Background(), builder.Spec{ContextDir: ctxDir, DockerfileDir: dfDir, Dockerfile: "Dockerfile", Output: builder.OutputTar, Dest: dest}, &log)
	if err != nil {
		return log.String(), err
	}
	return dest, nil
}

func tarContains(t *testing.T, path, name string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err != nil {
			return "", false
		}
		if strings.TrimPrefix(h.Name, "./") == name {
			b, _ := io.ReadAll(tr)
			return string(b), true
		}
	}
}

// ST-01 / Q4 / Q6-Q8 / Q63 / Q64 (trusted boundary via BuildKit).
func TestMaliciousBuilds(t *testing.T) {
	need(t)
	ex := &builder.DockerBuildx{}
	sentinel := filepath.Join(t.TempDir(), "platform-secret")
	_ = os.WriteFile(sentinel, []byte("TOP-SECRET-PLATFORM-STATE"), 0o600)

	t.Run("insecure entitlement refused", func(t *testing.T) {
		if _, err := buildWith(t, ex, "FROM alpine:3.20\nRUN --security=insecure echo pwned > /pwned\n", nil); err == nil {
			t.Fatal("security.insecure entitlement granted")
		}
	})
	t.Run("host network entitlement refused", func(t *testing.T) {
		if _, err := buildWith(t, ex, "FROM alpine:3.20\nRUN --network=host echo pwned > /pwned\n", nil); err == nil {
			t.Fatal("network.host entitlement granted")
		}
	})
	t.Run("no runtime sockets inside builds", func(t *testing.T) {
		df := "FROM alpine:3.20\nRUN for s in /var/run/docker.sock /run/containerd/containerd.sock /run/opendeploy /var/lib/opendeploy; do if [ -e $s ]; then echo FOUND $s; exit 1; fi; done\n"
		if out, err := buildWith(t, ex, df, nil); err != nil {
			t.Fatalf("socket/state visible in build: %v\n%s", err, out)
		}
	})
	t.Run("host files unreadable via symlinked context", func(t *testing.T) {
		out, err := buildWith(t, ex, "FROM alpine:3.20 AS b\nCOPY . /ctx\nFROM scratch\nCOPY --from=b /ctx /ctx\n",
			map[string]string{"leak": "symlink:" + sentinel, "leak2": "symlink:/etc/shadow"})
		if err != nil {
			t.Logf("build refused symlinked context (acceptable): %v", err)
			return
		}
		for _, n := range []string{"ctx/leak", "ctx/leak2"} {
			if body, ok := tarContains(t, out, n); ok && (strings.Contains(body, "TOP-SECRET") || strings.Contains(body, "root:")) {
				t.Fatalf("host file content leaked through %s", n)
			}
		}
	})
	t.Run("builds cannot reach host, metadata or private ranges", func(t *testing.T) {
		gw, _ := dockerOut(t, "network", "inspect", "bridge", "-f", "{{(index .IPAM.Config 0).Gateway}}")
		if net.ParseIP(gw) == nil {
			t.Skip("CAPABILITY-BLOCKED: default docker bridge not found")
		}
		ln, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		port := ln.Addr().(*net.TCPAddr).Port
		// Control: without egressd rules the host listener is reachable from a
		// build step, so a pass below is attributable to enforcement.
		network.Flush(context.Background(), "")
		ctl := fmt.Sprintf("FROM alpine:3.20\nRUN nc -z -w 3 %s %d && echo CONTROL-%s\n", gw, port, ids.Token(4))
		if out, err := buildWith(t, ex, ctl, nil); err != nil {
			t.Skipf("CAPABILITY-BLOCKED: build steps cannot reach the host even without policy (%v)\n%s", err, out)
		}
		svc := &network.Service{StateFile: t.TempDir() + "/p.json", BuildBridges: []string{"docker0"}}
		if err := svc.Init(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer network.Flush(context.Background(), "")
		df := fmt.Sprintf("FROM alpine:3.20\nRUN echo %s; for t in %s:%d 169.254.169.254:80 10.255.255.1:80; do h=${t%%:*}; p=${t##*:}; if nc -z -w 3 $h $p; then echo REACHED $t; exit 1; fi; done\n", ids.Token(4), gw, port)
		if out, err := buildWith(t, ex, df, nil); err != nil {
			t.Fatalf("build reached a forbidden destination: %v\n%s", err, out)
		}
	})
}

// ST-01 untrusted path: the sandboxed executor runs under gVisor when the
// Docker engine has a runsc runtime; otherwise the capability is blocked
// and platform policy fails closed (covered by unit tests).
func TestUntrustedBuildSandbox(t *testing.T) {
	need(t)
	info, _ := dockerOut(t, "info", "--format", "{{json .Runtimes}}")
	if !strings.Contains(info, "runsc") {
		t.Skip("CAPABILITY-BLOCKED: docker has no runsc runtime (install gVisor)")
	}
	ex := &builder.SandboxedBuildKit{Image: "moby/buildkit:v0.24.0-rootless", Runtime: "runsc", Network: "bridge"}
	out, err := buildWith(t, ex, "FROM alpine:3.20\nRUN dmesg 2>&1 | head -3 > /kernel.txt || true\nRUN cat /proc/version > /version.txt\n", nil)
	if err != nil {
		t.Fatalf("sandboxed build failed: %v\n%s", err, out)
	}
	body, ok := tarContains(t, out, "version.txt")
	if !ok {
		t.Fatal("output missing")
	}
	if !strings.Contains(strings.ToLower(body), "gvisor") && !strings.Contains(body, "4.4.0") {
		t.Fatalf("build did not run under gVisor: %q", body)
	}
	if o, _ := exec.Command("docker", "ps", "-a", "--filter", "label=org.opendeploy.managed=untrusted-build", "-q").Output(); len(bytes.TrimSpace(o)) != 0 {
		t.Fatal("disposable build sandbox not removed")
	}
}
