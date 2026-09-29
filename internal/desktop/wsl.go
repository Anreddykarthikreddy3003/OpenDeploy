package desktop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// WSL runs the data plane as a managed WSL2 distribution. The distro's
// /etc/wsl.conf enables systemd and disables Windows interop, drive
// automounts and PATH sharing, so workloads inside cannot reach the Windows
// host through WSL integration (PRD Q3). WSL stops a distro when no client
// process is attached, so the supervisor holds a keep-alive process.
type WSL struct {
	Exe        string // wsl.exe
	Distro     string // registered name, e.g. "OpenDeploy"
	InstallDir string // where the distro's ext4.vhdx lives
	Rootfs     string // the packaged .wsl (tar.gz) image
	// ConfigFile is the service account's %UserProfile%\.wslconfig; when
	// set, Ensure makes the WSL VM boot with a cgroup v2-only hierarchy,
	// which the node's resource limits require.
	ConfigFile string
	Log        *slog.Logger

	mu        sync.Mutex
	keepalive *exec.Cmd
}

// hideConsole is set on Windows so child processes get no console window.
var hideConsole func(*exec.Cmd)

func (w *WSL) Kind() string { return "wsl2" }

func (w *WSL) exe() string {
	if w.Exe != "" {
		return w.Exe
	}
	return "wsl.exe"
}

func (w *WSL) command(ctx context.Context, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, w.exe(), args...)
	// wsl.exe writes UTF-16 unless told otherwise.
	c.Env = append(os.Environ(), "WSL_UTF8=1")
	if hideConsole != nil {
		hideConsole(c)
	}
	return c
}

func (w *WSL) run(ctx context.Context, args ...string) (string, error) {
	out, err := w.command(ctx, args...).CombinedOutput()
	s := decodeWSLOutput(out)
	if err != nil {
		return s, fmt.Errorf("wsl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(s))
	}
	return s, nil
}

// decodeWSLOutput handles both UTF-8 and the UTF-16LE older wsl.exe prints.
func decodeWSLOutput(b []byte) string {
	if len(b) >= 2 && bytes.Count(b, []byte{0}) >= len(b)/3 {
		b = bytes.TrimPrefix(b, []byte{0xff, 0xfe})
		u := make([]uint16, 0, len(b)/2)
		for i := 0; i+1 < len(b); i += 2 {
			u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
		}
		return string(utf16.Decode(u))
	}
	return string(b)
}

// Installed reports whether the distro is registered for this account.
func (w *WSL) Installed(ctx context.Context) (bool, error) {
	out, err := w.run(ctx, "--list", "--quiet")
	if err != nil {
		// No distributions at all makes older wsl.exe exit non-zero.
		if strings.Contains(strings.ToLower(out), "no installed distributions") {
			return false, nil
		}
		return false, err
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.EqualFold(strings.TrimSpace(strings.Trim(line, "\r\x00")), w.Distro) {
			return true, nil
		}
	}
	return false, nil
}

// WSLConfig is the .wslconfig written for the service account.
const WSLConfig = "# Managed by OpenDeploy.\n[wsl2]\nkernelCommandLine = cgroup_no_v1=all\n"

func (w *WSL) Ensure(ctx context.Context) error {
	if w.ConfigFile != "" {
		if b, err := os.ReadFile(w.ConfigFile); err != nil || string(b) != WSLConfig {
			if err := os.WriteFile(w.ConfigFile, []byte(WSLConfig), 0o644); err != nil {
				return fmt.Errorf("write %s: %w", w.ConfigFile, err)
			}
			// The setting applies when the WSL VM next boots.
			_, _ = w.run(ctx, "--shutdown")
		}
	}
	if _, err := w.run(ctx, "--status"); err != nil {
		return fmt.Errorf("WSL is not available (enable it with `wsl --install --no-distribution` as an administrator and reboot): %w", err)
	}
	ok, err := w.Installed(ctx)
	if err != nil || ok {
		return err
	}
	if _, err := os.Stat(w.Rootfs); err != nil {
		return fmt.Errorf("guest image: %w", err)
	}
	if err := os.MkdirAll(w.InstallDir, 0o700); err != nil {
		return err
	}
	w.logger().Info("importing the OpenDeploy WSL distribution (first start)", "dir", w.InstallDir)
	_, err = w.run(ctx, "--import", w.Distro, w.InstallDir, w.Rootfs, "--version", "2")
	return err
}

func (w *WSL) logger() *slog.Logger {
	if w.Log == nil {
		return slog.Default()
	}
	return w.Log
}

func (w *WSL) Start(ctx context.Context) (<-chan error, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.keepalive != nil {
		return nil, errors.New("guest already started")
	}
	// Booting the distro runs its systemd, which starts opendeploy.target.
	// The keep-alive holds the instance open; it has no other purpose.
	c := w.command(context.Background(), "--distribution", w.Distro, "--user", "root", "--exec", "/usr/bin/sleep", "infinity")
	var stderr bytes.Buffer
	c.Stderr = &stderr
	if err := c.Start(); err != nil {
		return nil, err
	}
	w.keepalive = c
	done := make(chan error, 1)
	go func() {
		err := c.Wait()
		w.mu.Lock()
		if w.keepalive == c {
			w.keepalive = nil
		}
		w.mu.Unlock()
		if msg := strings.TrimSpace(decodeWSLOutput(stderr.Bytes())); msg != "" {
			err = fmt.Errorf("%v: %s", err, msg)
		}
		done <- fmt.Errorf("WSL instance exited: %w", err)
	}()
	// Wait until the instance reports Running so callers can probe it.
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		if out, err := w.run(ctx, "--list", "--running", "--quiet"); err == nil && containsLine(out, w.Distro) {
			return done, nil
		}
		select {
		case err := <-done:
			return nil, err
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return done, nil
}

func containsLine(out, want string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.EqualFold(strings.TrimSpace(strings.Trim(line, "\r\x00")), want) {
			return true
		}
	}
	return false
}

func (w *WSL) Stop(ctx context.Context, timeout time.Duration) error {
	// Let systemd stop the services cleanly before the instance goes away.
	sctx, cancel := context.WithTimeout(ctx, timeout)
	_, _ = w.run(sctx, "--distribution", w.Distro, "--user", "root", "--exec", "/usr/bin/systemctl", "stop", "opendeploy.target")
	cancel()
	w.mu.Lock()
	c := w.keepalive
	w.keepalive = nil
	w.mu.Unlock()
	if c != nil && c.Process != nil {
		_ = c.Process.Kill()
	}
	_, err := w.run(ctx, "--terminate", w.Distro)
	return err
}

func (w *WSL) BootstrapToken(ctx context.Context) (string, error) {
	out, err := w.command(ctx, "--distribution", w.Distro, "--user", "root", "--exec",
		"/bin/cat", "/var/lib/opendeploy/platformd/bootstrap-token").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", nil // no token file: the owner already exists
		}
		return "", err
	}
	return strings.TrimSpace(decodeWSLOutput(out)), nil
}

// Unregister removes the distro and its virtual disk (all node data).
func (w *WSL) Unregister(ctx context.Context) error {
	ok, err := w.Installed(ctx)
	if err != nil || !ok {
		return err
	}
	_, err = w.run(ctx, "--unregister", w.Distro)
	if err == nil {
		_ = os.Remove(filepath.Join(w.InstallDir, "ext4.vhdx"))
	}
	return err
}
