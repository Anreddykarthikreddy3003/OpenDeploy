package desktop

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeGuest struct {
	mu       sync.Mutex
	starts   int
	stops    int
	ensured  int
	exit     chan error
	token    string
	failBoot bool
}

func (g *fakeGuest) Kind() string { return "fake" }
func (g *fakeGuest) Ensure(context.Context) error {
	g.mu.Lock()
	g.ensured++
	g.mu.Unlock()
	return nil
}
func (g *fakeGuest) Start(context.Context) (<-chan error, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.starts++
	g.exit = make(chan error, 1)
	return g.exit, nil
}
func (g *fakeGuest) Stop(context.Context, time.Duration) error {
	g.mu.Lock()
	g.stops++
	g.mu.Unlock()
	return nil
}
func (g *fakeGuest) BootstrapToken(context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.token, nil
}
func (g *fakeGuest) crash() {
	g.mu.Lock()
	g.exit <- errors.New("kernel panic")
	g.mu.Unlock()
}
func (g *fakeGuest) count() (int, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.starts, g.stops
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSupervisorRestartsCrashedGuestAndStopsOnShutdown(t *testing.T) {
	dir := t.TempDir()
	g := &fakeGuest{token: "tok-123"}
	var healthy atomic.Bool
	s := &Supervisor{Guest: g, Config: Config{DataDir: dir}, MaxBackoff: 50 * time.Millisecond,
		Healthy: func(context.Context) error {
			if healthy.Load() {
				return nil
			}
			return errors.New("booting")
		}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- s.Run(ctx) }()

	waitFor(t, "first start", func() bool { st, _ := g.count(); return st == 1 })
	healthy.Store(true)
	waitFor(t, "running", func() bool { return s.Status().State == "running" })
	st, err := ReadStatus(dir)
	if err != nil || st.State != "running" || st.Guest != "fake" {
		t.Fatalf("status file: %+v %v", st, err)
	}
	waitFor(t, "token published", func() bool {
		b, _ := os.ReadFile(TokenPath(dir))
		return strings.TrimSpace(string(b)) == "tok-123"
	})

	g.crash()
	waitFor(t, "restart", func() bool { st, _ := g.count(); return st == 2 })
	if s.Status().Restart != 1 {
		t.Fatalf("restarts = %d", s.Status().Restart)
	}
	waitFor(t, "running again", func() bool { return s.Status().State == "running" })

	// Owner created: the published token disappears.
	g.mu.Lock()
	g.token = ""
	g.mu.Unlock()
	g.crash()
	waitFor(t, "token removed", func() bool { _, err := os.Stat(TokenPath(dir)); return os.IsNotExist(err) })

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("supervisor did not stop")
	}
	if _, stops := g.count(); stops == 0 {
		t.Fatal("guest not stopped on shutdown")
	}
	if st, _ := ReadStatus(dir); st.State != "stopped" {
		t.Fatalf("final state %q", st.State)
	}
}

func TestSupervisorRestartsGuestThatNeverBecomesReady(t *testing.T) {
	g := &fakeGuest{}
	s := &Supervisor{Guest: g, Config: Config{DataDir: t.TempDir()}, ReadyTimeout: 100 * time.Millisecond, MaxBackoff: 10 * time.Millisecond,
		Healthy: func(context.Context) error { return errors.New("never") }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()
	waitFor(t, "second boot", func() bool { st, _ := g.count(); return st >= 2 })
	if _, stops := g.count(); stops == 0 {
		t.Fatal("unready guest was not stopped before restarting")
	}
}

func TestForwardSplicesBothWays(t *testing.T) {
	backend, _ := net.Listen("tcp", "127.0.0.1:0")
	defer backend.Close()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func() {
				b, _ := io.ReadAll(c) // until the client half-closes
				_, _ = c.Write(bytes.ToUpper(b))
				c.Close()
			}()
		}
	}()
	front, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	fdone := make(chan struct{})
	go func() {
		_ = Forward(ctx, front, func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", backend.Addr().String())
		}, nil)
		close(fdone)
	}()
	for i := 0; i < 5; i++ {
		c, err := net.Dial("tcp", front.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("hello guest"))
		_ = c.(*net.TCPConn).CloseWrite()
		b, _ := io.ReadAll(c)
		c.Close()
		if string(b) != "HELLO GUEST" {
			t.Fatalf("got %q", b)
		}
	}
	cancel()
	select {
	case <-fdone:
	case <-time.After(5 * time.Second):
		t.Fatal("forwarder did not stop")
	}
}

func TestExpandImageIsSparseAndGrown(t *testing.T) {
	dir := t.TempDir()
	raw := make([]byte, 4<<20)
	copy(raw, "superblock")
	copy(raw[3<<20:], "inode table")
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(raw)
	zw.Close()
	src := filepath.Join(dir, "disk.img.gz")
	_ = os.WriteFile(src, gz.Bytes(), 0o644)
	dst := filepath.Join(dir, "disk.img")
	if err := ExpandImage(src, dst, 64<<20); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(dst)
	if fi.Size() != 64<<20 {
		t.Fatalf("size %d", fi.Size())
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got[:len(raw)], raw) || !bytes.Equal(got[len(raw):], make([]byte, len(got)-len(raw))) {
		t.Fatal("content mismatch")
	}
	if err := ExpandImage(filepath.Join(dir, "missing.gz"), filepath.Join(dir, "x"), 1); err == nil {
		t.Fatal("missing image accepted")
	}
	if _, err := os.Stat(dst + ".partial"); !os.IsNotExist(err) {
		t.Fatal("partial file left behind")
	}
}

func TestDecodeWSLOutput(t *testing.T) {
	utf16le := []byte{0xff, 0xfe, 'O', 0, 'p', 0, 'e', 0, 'n', 0, '\r', 0, '\n', 0}
	if got := decodeWSLOutput(utf16le); got != "Open\r\n" {
		t.Fatalf("%q", got)
	}
	if got := decodeWSLOutput([]byte("Ubuntu\nOpenDeploy\n")); !containsLine(got, "opendeploy") {
		t.Fatalf("%q", got)
	}
}

// fakeWSL is a shell stand-in for wsl.exe that records calls and keeps a
// registry of imported distros in a directory.
const fakeWSL = `#!/bin/sh
echo "$*" >> "$FAKE_WSL_DIR/calls"
case "$1" in
--status) exit 0 ;;
--list)
	if [ "$2" = "--running" ]; then [ -f "$FAKE_WSL_DIR/running" ] && cat "$FAKE_WSL_DIR/running"; exit 0; fi
	[ -f "$FAKE_WSL_DIR/distros" ] && cat "$FAKE_WSL_DIR/distros"; exit 0 ;;
--import) echo "$2" >> "$FAKE_WSL_DIR/distros"; test -f "$4" ;;
--terminate) rm -f "$FAKE_WSL_DIR/running" ;;
--unregister) : > "$FAKE_WSL_DIR/distros" ;;
--distribution)
	shift 5
	case "$1" in
	/usr/bin/sleep) echo "$(cat "$FAKE_WSL_DIR/distros")" > "$FAKE_WSL_DIR/running"; exec sleep 30 ;;
	/bin/cat) [ -f "$FAKE_WSL_DIR/token" ] || exit 1; cat "$FAKE_WSL_DIR/token" ;;
	*) exit 0 ;;
	esac ;;
esac
`

func TestWSLGuestLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell stand-in for wsl.exe")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "wsl.exe")
	_ = os.WriteFile(exe, []byte(fakeWSL), 0o755)
	t.Setenv("FAKE_WSL_DIR", dir)
	rootfs := filepath.Join(dir, "opendeploy.wsl")
	_ = os.WriteFile(rootfs, []byte("tar"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "distros"), []byte("Ubuntu\n"), 0o644)
	w := &WSL{Exe: exe, Distro: "OpenDeploy", InstallDir: filepath.Join(dir, "wsl"), Rootfs: rootfs, ConfigFile: filepath.Join(dir, ".wslconfig")}
	ctx := context.Background()

	for i := 0; i < 2; i++ { // idempotent: imports once
		if err := w.Ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
	if n := strings.Count(string(calls), "--import OpenDeploy"); n != 1 {
		t.Fatalf("imported %d times:\n%s", n, calls)
	}
	if !strings.Contains(string(calls), "--version 2") {
		t.Fatal("distro not imported as WSL2")
	}
	if b, _ := os.ReadFile(w.ConfigFile); string(b) != WSLConfig || strings.Count(string(calls), "--shutdown") != 1 {
		t.Fatalf(".wslconfig %q, calls:\n%s", b, calls)
	}
	done, err := w.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := w.BootstrapToken(ctx); err != nil || tok != "" {
		t.Fatalf("token before bootstrap file: %q %v", tok, err)
	}
	_ = os.WriteFile(filepath.Join(dir, "token"), []byte("abc\n"), 0o600)
	if tok, _ := w.BootstrapToken(ctx); tok != "abc" {
		t.Fatalf("token %q", tok)
	}
	if err := w.Stop(ctx, time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "exited") {
			t.Fatalf("exit reason %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("keep-alive not stopped")
	}
	calls, _ = os.ReadFile(filepath.Join(dir, "calls"))
	for _, want := range []string{"systemctl stop opendeploy.target", "--terminate OpenDeploy", "--user root --exec /usr/bin/sleep infinity"} {
		if !strings.Contains(string(calls), want) {
			t.Fatalf("missing call %q:\n%s", want, calls)
		}
	}
}
