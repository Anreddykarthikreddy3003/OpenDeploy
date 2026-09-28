package hostd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/hostops"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/update"
)

func TestRegistersExactlyTheClosedOpSet(t *testing.T) {
	srv := ipc.NewServer(identity.Host, nil, nil)
	Register(srv, New(&config.Node{DataDir: t.TempDir()}, "2.0.0", nil, nil))
	got := srv.Ops()
	want := append([]string{}, hostops.AllOps...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("hostd ops %v, want exactly %v", got, want)
	}
}

func TestFirewallRules(t *testing.T) {
	n := &config.Node{}
	n.API.Listen = "127.0.0.1:8080"
	n.Artifact.RegistryListen = "127.0.0.1:5010"
	h := &Host{Node: n}
	rules := h.firewallRules(hostops.FirewallReq{HTTPPort: 80, HTTPSPort: 443, LANOnly: true})
	for _, want := range []string{"table inet opendeploy_host", "tcp dport { 8080, 5010, 18080 } drop", `iifname "lo" accept`, "LAN-only edge", "policy accept"} {
		if !strings.Contains(rules, want) {
			t.Fatalf("missing %q in\n%s", want, rules)
		}
	}
	// Remote admin enabled on the API port: that port stays reachable.
	if r := h.firewallRules(hostops.FirewallReq{HTTPPort: 80, HTTPSPort: 443, AdminPort: 8080}); strings.Contains(r, "8080,") {
		t.Fatalf("admin port blocked:\n%s", r)
	}
	// The ruleset must parse (checked when nft is available and we are root).
	if _, err := exec.LookPath("nft"); err == nil && os.Geteuid() == 0 {
		cmd := exec.Command("nft", "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(rules)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft rejects the ruleset: %v %s", err, out)
		}
	}
}

func TestRedact(t *testing.T) {
	in := `password: hunter2
token=odt_abcdefghijklmnopqrstuvwxyz0123 api_key: "k-123"
url: postgres://app:s3cr3t@db:5432/x key AKIAABCDEFGHIJKLMNOP
-----BEGIN EC PRIVATE KEY-----
MHcCAQEE
-----END EC PRIVATE KEY-----
ghp_abcdefghijklmnopqrstuvwxyz0123456789`
	out := string(Redact([]byte(in)))
	for _, leak := range []string{"hunter2", "odt_abcdef", "k-123", "s3cr3t", "AKIAABCDEFGHIJKLMNOP", "MHcCAQEE", "ghp_abcdef"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leaked %q:\n%s", leak, out)
		}
	}
}

func tarball(files map[string]string) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for n, b := range files {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o755, Size: int64(len(b)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(b))
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

func TestStageCommitAndRollback(t *testing.T) {
	keys := map[string][]ed25519.PrivateKey{}
	for _, r := range []string{"root", "targets", "snapshot", "timestamp"} {
		_, k, _ := ed25519.GenerateKey(nil)
		keys[r] = []ed25519.PrivateKey{k}
	}
	repo := t.TempDir()
	pub, err := update.InitRepository(repo, keys, 1)
	if err != nil {
		t.Fatal(err)
	}
	plat := runtime.GOOS + "-" + runtime.GOARCH
	_ = pub.PublishRelease(update.Release{Version: "2.2.0", Channel: "stable", SchemaVersion: 1},
		map[string][]byte{plat: tarball(map[string]string{"bin/platformd": "new", "bin/opendeployctl": "ctl"})})
	srv := httptest.NewServer(http.FileServer(http.Dir(repo)))
	defer srv.Close()
	root := filepath.Join(t.TempDir(), "root.json")
	b, _ := os.ReadFile(filepath.Join(repo, "metadata", "1.root.json"))
	_ = os.WriteFile(root, b, 0o644)

	n := &config.Node{DataDir: t.TempDir()}
	n.Update.RepositoryURL, n.Update.TrustedRoot, n.Update.SlotsDir = srv.URL, root, filepath.Join(t.TempDir(), "slots")
	h := New(n, "2.1.0", nil, nil)
	_ = os.MkdirAll(filepath.Join(n.Update.SlotsDir, "a", "bin"), 0o755)
	_ = h.Slots.Activate("a")
	if err := h.Init(); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var restarted []string
	h.Systemctl = func(_ context.Context, verb, unit string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		restarted = append(restarted, verb+" "+unit)
		return "", nil
	}
	var healthy atomic.Bool
	healthy.Store(true)
	h.Healthy = func(context.Context) error {
		if healthy.Load() {
			return nil
		}
		return errors.New("down")
	}
	h.Readiness = time.Second
	ctx := context.Background()
	// Only the verified channel release can be staged.
	if err := h.Stage(ctx, "stable", "9.9.9"); err == nil {
		t.Fatal("staged a version the channel does not offer")
	}
	if err := h.Stage(ctx, "stable", "2.2.0"); err != nil {
		t.Fatal(err)
	}
	if err := h.CommitAsync("2.3.0"); err == nil {
		t.Fatal("committed an unstaged version")
	}
	if err := h.CommitAsync("2.2.0"); err != nil {
		t.Fatal(err)
	}
	waitOp := func(want string) {
		deadline := time.Now().Add(10 * time.Second)
		for h.State().Operation != want {
			if time.Now().After(deadline) {
				t.Fatalf("operation %q, want %q (%s)", h.State().Operation, want, h.State().Message)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitOp("applied")
	if st := h.State(); st.ActiveSlot != "b" || st.Versions["b"] != "2.2.0" {
		t.Fatalf("state %+v", st)
	}
	mu.Lock()
	if len(restarted) == 0 || restarted[len(restarted)-1] != "restart opendeploy-platformd.service" {
		t.Fatalf("restart order %v", restarted)
	}
	mu.Unlock()
	// Manual rollback returns to slot a.
	if err := h.Rollback(ctx); err != nil || h.State().ActiveSlot != "a" {
		t.Fatalf("rollback %v %+v", err, h.State())
	}
	// A release that fails readiness is rolled back automatically.
	h.Version = "2.1.0"
	if err := h.Stage(ctx, "stable", "2.2.0"); err != nil {
		t.Fatal(err)
	}
	healthy.Store(false)
	_ = h.CommitAsync("2.2.0")
	deadline := time.Now().Add(15 * time.Second)
	for h.State().Operation == "applying" && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if st := h.State(); st.Operation != "rolled_back" || st.ActiveSlot != "a" {
		t.Fatalf("unhealthy release kept: %+v", st)
	}
}
