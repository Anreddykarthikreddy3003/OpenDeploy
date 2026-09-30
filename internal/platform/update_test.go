package platform

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
	"path/filepath"
	"runtime"
	"testing"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/daemon"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/update"
)

func TestUpdateCheckFlow(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	keys := map[string][]ed25519.PrivateKey{}
	for _, r := range []string{"root", "targets", "snapshot", "timestamp"} {
		_, k, _ := ed25519.GenerateKey(nil)
		keys[r] = []ed25519.PrivateKey{k}
	}
	dir := t.TempDir()
	pub, err := update.InitRepository(dir, keys, 1)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	_ = tw.WriteHeader(&tar.Header{Name: "bin/platformd", Mode: 0o755, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	_ = zw.Close()
	plat := runtime.GOOS + "-" + runtime.GOARCH
	if err := pub.PublishRelease(update.Release{Version: "2.5.0", Channel: "stable", Notes: "Faster builds"}, map[string][]byte{plat: buf.Bytes()}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()
	rootPath := filepath.Join(t.TempDir(), "root.json")
	b, _ := os.ReadFile(filepath.Join(dir, "metadata", "1.root.json"))
	_ = os.WriteFile(rootPath, b, 0o644)
	h.p.Node.Update.RepositoryURL, h.p.Node.Update.TrustedRoot, h.p.Node.Update.Channel = srv.URL, rootPath, "stable"

	old := daemon.Version
	daemon.Version = "2.4.1"
	defer func() { daemon.Version = old }()
	st := h.p.CheckUpdates(ctx)
	if st.Error != "" || st.Available == nil || st.Available.Version != "2.5.0" || st.Blocked != "" {
		t.Fatalf("status %+v", st)
	}
	if got := h.p.UpdateStatus(ctx); got.Available == nil || got.Available.Version != "2.5.0" {
		t.Fatalf("recorded status %+v", got)
	}
	// Without hostd the apply is refused cleanly.
	if err := h.p.ApplyUpdate(ctx, "2.5.0"); !errors.Is(err, ErrNoHostAgent) {
		t.Fatalf("apply without hostd: %v", err)
	}
	// Publisher halts the release; the node refuses it.
	r, _ := pub.ReadChannel("stable")
	r.Halted = true
	_ = pub.SetChannel(*r)
	if st := h.p.CheckUpdates(ctx); st.Blocked == "" {
		t.Fatalf("halted release offered for install: %+v", st)
	}
	// Revocation of the running version is surfaced.
	r.Halted, r.Revoked = false, []string{"2.4.1"}
	_ = pub.SetChannel(*r)
	if st := h.p.CheckUpdates(ctx); !st.CurrentRevoked || st.Blocked != "" {
		t.Fatalf("revocation not surfaced: %+v", st)
	}
	// Corrupted repository: verification error, nothing offered.
	_ = os.WriteFile(filepath.Join(dir, "targets", "channels", "stable.json"), []byte(`{"version":"9.9.9"}`), 0o644)
	if st := h.p.CheckUpdates(ctx); st.Error == "" || st.Available != nil {
		t.Fatalf("tampered repository accepted: %+v", st)
	}
}
