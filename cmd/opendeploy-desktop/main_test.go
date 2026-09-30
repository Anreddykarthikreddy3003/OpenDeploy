package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/desktop"
)

// Regression test for F-7: status printed the host copy of the bootstrap
// token after the owner account existed.
func TestStatusHidesSpentBootstrapToken(t *testing.T) {
	var needs atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/setup" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"needs_bootstrap":%v,"version":"dev","require_mfa":false}`, needs.Load())
	}))
	defer srv.Close()
	cfg := desktop.Config{DataDir: t.TempDir(), APIPort: srv.Listener.Addr().(*net.TCPAddr).Port}
	ctx := context.Background()

	if got := bootstrapNotice(ctx, cfg); got != "" {
		t.Fatalf("no host token, notice %q", got)
	}
	if err := os.WriteFile(desktop.TokenPath(cfg.DataDir), []byte("tok-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	needs.Store(true)
	if got := bootstrapNotice(ctx, cfg); !strings.Contains(got, "tok-123") {
		t.Fatalf("owner still to be created, notice %q", got)
	}
	needs.Store(false)
	if got := bootstrapNotice(ctx, cfg); got != "" {
		t.Fatalf("owner exists, notice %q", got)
	}
	// The API cannot be asked: show the token as before.
	srv.Close()
	if got := bootstrapNotice(ctx, cfg); !strings.Contains(got, "tok-123") {
		t.Fatalf("API unreachable, notice %q", got)
	}
}
