package router

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func opts(dir string) Options {
	return Options{AdminSocket: filepath.Join(dir, "admin.sock"), HTTPPort: 18081, HTTPSPort: 18443, VerifyListen: "127.0.0.1:18082", MaxBodyBytes: 1 << 20, StateDir: dir}
}

func TestRouteValidation(t *testing.T) {
	bad := []Route{
		{EnvironmentID: "e", Hosts: []string{"a.example.com"}, Kind: KindProxy, Upstreams: []string{"127.0.0.1:7070"}, TLS: TLSNone},
		{EnvironmentID: "e", Hosts: []string{"a.example.com"}, Kind: KindProxy, Upstreams: []string{"169.254.169.254:80"}, TLS: TLSNone},
		{EnvironmentID: "e", Hosts: []string{"Bad Host"}, Kind: KindProxy, Upstreams: []string{"10.0.0.2:80"}, TLS: TLSNone},
		{EnvironmentID: "e", Hosts: []string{"a.example.com"}, Kind: KindRedirect, RedirectTo: "javascript:x", TLS: TLSNone},
		{EnvironmentID: "e", Hosts: []string{"a.example.com"}, Kind: "exec", TLS: TLSNone},
	}
	for i, r := range bad {
		if r.Validate() == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestRenderRejectsHostConflict(t *testing.T) {
	tbl := Table{Routes: []Route{
		{EnvironmentID: "e1", DeploymentID: "d1", Hosts: []string{"a.example.com"}, Kind: KindProxy, Upstreams: []string{"10.0.0.2:80"}, TLS: TLSNone},
		{EnvironmentID: "e2", DeploymentID: "d2", Hosts: []string{"a.example.com"}, Kind: KindProxy, Upstreams: []string{"10.0.0.3:80"}, TLS: TLSNone},
	}}
	if _, err := Render(tbl, opts(t.TempDir())); err == nil {
		t.Fatal("host conflict accepted")
	}
}

func TestRenderAdminStaysOnSocket(t *testing.T) {
	o := opts(t.TempDir())
	cfg, err := Render(Table{Routes: []Route{{EnvironmentID: "e1", DeploymentID: "d1", Hosts: []string{"a.example.com"}, Kind: KindProxy, Upstreams: []string{"10.0.0.2:80"}, TLS: TLSACME}}}, o)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(cfg, &m)
	admin := m["admin"].(map[string]any)
	if !strings.HasPrefix(admin["listen"].(string), "unix/") {
		t.Fatal("admin must listen on unix socket")
	}
	if !strings.Contains(string(cfg), `"subjects":["a.example.com"]`) {
		t.Fatal("acme policy missing")
	}
	if strings.Contains(string(cfg), "X-Opendeploy-Deployment") && !strings.Contains(string(cfg), `"verify"`) {
		t.Fatal("deployment header must only be on verify server")
	}
}

func nonLoopbackIP(t *testing.T) string {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
			return ipn.IP.String()
		}
	}
	t.Skip("no non-loopback address for upstream")
	return ""
}

// TestCaddyIntegration drives a real Caddy binary when available.
func TestCaddyIntegration(t *testing.T) {
	bin, err := exec.LookPath("caddy")
	if err != nil {
		t.Skip("caddy not installed")
	}
	dir := t.TempDir()
	o := opts(dir)
	boot := filepath.Join(dir, "boot.json")
	_ = os.WriteFile(boot, BootstrapConfig(o.AdminSocket), 0o600)
	cmd := exec.Command(bin, "run", "--config", boot)
	cmd.Env = append(os.Environ(), "HOME="+dir, "XDG_DATA_HOME="+dir, "XDG_CONFIG_HOME="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(o.AdminSocket); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	ip := nonLoopbackIP(t)
	mkUpstream := func(body string) string {
		ln, err := net.Listen("tcp", ip+":0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
		return ln.Addr().String()
	}
	v1, v2 := mkUpstream("v1"), mkUpstream("v2")
	static := filepath.Join(dir, "static")
	_ = os.MkdirAll(static, 0o755)
	_ = os.WriteFile(filepath.Join(static, "index.html"), []byte("<h1>static</h1>"), 0o644)
	_ = os.WriteFile(filepath.Join(static, ".secret"), []byte("hidden"), 0o644)

	m := NewManager(NewCaddy(o.AdminSocket), o)
	ctx := context.Background()
	tbl := Table{Routes: []Route{
		{EnvironmentID: "env_a", DeploymentID: "dep_1", Hosts: []string{"app.test"}, Kind: KindProxy, Upstreams: []string{v1}, TLS: TLSNone},
		{EnvironmentID: "env_s", DeploymentID: "dep_s", Hosts: []string{"site.test"}, Kind: KindStatic, StaticDir: static, TLS: TLSNone},
	}}
	if _, err := m.Apply(ctx, tbl, []string{"env_a", "env_s"}); err != nil {
		t.Fatal(err)
	}
	get := func(host, path string) (int, string, http.Header) {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d%s", o.HTTPPort, path), nil)
		req.Host = host
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b), res.Header
	}
	if code, body, h := get("app.test", "/"); code != 200 || body != "v1" || h.Get("X-Opendeploy-Deployment") != "" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%d %q %v", code, body, h)
	}
	if code, body, _ := get("site.test", "/"); code != 200 || !strings.Contains(body, "static") {
		t.Fatalf("static: %d %q", code, body)
	}
	if code, _, _ := get("site.test", "/.secret"); code == 200 {
		t.Fatal("dotfile served")
	}
	if code, _, _ := get("unknown.test", "/"); code != 404 {
		t.Fatalf("unknown host %d", code)
	}
	// Promote v2.
	tbl.Routes[0].DeploymentID, tbl.Routes[0].Upstreams = "dep_2", []string{v2}
	if _, err := m.Apply(ctx, tbl, []string{"env_a"}); err != nil {
		t.Fatal(err)
	}
	if _, body, _ := get("app.test", "/"); body != "v2" {
		t.Fatalf("after promote %q", body)
	}
	// A candidate whose upstream is down fails verification and the
	// previous (v2) configuration is restored.
	dead := ip + ":1"
	bad := tbl
	bad.Routes = append([]Route(nil), tbl.Routes...)
	bad.Routes[0].DeploymentID, bad.Routes[0].Upstreams = "dep_3", []string{dead}
	vctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := m.Apply(vctx, bad, []string{"env_a"}); err == nil {
		t.Fatal("dead candidate verified")
	}
	if _, body, _ := get("app.test", "/"); body != "v2" {
		t.Fatalf("last-known-good not restored: %q", body)
	}
	// Caddy restarting on its own comes back with only the bootstrap config;
	// the watchdog notices and reloads last-known-good.
	if reloaded, err := m.EnsureLoaded(ctx); err != nil || reloaded {
		t.Fatalf("healthy edge reloaded: %v %v", reloaded, err)
	}
	if err := NewCaddy(o.AdminSocket).Load(ctx, BootstrapConfig(o.AdminSocket)); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", o.HTTPPort), nil)
	req.Host = "app.test"
	if res, err := http.DefaultClient.Do(req); err == nil {
		res.Body.Close()
		t.Fatal("precondition: edge still serving after the simulated Caddy restart")
	}
	if reloaded, err := m.EnsureLoaded(ctx); err != nil || !reloaded {
		t.Fatalf("watchdog did not reload: %v %v", reloaded, err)
	}
	if _, body, _ := get("app.test", "/"); body != "v2" {
		t.Fatalf("routes not restored after Caddy restart: %q", body)
	}
	// Last-known-good persisted for reboot recovery.
	m2 := NewManager(NewCaddy(o.AdminSocket), o)
	if cur, _ := m2.Current(); len(cur.Routes) != 2 || cur.Routes[0].DeploymentID != "dep_2" {
		t.Fatalf("persisted table %+v", cur)
	}
	// Node reboot: a fresh routemgr restores last-known-good onto a Caddy
	// that only has its bootstrap config. Static directories are never
	// persisted; they are re-resolved from the artifact digest.
	if err := NewCaddy(o.AdminSocket).Load(ctx, BootstrapConfig(o.AdminSocket)); err != nil {
		t.Fatal(err)
	}
	if err := m2.Restore(ctx); err == nil {
		t.Fatal("restored static route without a resolver")
	}
	var resolved []string
	m2.Resolve = func(_ context.Context, digest string) (string, error) {
		resolved = append(resolved, digest)
		return static, nil
	}
	if err := m2.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if code, body, _ := get("site.test", "/"); code != 200 || !strings.Contains(body, "static") {
		t.Fatalf("static site after reboot restore: %d %q", code, body)
	}
	if _, body, _ := get("app.test", "/"); body != "v2" {
		t.Fatalf("proxy route after reboot restore: %q", body)
	}
	if len(resolved) != 1 {
		t.Fatalf("resolver calls: %v", resolved)
	}
}
