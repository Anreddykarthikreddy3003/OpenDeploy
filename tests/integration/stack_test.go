package integration

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/allinone"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/build/builder"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/git"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/git/github"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/runtime"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/services"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// ociExec writes a minimal valid OCI image layout (fake BuildKit).
type ociExec struct{ builds atomic.Int32 }

func (e *ociExec) Name() string { return "fake-buildkit" }
func (e *ociExec) Build(_ context.Context, s builder.Spec, log io.Writer) error {
	n := e.builds.Add(1)
	fmt.Fprintf(log, "fake build #%d\n", n)
	dg := func(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
	layer := []byte(fmt.Sprintf("layer-%d", n))
	cfg, _ := json.Marshal(map[string]any{"os": "linux", "architecture": "amd64", "config": map[string]any{"User": "10001", "ExposedPorts": map[string]any{"8080/tcp": map[string]any{}}}})
	m, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": dg(cfg), "size": len(cfg)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": dg(layer), "size": len(layer)}}})
	idx, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": dg(m), "size": len(m)}}})
	f, err := os.Create(s.Dest)
	if err != nil {
		return err
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	write := func(name string, b []byte) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(b)
	}
	write("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`))
	write("index.json", idx)
	for _, b := range [][]byte{layer, cfg, m} {
		write("blobs/sha256/"+strings.TrimPrefix(dg(b), "sha256:"), b)
	}
	return tw.Close()
}

func fixtureFetch(_ context.Context, dir string, src git.Source) (*git.Result, error) {
	_ = os.MkdirAll(dir, 0o755)
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\nEXPOSE 8080\n"), 0o644); err != nil {
		return nil, err
	}
	sha := src.SHA
	if sha == "" {
		sha = strings.Repeat("c", 40)
	}
	return &git.Result{SHA: sha, Message: "fixture"}, nil
}

func nonLoopbackIP(t *testing.T) string {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
			return ipn.IP.String()
		}
	}
	t.Skip("no non-loopback IPv4 address for fake workloads")
	return ""
}

// client is a tiny API client with cookie session + CSRF.
type client struct {
	t    *testing.T
	base string
	hc   *http.Client
	csrf string
}

func newClient(t *testing.T, base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: base, hc: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
}

func (c *client) do(method, path string, body any, out any) int {
	c.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	res, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if out != nil && len(data) > 0 {
		_ = json.Unmarshal(data, out)
	}
	if res.StatusCode >= 400 && out == nil {
		c.t.Logf("%s %s -> %d %s", method, path, res.StatusCode, data)
	}
	return res.StatusCode
}

func (c *client) login(email, pw string) {
	var s struct {
		CSRFToken string `json:"csrf_token"`
	}
	if code := c.do("POST", "/api/v2/auth/login", map[string]string{"email": email, "password": pw}, &s); code != 200 {
		c.t.Fatalf("login %d", code)
	}
	c.csrf = s.CSRFToken
}

func waitStatus(t *testing.T, c *client, depID string, want ...string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		var out struct {
			Deployment map[string]any `json:"deployment"`
		}
		c.do("GET", "/api/v2/deployments/"+depID, nil, &out)
		st, _ := out.Deployment["status"].(string)
		for _, w := range want {
			if st == w {
				return out.Deployment
			}
		}
		if st == "FAILED" && !contains(want, "FAILED") {
			var logs []store.LogLine
			c.do("GET", "/api/v2/deployments/"+depID+"/logs", nil, &logs)
			for _, l := range logs {
				t.Log(l.Line)
			}
			t.Fatalf("deployment failed: %v", out.Deployment["error"])
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("deployment %s did not reach %v", depID, want)
	return nil
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestFullStack(t *testing.T) {
	ip := nonLoopbackIP(t)
	// A real HTTP "workload" listening on a non-loopback address.
	ln, err := net.Listen("tcp", ip+":0")
	if err != nil {
		t.Fatal(err)
	}
	app := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "hello") })}
	go app.Serve(ln)
	defer app.Close()
	fake := runtime.NewFake()
	fake.EndpointFor = func(*runtime.Spec) string { return ln.Addr().String() }
	ex := &ociExec{}
	ctx := context.Background()
	s, err := allinone.Start(ctx, allinone.Options{DataDir: t.TempDir(), Backend: fake, Executor: ex, Fetch: fixtureFetch})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := "http://" + s.APIAddr
	c := newClient(t, base)

	// ---- bootstrap owner (requires the one-time token file)
	tok, _ := os.ReadFile(services.BootstrapTokenPath(s.Node))
	if code := c.do("POST", "/api/v2/auth/bootstrap", map[string]string{"token": "wrong", "email": "o@example.com", "password": "correct horse battery"}, nil); code != 403 {
		t.Fatalf("bootstrap with wrong token: %d", code)
	}
	var sess struct {
		CSRFToken string `json:"csrf_token"`
	}
	if code := c.do("POST", "/api/v2/auth/bootstrap", map[string]string{"token": strings.TrimSpace(string(tok)), "email": "o@example.com", "password": "correct horse battery"}, &sess); code != 201 {
		t.Fatalf("bootstrap %d", code)
	}
	c.csrf = sess.CSRFToken
	if code := c.do("POST", "/api/v2/auth/bootstrap", map[string]string{"token": strings.TrimSpace(string(tok)), "email": "x@example.com", "password": "correct horse battery"}, nil); code == 201 {
		t.Fatal("second bootstrap allowed")
	}

	// ---- CSRF: mutating request without token is rejected
	csrf := c.csrf
	c.csrf = ""
	if code := c.do("POST", "/api/v2/projects", map[string]any{"name": "nocsrf"}, nil); code != 403 {
		t.Fatalf("missing csrf allowed: %d", code)
	}
	c.csrf = csrf

	// ---- import a project (public git URL; fetch is a fixture)
	var created struct {
		Project    store.Project     `json:"project"`
		Deployment *store.Deployment `json:"deployment"`
	}
	if code := c.do("POST", "/api/v2/projects", map[string]any{"name": "web", "clone_url": "https://140.82.112.3/example/web.git",
		"env": map[string]string{"API_KEY": "s3cr3t-value"}}, &created); code != 201 {
		t.Fatalf("create project %d", code)
	}
	if created.Deployment == nil {
		t.Fatal("no initial deployment")
	}
	d1 := waitStatus(t, c, created.Deployment.ID, "SUCCEEDED")
	if d1["generation"].(float64) != 1 {
		t.Fatalf("%v", d1)
	}
	// The workload received the secret as env and file.
	var gotSpec runtime.Spec
	for _, sp := range fake.Specs {
		gotSpec = sp
	}
	if gotSpec.Env["API_KEY"] != "s3cr3t-value" || gotSpec.SecretFiles["API_KEY"] != "s3cr3t-value" || gotSpec.Env["PORT"] != "" {
		t.Fatalf("secret injection: %+v", gotSpec.Env)
	}
	if !gotSpec.ReadOnlyRoot || gotSpec.MemoryBytes == 0 || gotSpec.PIDs == 0 {
		t.Fatalf("hardening defaults missing: %+v", gotSpec)
	}

	// ---- supersession: two rapid deploys, only the newest wins
	var dA, dB store.Deployment
	c.do("POST", "/api/v2/projects/"+created.Project.ID+"/deployments", map[string]any{}, &dA)
	c.do("POST", "/api/v2/projects/"+created.Project.ID+"/deployments", map[string]any{}, &dB)
	waitStatus(t, c, dB.ID, "SUCCEEDED")
	a := waitStatus(t, c, dA.ID, "SUPERSEDED", "SUCCEEDED", "FAILED")
	if a["status"] == "SUCCEEDED" {
		t.Log("first deploy finished before the second was created (acceptable race); checking pointer instead")
	}
	var pv struct {
		Environments []struct {
			ID                  string `json:"id"`
			CurrentDeploymentID string `json:"current_deployment_id"`
			DesiredGeneration   int64  `json:"desired_generation"`
			ObservedGeneration  int64  `json:"observed_generation"`
		} `json:"environments"`
	}
	c.do("GET", "/api/v2/projects/"+created.Project.ID, nil, &pv)
	if pv.Environments[0].CurrentDeploymentID != dB.ID || pv.Environments[0].ObservedGeneration != 3 {
		t.Fatalf("pointer not at newest generation: %+v", pv.Environments[0])
	}

	// ---- rollback to generation 1 (no rebuild)
	builds := ex.builds.Load()
	var rb store.Deployment
	if code := c.do("POST", "/api/v2/deployments/"+created.Deployment.ID+"/rollback", nil, &rb); code != 202 {
		t.Fatalf("rollback %d", code)
	}
	waitStatus(t, c, rb.ID, "SUCCEEDED")
	if ex.builds.Load() != builds {
		t.Fatal("rollback triggered a rebuild")
	}
	if rb.Generation != 4 {
		t.Fatalf("rollback generation %d", rb.Generation)
	}

	// ---- secrets API: list is metadata only; reveal needs recent reauth
	var metas []map[string]any
	c.do("GET", "/api/v2/projects/"+created.Project.ID+"/secrets?environment=production", nil, &metas)
	if len(metas) != 1 || metas[0]["preview"] != nil {
		t.Fatalf("secret list %v", metas)
	}
	// ---- GitHub webhook: signature, dedupe, ordering
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	secret := []byte("whsec")
	ghAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/access_tokens") {
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_test", "expires_at": time.Now().Add(time.Hour)})
			return
		}
		w.WriteHeader(404)
	}))
	defer ghAPI.Close()
	s.P.Platform.GitHub.SetForTest(github.NewApp(1, key, ghAPI.URL), secret)
	conn := &store.GitConnection{Provider: "github", AppID: 1, InstallationID: 77, AccountLogin: "acme", Status: "active"}
	if err := s.P.Store.UpsertGitConnection(ctx, conn); err != nil {
		t.Fatal(err)
	}
	gp := &store.Project{Name: "gh", GitConnectionID: conn.ID, RepoID: 555, RepoFullName: "acme/gh", CloneURL: "https://140.82.112.3/acme/gh.git", AutoDeploy: true}
	if err := s.P.Store.CreateProject(ctx, gp); err != nil {
		t.Fatal(err)
	}
	send := func(delivery, sha string, sign bool) (int, map[string]any) {
		body, _ := json.Marshal(map[string]any{"ref": "refs/heads/main", "after": sha, "repository": map[string]any{"id": 555, "full_name": "acme/gh"},
			"installation": map[string]any{"id": 77}, "head_commit": map[string]any{"id": sha, "message": "m"}})
		req, _ := http.NewRequest("POST", base+"/webhooks/github", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("X-GitHub-Delivery", delivery)
		if sign {
			req.Header.Set("X-Hub-Signature-256", github.Sign(secret, body))
		} else {
			req.Header.Set("X-Hub-Signature-256", github.Sign([]byte("forged"), body))
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}
	if code, _ := send("11111111-1111-1111-1111-111111111111", strings.Repeat("a", 40), false); code != 401 {
		t.Fatalf("forged webhook accepted: %d", code)
	}
	code, r1 := send("22222222-2222-2222-2222-222222222222", strings.Repeat("a", 40), true)
	if code != 202 || len(r1["deployments"].([]any)) != 1 {
		t.Fatalf("push: %d %v", code, r1)
	}
	if code, r := send("22222222-2222-2222-2222-222222222222", strings.Repeat("a", 40), true); code != 202 || !strings.Contains(r["outcome"].(string), "duplicate") {
		t.Fatalf("replay not deduplicated: %v", r)
	}
	_, r2 := send("33333333-3333-3333-3333-333333333333", strings.Repeat("b", 40), true)
	newest := r2["deployments"].([]any)[0].(string)
	waitStatus(t, c, newest, "SUCCEEDED")
	old := r1["deployments"].([]any)[0].(string)
	waitStatus(t, c, old, "SUPERSEDED", "SUCCEEDED")
	genv, _ := s.P.Store.GetEnvironmentByName(ctx, gp.ID, "production")
	if genv.CurrentDeploymentID != newest {
		t.Fatalf("older push overwrote newer generation: current=%s newest=%s", genv.CurrentDeploymentID, newest)
	}

	// ---- RBAC: a viewer cannot deploy and cannot see other projects
	c.do("POST", "/api/v2/users", map[string]string{"email": "v@example.com", "password": "viewer password 1", "role": "viewer"}, nil)
	c.do("PUT", "/api/v2/projects/"+created.Project.ID+"/members", map[string]string{"email": "v@example.com", "role": "viewer"}, nil)
	v := newClient(t, base)
	v.login("v@example.com", "viewer password 1")
	if code := v.do("POST", "/api/v2/projects/"+created.Project.ID+"/deployments", map[string]any{}, nil); code != 403 {
		t.Fatalf("viewer deploy: %d", code)
	}
	if code := v.do("GET", "/api/v2/projects/"+gp.ID, nil, nil); code != 404 {
		t.Fatalf("viewer saw non-member project: %d", code)
	}
	if code := v.do("GET", "/api/v2/projects/"+created.Project.ID+"/secrets", nil, nil); code != 403 {
		t.Fatalf("viewer listed secrets: %d", code)
	}

	// ---- audit chain intact and contains security events
	var ver map[string]any
	c.do("GET", "/api/v2/system/audit/verify", nil, &ver)
	if ver["ok"] != true {
		t.Fatalf("audit chain: %v", ver)
	}
	var evs []map[string]any
	c.do("GET", "/api/v2/system/audit?action=webhook.&limit=50", nil, &evs)
	denied := 0
	for _, e := range evs {
		if e["result"] == "denied" {
			denied++
		}
	}
	if denied == 0 {
		t.Fatal("forged webhook not audited")
	}
}
