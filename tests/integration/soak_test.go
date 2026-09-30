//go:build soak

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/allinone"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/git/github"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/runtime"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/services"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil && v > 0 {
		return v
	}
	return def
}

type footprint struct {
	goroutines, fds int
	heap            uint64
	dbBytes         int64
}

func measure(t *testing.T, dbPath string) footprint {
	t.Helper()
	// Let finished request and job goroutines exit before counting.
	time.Sleep(2 * time.Second)
	goruntime.GC()
	var ms goruntime.MemStats
	goruntime.ReadMemStats(&ms)
	fds, _ := os.ReadDir("/proc/self/fd")
	var db int64
	for _, suffix := range []string{"", "-wal"} {
		if fi, err := os.Stat(dbPath + suffix); err == nil {
			db += fi.Size()
		}
	}
	return footprint{goroutines: goruntime.NumGoroutine(), fds: len(fds), heap: ms.HeapAlloc, dbBytes: db}
}

// TestSoak drives the whole control plane (real IPC services, job queue,
// promotion journal, router) with the fake runtime and builder for many
// deploy rounds: sequential and concurrent deploys across projects plus a
// storm of duplicated and reordered webhooks. Leaks show up as growth that
// scales with the number of rounds; the node must end converged, with one
// live workload per environment and an empty queue.
//
//	go test -tags soak -run TestSoak ./tests/integration/            # smoke
//	SOAK_ROUNDS=40 SOAK_PROJECTS=20 go test -tags soak -timeout 2h ... # nightly
func TestSoak(t *testing.T) {
	rounds := envInt("SOAK_ROUNDS", 6)
	projects := envInt("SOAK_PROJECTS", 8)
	pushes := envInt("SOAK_PUSHES", 60)

	ip := nonLoopbackIP(t)
	ln, err := net.Listen("tcp", ip+":0")
	if err != nil {
		t.Fatal(err)
	}
	app := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })}
	go app.Serve(ln)
	defer app.Close()
	fake := runtime.NewFake()
	fake.EndpointFor = func(*runtime.Spec) string { return ln.Addr().String() }
	ctx := context.Background()
	s, err := allinone.Start(ctx, allinone.Options{DataDir: t.TempDir(), Backend: fake, Executor: &ociExec{}, Fetch: fixtureFetch})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dbPath := s.Node.ServiceDir("platformd") + "/platform.db"
	base := "http://" + s.APIAddr
	c := newClient(t, base)
	tok, _ := os.ReadFile(services.BootstrapTokenPath(s.Node))
	var sess struct {
		CSRFToken string `json:"csrf_token"`
	}
	if code := c.do("POST", "/api/v2/auth/bootstrap", map[string]string{"token": strings.TrimSpace(string(tok)), "email": "o@example.com", "password": "correct horse battery"}, &sess); code != 201 {
		t.Fatalf("bootstrap %d", code)
	}
	c.csrf = sess.CSRFToken

	ids := make([]string, projects)
	var first []string
	for i := range ids {
		var created struct {
			Project    store.Project     `json:"project"`
			Deployment *store.Deployment `json:"deployment"`
		}
		if code := c.do("POST", "/api/v2/projects", map[string]any{"name": fmt.Sprintf("soak-%d", i), "clone_url": "https://140.82.112.3/example/web.git"}, &created); code != 201 {
			t.Fatalf("create project %d", code)
		}
		ids[i] = created.Project.ID
		first = append(first, created.Deployment.ID)
	}
	for _, d := range first {
		waitStatus(t, c, d, "SUCCEEDED")
	}

	var triggered atomic.Int64
	// trigger starts a deploy without failing the test from a goroutine;
	// it returns "" (and records an error) if the API refused.
	trigger := func(projectID string) string {
		req, _ := http.NewRequest("POST", base+"/api/v2/projects/"+projectID+"/deployments", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", c.csrf)
		res, err := c.hc.Do(req)
		if err != nil {
			t.Errorf("deploy %s: %v", projectID, err)
			return ""
		}
		defer res.Body.Close()
		var d store.Deployment
		_ = json.NewDecoder(res.Body).Decode(&d)
		if (res.StatusCode != 201 && res.StatusCode != 202) || d.ID == "" {
			t.Errorf("deploy %s: %d", projectID, res.StatusCode)
			return ""
		}
		triggered.Add(1)
		return d.ID
	}
	wait := func(deps []string) {
		for _, d := range deps {
			if d != "" {
				waitStatus(t, c, d, "SUCCEEDED", "SUPERSEDED")
			}
		}
	}
	// deployAll triggers one deploy per project concurrently and waits for
	// all of them.
	deployAll := func() {
		var wg sync.WaitGroup
		deps := make([]string, len(ids))
		for i, id := range ids {
			wg.Add(1)
			go func() {
				defer wg.Done()
				deps[i] = trigger(id)
			}()
		}
		wg.Wait()
		wait(deps)
	}
	deployAll() // warm up caches, pools and prepared statements
	warm := measure(t, dbPath)
	triggered.Store(0)
	for r := 0; r < rounds; r++ {
		deployAll()
		// And a quick burst on one project: supersession under load.
		var burst []string
		for i := 0; i < 4; i++ {
			burst = append(burst, trigger(ids[0]))
		}
		wait(burst)
	}

	// Webhook storm: duplicated and reordered pushes to one repository.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	secret := []byte("whsec")
	ghAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/access_tokens") {
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_test", "expires_at": time.Now().Add(time.Hour)})
			return
		}
		w.WriteHeader(201)
	}))
	defer ghAPI.Close()
	s.P.Platform.GitHub.SetForTest(github.NewApp(1, key, ghAPI.URL), secret)
	conn := &store.GitConnection{Provider: "github", AppID: 1, InstallationID: 77, AccountLogin: "acme", Status: "active"}
	if err := s.P.Store.UpsertGitConnection(ctx, conn); err != nil {
		t.Fatal(err)
	}
	gp := &store.Project{Name: "gh-soak", GitConnectionID: conn.ID, RepoID: 555, RepoFullName: "acme/gh", CloneURL: "https://140.82.112.3/acme/gh.git", AutoDeploy: true}
	if err := s.P.Store.CreateProject(ctx, gp); err != nil {
		t.Fatal(err)
	}
	send := func(i int) {
		sha := fmt.Sprintf("%040x", i)
		body, _ := json.Marshal(map[string]any{"ref": "refs/heads/main", "after": sha, "repository": map[string]any{"id": 555, "full_name": "acme/gh"},
			"installation": map[string]any{"id": 77}, "head_commit": map[string]any{"id": sha, "message": "m"}})
		req, _ := http.NewRequest("POST", base+"/webhooks/github", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("X-GitHub-Delivery", fmt.Sprintf("00000000-0000-0000-0000-%012d", i))
		req.Header.Set("X-Hub-Signature-256", github.Sign(secret, body))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Error(err)
			return
		}
		res.Body.Close()
		if res.StatusCode != 202 {
			t.Errorf("webhook %d: %d", i, res.StatusCode)
		}
	}
	var wg sync.WaitGroup
	for i := 1; i <= pushes; i++ {
		for dup := 0; dup < 2; dup++ { // every delivery arrives twice
			wg.Add(1)
			go func() { defer wg.Done(); send(i) }()
		}
	}
	wg.Wait()
	// The last push accepted defines the desired generation; wait until the
	// environment observes it and nothing is left in the queue.
	deadline := time.Now().Add(5 * time.Minute)
	for {
		env, _ := s.P.Store.GetEnvironmentByName(ctx, gp.ID, "production")
		jobs := pendingDeployJobs(ctx, s.P.Store)
		if env != nil && env.DesiredGeneration > 0 && env.ObservedGeneration == env.DesiredGeneration && jobs == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("did not converge: env=%+v pending deploy jobs=%d", env, jobs)
		}
		time.Sleep(500 * time.Millisecond)
	}
	deps, _ := s.P.Store.ListDeployments(ctx, gp.ID, "", 2*pushes+10)
	var succeeded int
	for _, d := range deps {
		if d.Status == "SUCCEEDED" {
			succeeded++
		}
	}
	if len(deps) > pushes || succeeded == 0 {
		t.Fatalf("webhook storm: %d deployments for %d distinct pushes (%d succeeded); duplicates were not deduplicated", len(deps), pushes, succeeded)
	}

	end := measure(t, dbPath)
	t.Logf("footprint after warm-up: %+v", warm)
	t.Logf("footprint after %d rounds x %d projects + %d webhooks: %+v", rounds, projects, pushes*2, end)
	if g := end.goroutines - warm.goroutines; g > 40 {
		t.Errorf("goroutines grew by %d", g)
	}
	if f := end.fds - warm.fds; f > 20 {
		t.Errorf("open file descriptors grew by %d", f)
	}
	if h := int64(end.heap) - int64(warm.heap); h > 64<<20 {
		t.Errorf("live heap grew by %d MiB", h>>20)
	}
	// History grows with deployments; its cost per deployment must stay
	// small (logs and events are bounded, not accumulated in bulk).
	if n := triggered.Load() + int64(len(deps)); n > 0 {
		if per := (end.dbBytes - warm.dbBytes) / n; per > 64<<10 {
			t.Errorf("database grew %d bytes per deployment", per)
		}
	}
	// Exactly one live workload per environment: superseded and replaced
	// generations were drained.
	// (Replaced generations drain after the promotion's drain delay, and
	// durably through the reconciler.)
	want := projects + 1
	for deadline := time.Now().Add(90 * time.Second); fake.Running() != want && time.Now().Before(deadline); {
		time.Sleep(time.Second)
	}
	if fake.Running() != want {
		t.Errorf("%d workloads running, want %d (one per environment)", fake.Running(), want)
	}
	var ready struct {
		Ready bool `json:"ready"`
	}
	if code := c.do("GET", "/readyz", nil, &ready); code != 200 {
		t.Errorf("readyz after soak: %d", code)
	}
}

// pendingDeployJobs counts deploy jobs not yet finished (periodic
// maintenance jobs are always scheduled and are not counted).
func pendingDeployJobs(ctx context.Context, st *store.Store) int {
	n := 0
	for _, state := range []string{"queued", "running"} {
		js, _ := st.ListJobs(ctx, state, 500)
		for _, j := range js {
			if j.Kind == "deploy" {
				n++
			}
		}
	}
	return n
}
