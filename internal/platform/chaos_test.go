package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/artifact"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/build/builder"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/build/detect"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/git"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/model"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/network"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/policy"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/router"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/runtime"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// ---- fakes -----------------------------------------------------------------

type fakeBuilder struct {
	mu     sync.Mutex
	n      int
	delay  time.Duration
	failOn map[string]bool
	cron   []policy.CronJob
}

func (b *fakeBuilder) Start(ctx context.Context, r builder.Req) (*builder.Status, error) {
	return &builder.Status{State: "running"}, nil
}

func (b *fakeBuilder) Status(ctx context.Context, id string, after int64) (*builder.Status, error) {
	if b.delay > 0 {
		time.Sleep(b.delay)
	}
	b.mu.Lock()
	b.n++
	n := b.n
	fail := b.failOn[id]
	b.mu.Unlock()
	if fail {
		return &builder.Status{State: "failed", Error: "injected build failure"}, nil
	}
	cfg := policy.Default()
	cfg.Health.Startup = &policy.ProbeConfig{Path: "/", Grace: policy.Duration{Duration: 5 * time.Second}}
	cfg.Cron = b.cron
	return &builder.Status{State: "succeeded", Result: &builder.Result{
		Commit:   git.Result{SHA: strings.Repeat("a", 40)},
		Plan:     detect.Plan{Strategy: "dockerfile", Port: 8080},
		Config:   *cfg,
		Artifact: artifact.IngestResp{Info: artifact.Info{Kind: "oci", Digest: fmt.Sprintf("sha256:%064x", n)}, ImageRef: fmt.Sprintf("127.0.0.1:5010/od/x@sha256:%064x", n)},
		Executor: "fake"}}, nil
}
func (b *fakeBuilder) Cancel(context.Context, string) error { return nil }
func (b *fakeBuilder) Forget(context.Context, string) error { return nil }
func (b *fakeBuilder) Plan(context.Context, builder.PlanReq) (*builder.PlanResp, error) {
	return nil, errors.New("unused")
}

// rtAdapter exposes runtime.Fake through the platform Runtime interface.
type rtAdapter struct{ f *runtime.Fake }

func (a rtAdapter) Capabilities(ctx context.Context) (*runtime.Capabilities, error) {
	return a.f.Capabilities(ctx)
}
func (a rtAdapter) EnsureNetwork(ctx context.Context, n runtime.NetworkSpec) (*runtime.NetworkInfo, error) {
	return a.f.EnsureNetwork(ctx, n)
}
func (a rtAdapter) RemoveNetwork(ctx context.Context, id string) error {
	return a.f.RemoveNetwork(ctx, id)
}
func (a rtAdapter) Start(ctx context.Context, s runtime.Spec) (*runtime.Workload, error) {
	return a.f.Start(ctx, &s, runtime.RegistryAuth{})
}
func (a rtAdapter) Stop(ctx context.Context, id string, t time.Duration) error {
	return a.f.Stop(ctx, id, t)
}
func (a rtAdapter) Remove(ctx context.Context, id string) error { return a.f.Remove(ctx, id) }
func (a rtAdapter) Inspect(ctx context.Context, id string) (*runtime.Workload, error) {
	return a.f.Inspect(ctx, id)
}
func (a rtAdapter) List(ctx context.Context, r runtime.ListReq) ([]runtime.Workload, error) {
	f := map[string]string{}
	if r.EnvironmentID != "" {
		f["environment"] = r.EnvironmentID
	}
	return a.f.List(ctx, f)
}
func (a rtAdapter) Logs(ctx context.Context, id string, tail int, since time.Time) ([]runtime.LogLine, error) {
	return a.f.Logs(ctx, id, tail, since)
}

// fakeRouter records the applied table and can inject failures.
type fakeRouter struct {
	mu      sync.Mutex
	table   router.Table
	applies int
	fail    func(t router.Table, verify []string) error
}

func (r *fakeRouter) Apply(ctx context.Context, t router.Table, verify []string) (*router.ApplyResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rt := range t.Routes {
		if err := rt.Validate(); err != nil && rt.Kind != router.KindStatic {
			return nil, err
		}
	}
	if r.fail != nil {
		if err := r.fail(t, verify); err != nil {
			return nil, err
		}
	}
	r.table = t
	r.applies++
	return &router.ApplyResult{Digest: fmt.Sprintf("sha256:%d", r.applies)}, nil
}

func (r *fakeRouter) Current(ctx context.Context) (*router.CurrentResp, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return &router.CurrentResp{Table: r.table}, nil
}

func (r *fakeRouter) deploymentFor(env string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rt := range r.table.Routes {
		if rt.EnvironmentID == env {
			return rt.DeploymentID
		}
	}
	return ""
}

// ---- harness ---------------------------------------------------------------

type harness struct {
	t   *testing.T
	p   *Platform
	s   *store.Store
	rt  *runtime.Fake
	rtr *fakeRouter
	b   *fakeBuilder
	env *store.Environment
	prj *store.Project
}

func workloadAddr(t *testing.T) string {
	addrs, _ := net.InterfaceAddrs()
	ip := ""
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
			ip = ipn.IP.String()
			break
		}
	}
	if ip == "" {
		t.Skip("no non-loopback address")
	}
	ln, err := net.Listen("tcp", ip+":0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "p.db"), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	t.Setenv("OPENDEPLOY_INSECURE_DEV", "1")
	n := &config.Node{DataDir: dir, RunDir: dir, DevMode: true}
	n.Ingress.BaseDomain = "od.test"
	n.ApplyDefaults()
	addr := workloadAddr(t)
	f := runtime.NewFake()
	f.EndpointFor = func(*runtime.Spec) string { return addr }
	rtr := &fakeRouter{}
	b := &fakeBuilder{failOn: map[string]bool{}}
	p := New(Deps{Store: st, Node: n, Builder: b, Runtime: rtAdapter{f}, Router: rtr, Egress: network.Nop{}, InsecureNoNetworkPolicy: true,
		GitHub: &GitHubProvider{Node: n}})
	prj := &store.Project{Name: "app", CloneURL: "https://140.82.112.3/o/app.git"}
	if err := st.CreateProject(context.Background(), prj); err != nil {
		t.Fatal(err)
	}
	env, _ := st.GetEnvironmentByName(context.Background(), prj.ID, "production")
	_ = st.SetGeneratedHostname(context.Background(), env.ID, "app.od.test")
	env, _ = st.GetEnvironment(context.Background(), env.ID)
	return &harness{t: t, p: p, s: st, rt: f, rtr: rtr, b: b, env: env, prj: prj}
}

func (h *harness) deploy() *store.Deployment {
	h.t.Helper()
	d, err := h.s.CreateDeployment(context.Background(), store.NewDeployment{EnvironmentID: h.env.ID, Trigger: "manual", CommitSHA: strings.Repeat("a", 40)})
	if err != nil {
		h.t.Fatal(err)
	}
	return d
}

// runTo drives a deployment through the pipeline synchronously.
func (h *harness) run(depID string) {
	h.t.Helper()
	if err := h.p.runDeploy(context.Background(), depID); err != nil {
		h.t.Fatalf("runDeploy: %v", err)
	}
}

func (h *harness) status(id string) model.DeploymentStatus {
	d, err := h.s.GetDeployment(context.Background(), id)
	if err != nil {
		h.t.Fatal(err)
	}
	return d.Status
}

func (h *harness) current() string {
	e, _ := h.s.GetEnvironment(context.Background(), h.env.ID)
	return e.CurrentDeploymentID
}

// driveToHealthy runs a deployment with auto-promotion disabled up to READY,
// returning it (so tests can craft interrupted promotions).
func (h *harness) driveToHealthChecking(t *testing.T) *store.Deployment {
	d := h.deploy()
	ctx := context.Background()
	steps := []func() error{
		func() error { return h.p.transition(ctx, d, model.StatusValidating, "") },
		func() error {
			proj, _ := h.s.GetProject(ctx, d.ProjectID)
			env, _ := h.s.GetEnvironment(ctx, d.EnvironmentID)
			return h.p.validate(ctx, d, proj, env)
		},
		func() error {
			proj, _ := h.s.GetProject(ctx, d.ProjectID)
			env, _ := h.s.GetEnvironment(ctx, d.EnvironmentID)
			return h.p.build(ctx, d, proj, env)
		},
		func() error {
			env, _ := h.s.GetEnvironment(ctx, d.EnvironmentID)
			d2, _ := h.s.GetDeployment(ctx, d.ID)
			*d = *d2
			return h.p.prepareCandidate(ctx, d, env)
		},
		func() error {
			proj, _ := h.s.GetProject(ctx, d.ProjectID)
			env, _ := h.s.GetEnvironment(ctx, d.EnvironmentID)
			return h.p.startCandidate(ctx, d, proj, env)
		},
	}
	for i, st := range steps {
		if err := st(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	d2, _ := h.s.GetDeployment(ctx, d.ID)
	if d2.Status != model.StatusHealthChecking {
		t.Fatalf("status %s", d2.Status)
	}
	return d2
}

// ---- tests -----------------------------------------------------------------

func TestHappyPathAndGeneration(t *testing.T) {
	h := newHarness(t)
	d := h.deploy()
	h.run(d.ID)
	if h.status(d.ID) != model.StatusSucceeded || h.current() != d.ID || h.rtr.deploymentFor(h.env.ID) != d.ID {
		t.Fatalf("status=%s current=%s edge=%s", h.status(d.ID), h.current(), h.rtr.deploymentFor(h.env.ID))
	}
}

// ST-09: crash after BeginPromotion (intent pending, router untouched).
func TestCrashAfterIntentPending(t *testing.T) {
	h := newHarness(t)
	d := h.driveToHealthChecking(t)
	if _, err := h.s.BeginPromotion(context.Background(), d.ID, ""); err != nil {
		t.Fatal(err)
	}
	// "reboot": reconciler finds the pending intent with a healthy candidate.
	if err := h.p.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.status(d.ID) != model.StatusSucceeded || h.current() != d.ID || h.rtr.deploymentFor(h.env.ID) != d.ID {
		t.Fatalf("did not converge: %s", h.status(d.ID))
	}
}

// ST-09: crash after the router switched but before the DB recorded it.
func TestCrashAfterRouterSwitchBeforeMark(t *testing.T) {
	h := newHarness(t)
	old := h.deploy()
	h.run(old.ID)
	d := h.driveToHealthChecking(t)
	ctx := context.Background()
	pi, _ := h.s.BeginPromotion(ctx, d.ID, "")
	tbl, _ := h.p.routeTable(ctx, h.env.ID, d.ID)
	_, _ = h.rtr.Apply(ctx, tbl, nil) // router switched; process "dies" here
	if h.rtr.deploymentFor(h.env.ID) != d.ID {
		t.Fatal("setup")
	}
	_ = pi
	if err := h.p.ReconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if h.status(d.ID) != model.StatusSucceeded || h.current() != d.ID {
		t.Fatalf("did not converge: %s current=%s", h.status(d.ID), h.current())
	}
}

// ST-09: crash after MarkRouterApplied and after CommitPromotion.
func TestCrashAtLaterIntentStates(t *testing.T) {
	for _, stopAfter := range []string{"router_applied", "committed"} {
		t.Run(stopAfter, func(t *testing.T) {
			h := newHarness(t)
			d := h.driveToHealthChecking(t)
			ctx := context.Background()
			pi, _ := h.s.BeginPromotion(ctx, d.ID, "")
			tbl, _ := h.p.routeTable(ctx, h.env.ID, d.ID)
			res, _ := h.rtr.Apply(ctx, tbl, nil)
			_ = h.s.MarkRouterApplied(ctx, pi.ID, res.Digest)
			if stopAfter == "committed" {
				_ = h.s.CommitPromotion(ctx, pi.ID)
			}
			if err := h.p.ReconcileOnce(ctx); err != nil {
				t.Fatal(err)
			}
			if h.status(d.ID) != model.StatusSucceeded || h.current() != d.ID {
				t.Fatalf("%s: status %s current %s", stopAfter, h.status(d.ID), h.current())
			}
			if n, _ := h.s.InflightPromotions(ctx); len(n) != 0 {
				t.Fatal("intent left in flight")
			}
		})
	}
}

// Candidate died while the promotion was interrupted: restore last good.
func TestInterruptedPromotionUnhealthyCandidateRestores(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	old := h.deploy()
	h.run(old.ID)
	d := h.driveToHealthChecking(t)
	_, _ = h.s.BeginPromotion(ctx, d.ID, "")
	tbl, _ := h.p.routeTable(ctx, h.env.ID, d.ID)
	_, _ = h.rtr.Apply(ctx, tbl, nil)
	ws, _ := h.s.WorkloadsForDeployment(ctx, d.ID)
	_ = h.rt.Stop(ctx, ws[0].ID, 0) // candidate crashed
	if err := h.p.ReconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if h.status(d.ID) != model.StatusFailed {
		t.Fatalf("candidate status %s", h.status(d.ID))
	}
	if h.current() != old.ID || h.rtr.deploymentFor(h.env.ID) != old.ID {
		t.Fatalf("edge not restored: current=%s edge=%s", h.current(), h.rtr.deploymentFor(h.env.ID))
	}
}

// Router rejects the candidate: deployment fails, previous stays live.
func TestRouterFailureKeepsPrevious(t *testing.T) {
	h := newHarness(t)
	old := h.deploy()
	h.run(old.ID)
	h.rtr.fail = func(t router.Table, verify []string) error {
		if len(verify) > 0 {
			return errors.New("verification failed: 502 from candidate")
		}
		return nil
	}
	d := h.deploy()
	h.run(d.ID)
	if h.status(d.ID) != model.StatusFailed || h.current() != old.ID || h.rtr.deploymentFor(h.env.ID) != old.ID {
		t.Fatalf("status=%s current=%s edge=%s", h.status(d.ID), h.current(), h.rtr.deploymentFor(h.env.ID))
	}
	if n, _ := h.s.InflightPromotions(context.Background()); len(n) != 0 {
		t.Fatal("intent left in flight after abort")
	}
	if ws, _ := h.s.WorkloadsForDeployment(context.Background(), d.ID); ws[0].State != "stopped" {
		t.Fatalf("failed candidate still running: %s", ws[0].State)
	}
}

// Q47/Q48: many concurrent deployments; only the newest generation may end
// up current and observed generation never decreases.
func TestConcurrentDeploymentsConverge(t *testing.T) {
	h := newHarness(t)
	h.b.delay = 5 * time.Millisecond
	ctx := context.Background()
	var mu sync.Mutex
	var created []*store.Deployment
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := h.deploy()
			mu.Lock()
			created = append(created, d)
			mu.Unlock()
		}()
	}
	wg.Wait()
	var maxGen int64
	var newest *store.Deployment
	for _, d := range created {
		if d.Generation > maxGen {
			maxGen, newest = d.Generation, d
		}
	}
	var runs sync.WaitGroup
	var errs atomic.Int32
	for _, d := range created {
		runs.Add(1)
		go func(id string) {
			defer runs.Done()
			for i := 0; i < 20; i++ {
				err := h.p.runDeploy(ctx, id)
				if err == nil {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
			errs.Add(1)
		}(d.ID)
	}
	runs.Wait()
	if errs.Load() > 0 {
		t.Fatal("some deployments never settled")
	}
	e, _ := h.s.GetEnvironment(ctx, h.env.ID)
	if e.CurrentDeploymentID != newest.ID || e.ObservedGeneration != maxGen || h.rtr.deploymentFor(h.env.ID) != newest.ID {
		t.Fatalf("current=%s (want %s) observed=%d max=%d edge=%s", e.CurrentDeploymentID, newest.ID, e.ObservedGeneration, maxGen, h.rtr.deploymentFor(h.env.ID))
	}
	for _, d := range created {
		st := h.status(d.ID)
		if d.ID != newest.ID && st == model.StatusSucceeded {
			// A lower generation may only have succeeded before the newer
			// one was created; with all created up-front none may.
			t.Fatalf("stale generation %d succeeded", d.Generation)
		}
	}
}

// Reboot: all workloads vanished; reconciler restores them and the edge.
func TestRebootRestoresDesiredState(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	d := h.deploy()
	h.run(d.ID)
	ws, _ := h.s.WorkloadsForDeployment(ctx, d.ID)
	for _, w := range ws {
		_ = h.rt.Remove(ctx, w.ID)
	}
	if h.rt.Running() != 0 {
		t.Fatal("setup")
	}
	if err := h.p.ReconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if h.rt.Running() != len(ws) {
		t.Fatalf("running %d want %d", h.rt.Running(), len(ws))
	}
	if h.rtr.deploymentFor(h.env.ID) != d.ID {
		t.Fatal("edge not restored")
	}
}

// Workloads the platform does not know about are removed.
func TestOrphanRemoval(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	d := h.deploy()
	h.run(d.ID)
	orphan := runtime.Spec{ID: ids.New("wkl"), ProjectID: h.prj.ID, EnvironmentID: h.env.ID, DeploymentID: ids.New("dep"), Service: "web", Kind: "app"}
	_, _ = h.rt.Start(ctx, &orphan, runtime.RegistryAuth{})
	h.rt.W[orphan.ID].StartedAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := h.p.ReconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := h.rt.Inspect(ctx, orphan.ID); err == nil {
		t.Fatal("orphan not removed")
	}
	if h.rt.Running() != 1 {
		t.Fatalf("legit workload affected: %d running", h.rt.Running())
	}
}

// Interrupted build (platform restarted mid-pipeline) resumes.
func TestInterruptedPipelineResumes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	d := h.deploy()
	_ = h.p.transition(ctx, d, model.StatusValidating, "")
	// No job exists (crash before enqueue was processed): reconciler enqueues.
	if err := h.p.ReconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}
	job, err := h.s.ClaimJob(ctx, "w", []string{JobDeploy}, time.Minute)
	if err != nil || job == nil {
		t.Fatalf("resume job not enqueued: %v", err)
	}
	if err := h.p.dispatch(ctx, job); err != nil {
		t.Fatal(err)
	}
	if h.status(d.ID) != model.StatusSucceeded {
		t.Fatalf("status %s", h.status(d.ID))
	}
}

// Circuit breaker stops hammering a failing environment.
func TestBreakerOpensOnRepeatedRestoreFailures(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	d := h.deploy()
	h.run(d.ID)
	ws, _ := h.s.WorkloadsForDeployment(ctx, d.ID)
	_ = h.rt.Remove(ctx, ws[0].ID)
	h.rt.FailStart = func(*runtime.Spec) error { return errors.New("image pull failed") }
	for i := 0; i < store.BreakerThreshold+2; i++ {
		_ = h.p.ReconcileOnce(ctx)
	}
	ok, b, _ := h.s.BreakerAllow(ctx, "env:"+h.env.ID)
	if ok || b.State != "open" {
		t.Fatalf("breaker %+v", b)
	}
}

// Failed builds never touch the edge.
func TestBuildFailureDoesNotTouchEdge(t *testing.T) {
	h := newHarness(t)
	old := h.deploy()
	h.run(old.ID)
	applies := h.rtr.applies
	d := h.deploy()
	h.b.failOn[d.ID] = true
	h.run(d.ID)
	if h.status(d.ID) != model.StatusFailed || h.current() != old.ID || h.rtr.applies != applies {
		t.Fatalf("status %s current %s applies %d->%d", h.status(d.ID), h.current(), applies, h.rtr.applies)
	}
}

// Live corruption detected by the periodic integrity check degrades the
// platform: reconciliation stops mutating and writes fail.
func TestLiveCorruptionEntersDegradedMode(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	d := h.deploy()
	h.run(d.ID)
	other := &store.Project{Name: "other"}
	_ = h.s.CreateProject(ctx, other)
	oenv, _ := h.s.GetEnvironmentByName(ctx, other.ID, "production")
	// Corrupt: point another project's environment at this deployment.
	if err := h.s.Tx(ctx, func(tx *sqlTx) error {
		_, err := tx.ExecContext(ctx, `UPDATE environments SET current_deployment_id=? WHERE id=?`, d.ID, oenv.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if problems := h.p.CheckIntegrity(ctx); len(problems) == 0 {
		t.Fatal("corruption not detected")
	}
	if h.s.DB.Degraded() == "" {
		t.Fatal("not degraded")
	}
	if err := h.p.ReconcileOnce(ctx); err == nil {
		t.Fatal("reconcile ran in degraded mode")
	}
	if _, err := h.s.CreateDeployment(ctx, store.NewDeployment{EnvironmentID: h.env.ID, Trigger: "manual"}); err == nil {
		t.Fatal("write allowed in degraded mode")
	}
}

func TestCronRuns(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.b.cron = []policy.CronJob{{Name: "cleanup", Schedule: "*/5 * * * *", Command: []string{"./cleanup", "--old"}}}
	d := h.deploy()
	h.run(d.ID)
	due := time.Date(2026, 9, 28, 10, 5, 0, 0, time.UTC)
	if err := h.p.RunCron(ctx, due); err != nil {
		t.Fatal(err)
	}
	var cronID string
	for id, sp := range h.rt.Specs {
		if sp.Service == "cron-cleanup" {
			cronID = id
			if strings.Join(sp.Command, " ") != "./cleanup --old" || sp.Port != 0 || !sp.ReadOnlyRoot {
				t.Fatalf("cron spec %+v", sp)
			}
		}
	}
	if cronID == "" {
		t.Fatal("cron run not started")
	}
	// Same minute again: idempotent. Next due minute while still running: no overlap.
	_ = h.p.RunCron(ctx, due)
	_ = h.p.RunCron(ctx, due.Add(5*time.Minute))
	count := 0
	for _, sp := range h.rt.Specs {
		if sp.Service == "cron-cleanup" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("cron runs = %d", count)
	}
	// Not due: nothing new. Finished run is reaped.
	_ = h.rt.Stop(ctx, cronID, 0)
	_ = h.p.RunCron(ctx, due.Add(7*time.Minute))
	if _, err := h.rt.Inspect(ctx, cronID); err == nil {
		t.Fatal("finished cron run not reaped")
	}
	w, _ := h.s.GetWorkload(ctx, cronID)
	if w.State != "stopped" {
		t.Fatalf("cron row %s", w.State)
	}
}
