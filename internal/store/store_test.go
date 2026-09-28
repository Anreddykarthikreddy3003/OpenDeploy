package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/model"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(context.Background(), filepath.Join(dir, "platform.db"), filepath.Join(dir, "snap"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := s.DB.Degraded(); d != "" {
		t.Fatal(d)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mkProject(t *testing.T, s *Store, name string) (*Project, *Environment) {
	t.Helper()
	ctx := context.Background()
	p := &Project{Name: name, RepoID: 42, RepoFullName: "o/" + name, AutoDeploy: true}
	if err := s.CreateProject(ctx, p); err != nil {
		t.Fatal(err)
	}
	e, err := s.GetEnvironmentByName(ctx, p.ID, "production")
	if err != nil {
		t.Fatal(err)
	}
	return p, e
}

// advance moves a deployment to HEALTH_CHECKING.
func advance(t *testing.T, s *Store, id string) {
	t.Helper()
	ctx := context.Background()
	steps := []model.DeploymentStatus{model.StatusReceived, model.StatusValidating, model.StatusFetching, model.StatusDetecting,
		model.StatusBuilding, model.StatusArtifactReady, model.StatusStartingCandidate, model.StatusHealthChecking}
	for i := 0; i < len(steps)-1; i++ {
		if err := s.Transition(ctx, id, steps[i], steps[i+1], ""); err != nil {
			t.Fatalf("%s->%s: %v", steps[i], steps[i+1], err)
		}
	}
}

func promote(t *testing.T, s *Store, depID string) error {
	t.Helper()
	ctx := context.Background()
	pi, err := s.BeginPromotion(ctx, depID, "sha256:x")
	if err != nil {
		return err
	}
	if err := s.MarkRouterApplied(ctx, pi.ID, "sha256:y"); err != nil {
		return err
	}
	if err := s.CommitPromotion(ctx, pi.ID); err != nil {
		return err
	}
	if err := s.CompletePromotion(ctx, pi.ID); err != nil {
		return err
	}
	return s.Transition(ctx, depID, model.StatusDrainingOld, model.StatusSucceeded, "")
}

func TestGenerationMonotonicAndSupersede(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_, env := mkProject(t, s, "app")
	d1, err := s.CreateDeployment(ctx, NewDeployment{EnvironmentID: env.ID, Trigger: "push", CommitSHA: "a"})
	if err != nil {
		t.Fatal(err)
	}
	advance(t, s, d1.ID)
	d2, err := s.CreateDeployment(ctx, NewDeployment{EnvironmentID: env.ID, Trigger: "push", CommitSHA: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if d1.Generation != 1 || d2.Generation != 2 {
		t.Fatalf("generations %d %d", d1.Generation, d2.Generation)
	}
	got, _ := s.GetDeployment(ctx, d1.ID)
	if got.Status != model.StatusSuperseded {
		t.Fatalf("old deployment status %s", got.Status)
	}
	// Even if the stale build reports success late, it cannot promote.
	if _, err := s.BeginPromotion(ctx, d1.ID, "x"); err == nil {
		t.Fatal("superseded deployment promoted")
	}
}

// Q47/Q73: a slow old build finishing after a newer one cannot overwrite.
func TestOutOfOrderCompletion(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_, env := mkProject(t, s, "app")
	d1, _ := s.CreateDeployment(ctx, NewDeployment{EnvironmentID: env.ID, Trigger: "push", CommitSHA: "old"})
	// Simulate d1 already at HEALTH_CHECKING when d2 is created is covered above;
	// here d2 is promoted first, then d1 attempts promotion.
	d2, _ := s.CreateDeployment(ctx, NewDeployment{EnvironmentID: env.ID, Trigger: "push", CommitSHA: "new"})
	advance(t, s, d2.ID)
	if err := promote(t, s, d2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginPromotion(ctx, d1.ID, "x"); err == nil {
		t.Fatal("old generation promoted after newer")
	}
	e, _ := s.GetEnvironment(ctx, env.ID)
	if e.CurrentDeploymentID != d2.ID || e.ObservedGeneration != 2 {
		t.Fatalf("env %+v", e)
	}
}

func TestBeginPromotionSupersedesStaleCandidate(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_, env := mkProject(t, s, "app")
	d1, _ := s.CreateDeployment(ctx, NewDeployment{EnvironmentID: env.ID, Trigger: "push"})
	advance(t, s, d1.ID)
	// Bump desired generation behind its back via a rollback-style request
	// that fails before superseding (simulate by direct SQL).
	if _, err := s.DB.R().ExecContext(ctx, "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Tx(ctx, func(tx *sqlTx) error {
		_, err := tx.ExecContext(ctx, `UPDATE environments SET desired_generation=desired_generation+1 WHERE id=?`, env.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginPromotion(ctx, d1.ID, "x"); !errors.Is(err, ErrSuperseded) {
		t.Fatalf("got %v", err)
	}
	got, _ := s.GetDeployment(ctx, d1.ID)
	if got.Status != model.StatusSuperseded {
		t.Fatalf("status %s", got.Status)
	}
}

// Q48: two simultaneous promotions; only one wins the lock.
func TestConcurrentPromotionLock(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_, env := mkProject(t, s, "app")
	d, _ := s.CreateDeployment(ctx, NewDeployment{EnvironmentID: env.ID, Trigger: "push"})
	advance(t, s, d.ID)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.BeginPromotion(ctx, d.ID, "x"); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("wins=%d", wins)
	}
}

func TestRollbackIsNewGeneration(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	p, env := mkProject(t, s, "app")
	art, err := s.UpsertArtifact(ctx, &Artifact{ProjectID: p.ID, Kind: "oci", Digest: "sha256:aa"})
	if err != nil {
		t.Fatal(err)
	}
	d1, _ := s.CreateDeployment(ctx, NewDeployment{EnvironmentID: env.ID, Trigger: "push"})
	aid := art.ID
	_ = s.PatchDeployment(ctx, d1.ID, DeploymentPatch{ArtifactID: &aid})
	advance(t, s, d1.ID)
	if err := promote(t, s, d1.ID); err != nil {
		t.Fatal(err)
	}
	rb, err := s.CreateDeployment(ctx, NewDeployment{EnvironmentID: env.ID, Trigger: "rollback", RollbackOf: d1.ID, ArtifactID: art.ID})
	if err != nil {
		t.Fatal(err)
	}
	if rb.Generation != 2 || rb.ArtifactID != art.ID {
		t.Fatalf("%+v", rb)
	}
	// Artifact of another project is refused.
	p2, env2 := mkProject(t, s, "other")
	_ = p2
	if _, err := s.CreateDeployment(ctx, NewDeployment{EnvironmentID: env2.ID, Trigger: "rollback", ArtifactID: art.ID}); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-project artifact: %v", err)
	}
}

func TestIllegalTransitionRejected(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_, env := mkProject(t, s, "app")
	d, _ := s.CreateDeployment(ctx, NewDeployment{EnvironmentID: env.ID, Trigger: "push"})
	if err := s.Transition(ctx, d.ID, model.StatusReceived, model.StatusSucceeded, ""); err != nil {
		// forward skip is legal by rule; ensure CAS on wrong from fails
		t.Fatal(err)
	}
	if err := s.Transition(ctx, d.ID, model.StatusReceived, model.StatusValidating, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("CAS mismatch must conflict: %v", err)
	}
}

func TestInvariantViolationDegrades(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.db")
	ctx := context.Background()
	s, err := Open(ctx, path, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, e1 := mkProject(t, s, "a")
	_, e2 := mkProject(t, s, "b")
	d, _ := s.CreateDeployment(ctx, NewDeployment{EnvironmentID: e2.ID, Trigger: "push"})
	// Corrupt: point env a at env b's deployment.
	if err := s.DB.Tx(ctx, func(tx *sqlTx) error {
		_, err := tx.ExecContext(ctx, `UPDATE environments SET current_deployment_id=? WHERE id=?`, d.ID, e1.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := Open(ctx, path, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.DB.Degraded() == "" {
		t.Fatal("expected degraded mode")
	}
	if _, err := s2.CreateDeployment(ctx, NewDeployment{EnvironmentID: e1.ID, Trigger: "push"}); !errors.Is(err, state.ErrDegraded) {
		t.Fatalf("writes must fail in degraded mode: %v", err)
	}
}

func TestJobsLeaseAndBackoff(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	id, err := s.Enqueue(ctx, "build", "k1", map[string]string{"a": "b"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	id2, _ := s.Enqueue(ctx, "build", "k1", nil, 2)
	if id != id2 {
		t.Fatal("idempotency key not honoured")
	}
	j, err := s.ClaimJob(ctx, "w", []string{"build"}, 1)
	if err != nil || j == nil || j.ID != id {
		t.Fatalf("%+v %v", j, err)
	}
	// Lease of 1ns expired: another worker can reclaim (crash recovery).
	j2, _ := s.ClaimJob(ctx, "w2", []string{"build"}, 1e9)
	if j2 == nil || j2.Attempts != 2 {
		t.Fatalf("reclaim %+v", j2)
	}
	dead, err := s.FailJob(ctx, id, "boom", false)
	if err != nil || !dead {
		t.Fatalf("exhausted job should be dead: %v %v", dead, err)
	}
}

func TestBreaker(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for i := 0; i < BreakerThreshold; i++ {
		_ = s.BreakerRecord(ctx, "env:x", errors.New("fail"))
	}
	ok, b, _ := s.BreakerAllow(ctx, "env:x")
	if ok || b.State != "open" {
		t.Fatalf("breaker should be open: %v %+v", ok, b)
	}
	_ = s.BreakerRecord(ctx, "env:x", nil)
	if ok, _, _ := s.BreakerAllow(ctx, "env:x"); !ok {
		t.Fatal("breaker should reset on success")
	}
}

func TestSnapshotVerify(t *testing.T) {
	s := newStore(t)
	p, err := s.DB.Snapshot(context.Background(), t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := state.VerifySnapshot(p); err != nil {
		t.Fatal(err)
	}
}

type sqlTx = sql.Tx
