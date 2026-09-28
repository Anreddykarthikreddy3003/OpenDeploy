package secrets

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	_ "modernc.org/sqlite"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	kr, err := LoadOrCreateKeyRing(filepath.Join(dir, "kek"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), filepath.Join(dir, "secrets.db"), kr, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

type fixture struct {
	pA, pB, prodA, prevA, prodB string
}

func seed(t *testing.T, s *Store) fixture {
	ctx := context.Background()
	f := fixture{pA: ids.New("prj"), pB: ids.New("prj"), prodA: ids.New("env"), prevA: ids.New("env"), prodB: ids.New("env")}
	must := func(_ *Meta, err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.Set(ctx, Ref{Scope: ScopeInstance, Name: "SMTP_HOST"}, []byte("smtp.example.com"), false, false, "u"))
	must(s.Set(ctx, Ref{Scope: ScopeProject, ProjectID: f.pA, Name: "SHARED_KEY"}, []byte("project-level-prod-ish"), true, false, "u"))
	must(s.Set(ctx, Ref{Scope: ScopeEnvironment, ProjectID: f.pA, EnvironmentID: f.prodA, Name: "DATABASE_URL"}, []byte("postgres://prod"), true, false, "u"))
	must(s.Set(ctx, Ref{Scope: ScopeEnvironment, ProjectID: f.pA, EnvironmentID: f.prodA, Name: "NPM_TOKEN"}, []byte("npm-prod-token"), true, true, "u"))
	must(s.Set(ctx, Ref{Scope: ScopePreview, ProjectID: f.pA, Name: "DATABASE_URL"}, []byte("postgres://preview"), true, false, "u"))
	must(s.Set(ctx, Ref{Scope: ScopeEnvironment, ProjectID: f.pB, EnvironmentID: f.prodB, Name: "DATABASE_URL"}, []byte("postgres://B"), true, false, "u"))
	return f
}

func TestResolveProduction(t *testing.T) {
	s, _ := newStore(t)
	f := seed(t, s)
	r, err := s.Resolve(context.Background(), ResolveReq{ProjectID: f.pA, EnvironmentID: f.prodA, EnvKind: "production", TrustClass: "trusted", Purpose: "runtime"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"SMTP_HOST": "smtp.example.com", "SHARED_KEY": "project-level-prod-ish", "DATABASE_URL": "postgres://prod", "NPM_TOKEN": "npm-prod-token"}
	for k, v := range want {
		if r.Values[k] != v {
			t.Errorf("%s=%q want %q", k, r.Values[k], v)
		}
	}
}

// Q19/Q65/ST-03: previews never inherit production or project secrets.
func TestPreviewIsolation(t *testing.T) {
	s, _ := newStore(t)
	f := seed(t, s)
	r, err := s.Resolve(context.Background(), ResolveReq{ProjectID: f.pA, EnvironmentID: f.prevA, EnvKind: "preview", TrustClass: "trusted", Purpose: "runtime"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Values["DATABASE_URL"] != "postgres://preview" {
		t.Fatalf("preview got %q", r.Values["DATABASE_URL"])
	}
	if _, ok := r.Values["SHARED_KEY"]; ok {
		t.Fatal("preview inherited project secret")
	}
	if _, ok := r.Values["NPM_TOKEN"]; ok {
		t.Fatal("preview inherited production secret")
	}
	// Guessing the production environment id from a preview request with a
	// preview kind still only returns the production environment's secrets
	// if the caller lies about the environment; platformd derives env ids
	// from the DB, and secretd refuses fork workloads in production.
	if _, err := s.Resolve(context.Background(), ResolveReq{ProjectID: f.pA, EnvironmentID: f.prodA, EnvKind: "production", Purpose: "runtime", FromFork: true}); !errors.Is(err, ErrDenied) {
		t.Fatalf("fork in production: %v", err)
	}
}

// Q9: cross-project IDOR attempts return nothing.
func TestCrossProjectIsolation(t *testing.T) {
	s, _ := newStore(t)
	f := seed(t, s)
	r, err := s.Resolve(context.Background(), ResolveReq{ProjectID: f.pA, EnvironmentID: f.prodB, EnvKind: "production", Purpose: "runtime"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.Values["DATABASE_URL"], "B") {
		t.Fatal("project A resolved project B's secret")
	}
	list, _ := s.List(context.Background(), ScopeEnvironment, f.pB, f.prodB)
	if _, _, err := s.Reveal(context.Background(), list[0].ID, f.pA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-project reveal: %v", err)
	}
}

func TestBuildSecrets(t *testing.T) {
	s, _ := newStore(t)
	f := seed(t, s)
	r, _ := s.Resolve(context.Background(), ResolveReq{ProjectID: f.pA, EnvironmentID: f.prodA, EnvKind: "production", TrustClass: "trusted", Purpose: "build"})
	if len(r.Values) != 1 || r.Values["NPM_TOKEN"] != "npm-prod-token" {
		t.Fatalf("build secrets %v", r.Values)
	}
	r, _ = s.Resolve(context.Background(), ResolveReq{ProjectID: f.pA, EnvironmentID: f.prodA, EnvKind: "production", TrustClass: "untrusted", Purpose: "build"})
	if len(r.Values) != 0 {
		t.Fatal("untrusted build received secrets")
	}
}

func TestListNeverReturnsSensitiveValues(t *testing.T) {
	s, _ := newStore(t)
	f := seed(t, s)
	list, _ := s.List(context.Background(), ScopeEnvironment, f.pA, f.prodA)
	for _, m := range list {
		if m.Preview != "" {
			t.Fatalf("sensitive preview leaked: %+v", m)
		}
	}
	inst, _ := s.List(context.Background(), ScopeInstance, "", "")
	if len(inst) != 1 || inst[0].Preview != "smtp.example.com" {
		t.Fatalf("%+v", inst)
	}
}

func TestVersioningAndDelete(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	p, e := ids.New("prj"), ids.New("env")
	ref := Ref{Scope: ScopeEnvironment, ProjectID: p, EnvironmentID: e, Name: "K"}
	_, _ = s.Set(ctx, ref, []byte("v1"), true, false, "u")
	m, _ := s.Set(ctx, ref, []byte("v2"), true, false, "u")
	if m.Version != 2 {
		t.Fatal(m.Version)
	}
	r, _ := s.Resolve(ctx, ResolveReq{ProjectID: p, EnvironmentID: e, EnvKind: "production", Purpose: "runtime"})
	if r.Values["K"] != "v2" {
		t.Fatal(r.Values)
	}
	if err := s.Delete(ctx, ref); err != nil {
		t.Fatal(err)
	}
	r, _ = s.Resolve(ctx, ResolveReq{ProjectID: p, EnvironmentID: e, EnvKind: "production", Purpose: "runtime"})
	if _, ok := r.Values["K"]; ok {
		t.Fatal("deleted secret resolved")
	}
}

// Ciphertext rows are bound to identity: moving a row to another project
// makes it undecryptable rather than leaking.
func TestCiphertextSwapDetected(t *testing.T) {
	s, dir := newStore(t)
	f := seed(t, s)
	db, _ := sql.Open("sqlite", filepath.Join(dir, "secrets.db"))
	defer db.Close()
	_, err := db.Exec(`UPDATE secrets SET project_id=?, environment_id=? WHERE project_id=? AND name='DATABASE_URL' AND scope='environment'`, f.pA, f.prodA, f.pB)
	if err != nil {
		// unique index may block direct move; move to a new env instead
		_, err = db.Exec(`UPDATE secrets SET project_id=? WHERE project_id=?`, f.pA, f.pB)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = s.Resolve(context.Background(), ResolveReq{ProjectID: f.pA, EnvironmentID: f.prodB, EnvKind: "production", Purpose: "runtime"})
	if err == nil {
		t.Fatal("swapped ciphertext decrypted under a different identity")
	}
}

func TestKEKRotation(t *testing.T) {
	s, dir := newStore(t)
	f := seed(t, s)
	id, n, err := s.RotateKEK(context.Background())
	if err != nil || n != 6 {
		t.Fatalf("%s %d %v", id, n, err)
	}
	r, err := s.Resolve(context.Background(), ResolveReq{ProjectID: f.pA, EnvironmentID: f.prodA, EnvKind: "production", Purpose: "runtime"})
	if err != nil || r.Values["DATABASE_URL"] != "postgres://prod" {
		t.Fatalf("%v %v", r, err)
	}
	kr, err := LoadOrCreateKeyRing(filepath.Join(dir, "kek"))
	if err != nil || len(kr.Keys) != 1 || kr.Current != id {
		t.Fatalf("old kek not purged: %+v %v", kr, err)
	}
	fi, _ := os.Stat(filepath.Join(dir, "kek"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatal("key ring permissions")
	}
}

func TestValidation(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	bad := []Ref{
		{Scope: ScopeInstance, ProjectID: ids.New("prj"), Name: "A"},
		{Scope: ScopeEnvironment, ProjectID: ids.New("prj"), Name: "A"},
		{Scope: "global", Name: "A"},
		{Scope: ScopeInstance, Name: "../x"},
	}
	for _, r := range bad {
		if _, err := s.Set(ctx, r, []byte("x"), true, false, "u"); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
	if _, err := s.Set(ctx, Ref{Scope: ScopeInstance, Name: "BIG"}, make([]byte, MaxValueBytes+1), true, false, "u"); err == nil {
		t.Fatal("oversize accepted")
	}
}
