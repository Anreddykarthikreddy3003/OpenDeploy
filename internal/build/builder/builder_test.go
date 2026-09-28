package builder

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/artifact"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/git"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

// fakeExec writes a tiny valid output for whichever kind is requested.
type fakeExec struct {
	spec Spec
	out  string // extra log line
}

func (f *fakeExec) Name() string { return "fake" }
func (f *fakeExec) Build(_ context.Context, s Spec, log io.Writer) error {
	f.spec = s
	fmt.Fprintln(log, f.out)
	if s.Output == OutputTar {
		fd, _ := os.Create(s.Dest)
		tw := tar.NewWriter(fd)
		_ = tw.WriteHeader(&tar.Header{Name: "index.html", Typeflag: tar.TypeReg, Size: 2, Mode: 0o644})
		_, _ = tw.Write([]byte("hi"))
		tw.Close()
		fd.Close()
		return nil
	}
	return errors.New("fake executor only produces static output; use docker test for images")
}

func fixtureFetch(files map[string]string) func(context.Context, string, git.Source) (*git.Result, error) {
	return func(_ context.Context, dir string, s git.Source) (*git.Result, error) {
		for n, c := range files {
			p := filepath.Join(dir, n)
			_ = os.MkdirAll(filepath.Dir(p), 0o755)
			if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
				return nil, err
			}
		}
		return &git.Result{SHA: strings.Repeat("a", 40), Message: "m"}, nil
	}
}

func newSvc(t *testing.T, ex Executor, files map[string]string) (*Service, *audit.Memory) {
	t.Helper()
	root := t.TempDir()
	st, err := artifact.NewStore(filepath.Join(root, "artifacts"), artifact.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	mem := &audit.Memory{}
	asvc := &artifact.Service{Store: st, Registry: artifact.NewRegistry(st, "p", nil), RegistryURL: "127.0.0.1:5010", HandoffDir: filepath.Join(root, "handoff"), Audit: mem}
	s := New(Config{WorkDir: filepath.Join(root, "work"), HandoffDir: asvc.HandoffDir, SourcesDir: filepath.Join(root, "sources"),
		Trusted: ex, Artifacts: localArtifacts{asvc}, Audit: mem, Fetch: fixtureFetch(files)})
	return s, mem
}

type localArtifacts struct{ s *artifact.Service }

func (l localArtifacts) Ingest(ctx context.Context, r artifact.IngestReq) (*artifact.IngestResp, error) {
	return l.s.Ingest(ctx, r)
}

func waitDone(t *testing.T, s *Service, id string) *Status {
	t.Helper()
	s.Wait(id)
	st, err := s.Status(StatusReq{DeploymentID: id})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestStaticSiteBuildNoContainer(t *testing.T) {
	s, mem := newSvc(t, &fakeExec{}, map[string]string{"public/index.html": "<h1>x</h1>", "public/.env": "SECRET=1", "public/opendeploy.yaml": "x"})
	dep, prj := ids.New("dep"), ids.New("prj")
	if _, err := s.Start(context.Background(), Req{DeploymentID: dep, ProjectID: prj, Source: SourceSpec{Kind: "git", CloneURL: "https://github.com/a/b", SHA: strings.Repeat("a", 40)}}); err != nil {
		t.Fatal(err)
	}
	st := waitDone(t, s, dep)
	if st.State != "succeeded" {
		t.Fatalf("%+v", st)
	}
	if st.Result.Artifact.Kind != "static" || st.Result.Plan.Strategy != "static" {
		t.Fatalf("%+v", st.Result)
	}
	if len(mem.Find("build.complete")) != 1 || len(mem.Find("artifact.ingest")) != 1 {
		t.Fatal("audit events missing")
	}
}

func TestViteBuildUsesStaticTarget(t *testing.T) {
	ex := &fakeExec{}
	s, _ := newSvc(t, ex, map[string]string{"package.json": `{"scripts":{"build":"vite build"},"devDependencies":{"vite":"5"}}`, "package-lock.json": "{}"})
	dep, prj := ids.New("dep"), ids.New("prj")
	_, _ = s.Start(context.Background(), Req{DeploymentID: dep, ProjectID: prj, Source: SourceSpec{Kind: "git", CloneURL: "https://github.com/a/b", SHA: strings.Repeat("a", 40)}})
	st := waitDone(t, s, dep)
	if st.State != "succeeded" || ex.spec.Target != "static" || ex.spec.Output != OutputTar {
		t.Fatalf("%+v %+v", st, ex.spec)
	}
	if ex.spec.BuildArgs["SOURCE_COMMIT"] != strings.Repeat("a", 40) {
		t.Fatal("SOURCE_COMMIT missing")
	}
}

func TestSecretMaskingAndLeakReport(t *testing.T) {
	ex := &fakeExec{out: "printing token supersecretvalue123 oops"}
	s, _ := newSvc(t, ex, map[string]string{"opendeploy.yaml": "build:\n  secrets: [NPM_TOKEN]\n", "package.json": `{"scripts":{"build":"vite build"},"devDependencies":{"vite":"5"}}`})
	dep, prj := ids.New("dep"), ids.New("prj")
	_, _ = s.Start(context.Background(), Req{DeploymentID: dep, ProjectID: prj, BuildSecrets: map[string]string{"NPM_TOKEN": "supersecretvalue123"},
		Source: SourceSpec{Kind: "git", CloneURL: "https://github.com/a/b", SHA: strings.Repeat("a", 40)}})
	st := waitDone(t, s, dep)
	if st.State != "succeeded" {
		t.Fatalf("%+v", st)
	}
	for _, l := range st.Lines {
		if strings.Contains(l.Text, "supersecretvalue123") {
			t.Fatal("secret leaked into logs")
		}
	}
	if len(st.Result.LeakedSecrets) != 1 {
		t.Fatalf("leak not reported: %+v", st.Result.LeakedSecrets)
	}
	if b, _ := os.ReadFile(ex.spec.Secrets["NPM_TOKEN"]); len(b) != 0 {
		t.Fatal("secret file not cleaned up after build")
	}
}

func TestUntrustedFailsClosedAndNoSecrets(t *testing.T) {
	s, _ := newSvc(t, &fakeExec{}, nil)
	_, err := s.Start(context.Background(), Req{DeploymentID: ids.New("dep"), ProjectID: ids.New("prj"), Class: "untrusted", BuildRuntime: "runsc"})
	if !ipc.IsCode(err, ipc.CodeUnavailable) {
		t.Fatalf("got %v", err)
	}
	_, err = s.Start(context.Background(), Req{DeploymentID: ids.New("dep"), ProjectID: ids.New("prj"), Class: "untrusted", BuildRuntime: "runc"})
	if !ipc.IsCode(err, ipc.CodeForbidden) {
		t.Fatalf("untrusted on runc: %v", err)
	}
	s.cfg.Untrusted = &fakeExec{}
	_, err = s.Start(context.Background(), Req{DeploymentID: ids.New("dep"), ProjectID: ids.New("prj"), Class: "untrusted", BuildRuntime: "runsc", BuildSecrets: map[string]string{"A": "b"}})
	if !ipc.IsCode(err, ipc.CodeForbidden) {
		t.Fatalf("untrusted with secrets: %v", err)
	}
}

func TestRootDirEscape(t *testing.T) {
	s, _ := newSvc(t, &fakeExec{}, map[string]string{"a/index.html": "x"})
	dep := ids.New("dep")
	_, _ = s.Start(context.Background(), Req{DeploymentID: dep, ProjectID: ids.New("prj"), RootDir: "../../..", Source: SourceSpec{Kind: "git", CloneURL: "https://github.com/a/b", SHA: strings.Repeat("a", 40)}})
	if st := waitDone(t, s, dep); st.State != "failed" {
		t.Fatalf("%+v", st)
	}
}

func writeArchive(t *testing.T, p string, entries []tar.Header, bodies map[string]string) {
	t.Helper()
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	f, _ := os.Create(p)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, h := range entries {
		b := bodies[h.Name]
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(b))
		}
		_ = tw.WriteHeader(&h)
		if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write([]byte(b))
		}
	}
	tw.Close()
	gz.Close()
	f.Close()
}

func TestArchiveSourceSafety(t *testing.T) {
	s, _ := newSvc(t, &fakeExec{}, nil)
	bad := map[string][]tar.Header{
		"traversal":   {{Name: "../evil", Typeflag: tar.TypeReg}},
		"abs-symlink": {{Name: "l", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}},
		"escape-link": {{Name: "a/l", Typeflag: tar.TypeSymlink, Linkname: "../../x"}},
		"device":      {{Name: "d", Typeflag: tar.TypeBlock}},
	}
	for name, hs := range bad {
		dep := ids.New("dep")
		writeArchive(t, filepath.Join(s.cfg.SourcesDir, dep+".tar.gz"), hs, map[string]string{"../evil": "x"})
		if _, err := s.extractArchive(dep, filepath.Join(t.TempDir(), "src")); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	dep := ids.New("dep")
	writeArchive(t, filepath.Join(s.cfg.SourcesDir, dep+".tar.gz"), []tar.Header{{Name: "public/index.html", Typeflag: tar.TypeReg}, {Name: "public/link.html", Typeflag: tar.TypeSymlink, Linkname: "index.html"}},
		map[string]string{"public/index.html": "<p>ok</p>"})
	if _, err := s.extractArchive(dep, filepath.Join(t.TempDir(), "src")); err != nil {
		t.Fatal(err)
	}
}

// TestDockerBuildIntegration runs a real BuildKit build through Docker when
// OPENDEPLOY_DOCKER_TESTS=1 (CI and dev hosts with a Docker daemon).
func TestDockerBuildIntegration(t *testing.T) {
	if os.Getenv("OPENDEPLOY_DOCKER_TESTS") != "1" {
		t.Skip("set OPENDEPLOY_DOCKER_TESTS=1 to run")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	s, _ := newSvc(t, &DockerBuildx{}, map[string]string{
		"go.mod":  "module example.com/hello\n\ngo 1.22\n",
		"main.go": "package main\nimport (\"net/http\";\"os\")\nfunc main(){http.HandleFunc(\"/\",func(w http.ResponseWriter,r *http.Request){w.Write([]byte(\"ok\"))});http.ListenAndServe(\":\"+os.Getenv(\"PORT\"),nil)}\n",
	})
	dep := ids.New("dep")
	_, _ = s.Start(context.Background(), Req{DeploymentID: dep, ProjectID: ids.New("prj"), Source: SourceSpec{Kind: "git", CloneURL: "https://github.com/a/b", SHA: strings.Repeat("a", 40)}})
	done := make(chan struct{})
	go func() { s.Wait(dep); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Minute):
		t.Fatal("build timeout")
	}
	st, _ := s.Status(StatusReq{DeploymentID: dep})
	if st.State != "succeeded" {
		for _, l := range st.Lines {
			t.Log(l.Text)
		}
		t.Fatalf("%s", st.Error)
	}
	if st.Result.Artifact.Kind != "oci" || !strings.Contains(st.Result.Artifact.ImageRef, "@sha256:") || st.Result.Artifact.User != "65532:65532" {
		t.Fatalf("%+v", st.Result.Artifact)
	}
}
