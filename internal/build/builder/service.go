package builder

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/artifact"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/build/detect"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/git"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/policy"
)

// IPC operations.
const (
	OpStart  = "build.start"
	OpStatus = "build.status"
	OpCancel = "build.cancel"
	OpForget = "build.forget"
	OpPlan   = "build.plan"
)

// SourceSpec describes where source comes from.
type SourceSpec struct {
	Kind         string   `json:"kind"` // git | archive
	CloneURL     string   `json:"clone_url,omitempty"`
	SHA          string   `json:"sha,omitempty"`
	Ref          string   `json:"ref,omitempty"`
	Token        string   `json:"token,omitempty"`
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
}

// Req is a build request from platformd.
type Req struct {
	DeploymentID   string            `json:"deployment_id"`
	ProjectID      string            `json:"project_id"`
	Environment    string            `json:"environment"` // production | staging | preview
	Source         SourceSpec        `json:"source"`
	RootDir        string            `json:"root_dir"`
	ConfigOverride string            `json:"config_override,omitempty"`
	Overrides      detect.Overrides  `json:"overrides"`
	Class          string            `json:"class"`
	BuildRuntime   string            `json:"build_runtime"`           // runc | runsc | vm
	BuildSecrets   map[string]string `json:"build_secrets,omitempty"` // name -> value (trusted builds only)
	BuildArgs      map[string]string `json:"build_args,omitempty"`
}

// Result of a successful build.
type Result struct {
	Commit        git.Result          `json:"commit"`
	Plan          detect.Plan         `json:"plan"`
	Dockerfile    string              `json:"dockerfile,omitempty"`
	Config        policy.Config       `json:"config"`
	Artifact      artifact.IngestResp `json:"artifact"`
	Executor      string              `json:"executor"`
	LeakedSecrets []string            `json:"leaked_secrets,omitempty"`
	DurationMS    int64               `json:"duration_ms"`
}

// StatusReq polls a build.
type StatusReq struct {
	DeploymentID string `json:"deployment_id"`
	AfterSeq     int64  `json:"after_seq"`
}

// Line is one log line.
type Line struct {
	Seq  int64  `json:"seq"`
	Text string `json:"text"`
}

// Status is the build state.
type Status struct {
	State   string  `json:"state"` // queued | running | succeeded | failed | cancelled
	Phase   string  `json:"phase"` // fetching | detecting | building | ingesting
	Lines   []Line  `json:"lines"`
	NextSeq int64   `json:"next_seq"`
	Result  *Result `json:"result,omitempty"`
	Error   string  `json:"error,omitempty"`
}

type IDReq struct {
	DeploymentID string `json:"deployment_id"`
}

type Empty struct{}

// ArtifactClient is the subset of artifactd used by builderd.
type ArtifactClient interface {
	Ingest(ctx context.Context, r artifact.IngestReq) (*artifact.IngestResp, error)
}

// Config configures the builder service.
type Config struct {
	WorkDir       string
	HandoffDir    string
	SourcesDir    string
	MaxConcurrent int
	Trusted       Executor // rootless BuildKit / docker for trusted class
	Untrusted     Executor // sandboxed BuildKit (gVisor / VM); nil = unavailable
	Artifacts     ArtifactClient
	Audit         audit.Sink
	Log           *slog.Logger
	ImagePrefix   string
	BuildpacksOn  bool
	NixpacksOn    bool
	EgressProxy   string // HTTP(S) proxy URL injected as build args
	// BuildCABundle is an extra PEM bundle (enterprise TLS inspection) that
	// build steps must trust; see detect.WithBuildCA.
	BuildCABundle string
	MaxLogLines   int
	Fetch         func(ctx context.Context, dir string, s git.Source) (*git.Result, error)
}

// Service runs builds.
type Service struct {
	cfg  Config
	sem  chan struct{}
	mu   sync.Mutex
	jobs map[string]*job
}

type job struct {
	mu      sync.Mutex
	state   string
	phase   string
	lines   []Line
	seq     int64
	dropped int64
	result  *Result
	err     string
	cancel  context.CancelFunc
	done    chan struct{}
	updated time.Time
}

// New creates the service.
func New(cfg Config) *Service {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 1
	}
	if cfg.MaxLogLines <= 0 {
		cfg.MaxLogLines = 20000
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Fetch == nil {
		cfg.Fetch = git.Fetch
	}
	if cfg.Audit == nil {
		cfg.Audit = audit.Nop{}
	}
	s := &Service{cfg: cfg, sem: make(chan struct{}, cfg.MaxConcurrent), jobs: map[string]*job{}}
	go s.janitor()
	return s
}

func (j *job) log(text string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.seq++
	j.lines = append(j.lines, Line{Seq: j.seq, Text: text})
	if len(j.lines) > 5000 {
		// keep a bounded ring; platformd polls every second so it has
		// already persisted older lines.
		j.dropped += int64(len(j.lines) - 5000)
		j.lines = j.lines[len(j.lines)-5000:]
	}
	j.updated = time.Now()
}

func (j *job) setPhase(p string) {
	j.mu.Lock()
	j.phase = p
	j.updated = time.Now()
	j.mu.Unlock()
}

// Start begins a build (idempotent per deployment).
func (s *Service) Start(ctx context.Context, r Req) (*Status, error) {
	if !ids.HasPrefix(r.DeploymentID, "dep") || !ids.HasPrefix(r.ProjectID, "prj") {
		return nil, ipc.Errorf(ipc.CodeBadRequest, "invalid ids")
	}
	s.mu.Lock()
	if j, ok := s.jobs[r.DeploymentID]; ok {
		s.mu.Unlock()
		return s.status(j, 0), nil
	}
	// Fail closed before queueing if the requested isolation is unavailable.
	exec, err := s.executorFor(r)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	bctx, cancel := context.WithCancel(context.Background())
	j := &job{state: "queued", cancel: cancel, done: make(chan struct{}), updated: time.Now()}
	s.jobs[r.DeploymentID] = j
	s.mu.Unlock()
	go s.run(bctx, j, r, exec)
	return s.status(j, 0), nil
}

func (s *Service) executorFor(r Req) (Executor, error) {
	switch r.BuildRuntime {
	case "runsc", "vm":
		if s.cfg.Untrusted == nil {
			return nil, ipc.Errorf(ipc.CodeUnavailable, "untrusted build sandbox unavailable on this node (fail closed)")
		}
		if len(r.BuildSecrets) > 0 {
			return nil, ipc.Errorf(ipc.CodeForbidden, "untrusted builds never receive secrets")
		}
		return s.cfg.Untrusted, nil
	case "runc", "":
		if r.Class == "untrusted" {
			return nil, ipc.Errorf(ipc.CodeForbidden, "untrusted class requires a sandboxed build runtime")
		}
		if s.cfg.Trusted == nil {
			return nil, ipc.Errorf(ipc.CodeUnavailable, "no build executor configured")
		}
		return s.cfg.Trusted, nil
	}
	return nil, ipc.Errorf(ipc.CodeBadRequest, "unknown build runtime %q", r.BuildRuntime)
}

func (s *Service) run(ctx context.Context, j *job, r Req, exec Executor) {
	defer close(j.done)
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		s.finish(j, nil, ctx.Err())
		return
	}
	defer func() { <-s.sem }()
	j.mu.Lock()
	j.state = "running"
	j.mu.Unlock()
	timeout := 20 * time.Minute
	started := time.Now()
	res, err := s.build(ctx, j, r, exec, &timeout)
	if res != nil {
		res.DurationMS = time.Since(started).Milliseconds()
	}
	s.finish(j, res, err)
	result := audit.Success
	details := map[string]string{"deployment_id": r.DeploymentID, "trust_class": r.Class, "runtime": r.BuildRuntime}
	if err != nil {
		result = audit.Failure
		details["error"] = truncate(err.Error(), 500)
	} else {
		details["commit"] = res.Commit.SHA
		details["artifact_digest"] = res.Artifact.Digest
		if len(res.LeakedSecrets) > 0 {
			details["secret_name"] = strings.Join(res.LeakedSecrets, ",")
			details["reason"] = "exact secret value appeared in build output"
		}
	}
	_, _ = s.cfg.Audit.Append(context.Background(), audit.Event{ActorType: audit.ActorService, ActorID: identity.Builder,
		Action: "build.complete", ResourceType: "deployment", ResourceID: r.DeploymentID, ProjectID: r.ProjectID, Result: result, Details: details})
}

func (s *Service) finish(j *job, res *Result, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.updated = time.Now()
	switch {
	case errors.Is(err, context.Canceled):
		j.state, j.err = "cancelled", "build cancelled"
	case err != nil:
		j.state, j.err = "failed", err.Error()
	default:
		j.state, j.result = "succeeded", res
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *Service) build(ctx context.Context, j *job, r Req, exec Executor, timeout *time.Duration) (*Result, error) {
	ws := filepath.Join(s.cfg.WorkDir, r.DeploymentID)
	_ = os.RemoveAll(ws)
	if err := os.MkdirAll(ws, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(ws)
	src := filepath.Join(ws, "src")
	mask := NewMasker()
	for k, v := range r.BuildSecrets {
		mask.Add(k, v)
	}
	if r.Source.Token != "" {
		mask.Add("github-token", r.Source.Token)
	}
	lw := NewLineWriter(j.log, mask)
	defer lw.Flush()

	// 1. Fetch
	j.setPhase("fetching")
	res := &Result{Executor: exec.Name()}
	switch r.Source.Kind {
	case "git":
		fmt.Fprintf(lw, "==> fetching %s @ %s", redactURL(r.Source.CloneURL), firstNonEmpty(r.Source.SHA, r.Source.Ref))
		fmt.Fprintln(lw)
		fr, err := s.cfg.Fetch(ctx, src, git.Source{CloneURL: r.Source.CloneURL, SHA: r.Source.SHA, Ref: r.Source.Ref, Token: r.Source.Token, AllowedHosts: r.Source.AllowedHosts})
		if err != nil {
			return nil, fmt.Errorf("fetch source: %w", err)
		}
		res.Commit = *fr
		fmt.Fprintf(lw, "==> checked out %s\n", fr.SHA)
	case "archive":
		fmt.Fprintln(lw, "==> extracting uploaded source archive")
		sum, err := s.extractArchive(r.DeploymentID, src)
		if err != nil {
			return nil, fmt.Errorf("source archive: %w", err)
		}
		res.Commit = git.Result{SHA: sum, Message: "uploaded source archive"}
	default:
		return nil, fmt.Errorf("unknown source kind %q", r.Source.Kind)
	}

	// 2. Config + detection
	j.setPhase("detecting")
	root, err := safeJoin(src, r.RootDir)
	if err != nil {
		return nil, err
	}
	var cfg *policy.Config
	switch {
	case r.ConfigOverride != "":
		cfg, err = policy.Parse([]byte(r.ConfigOverride))
		fmt.Fprintln(lw, "==> using administrator configuration override")
	default:
		b, rerr := readBounded(root, policy.FileName, policy.MaxConfigBytes)
		switch {
		case rerr == nil:
			cfg, err = policy.Parse(b)
			fmt.Fprintf(lw, "==> loaded %s\n", policy.FileName)
		case errors.Is(rerr, fs.ErrNotExist):
			cfg = policy.Default()
		default:
			err = rerr
		}
	}
	if err != nil {
		return nil, err
	}
	*timeout = cfg.Build.Timeout.Duration
	bctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	plan, err := detect.Detect(root, detect.Options{Config: cfg, Overrides: r.Overrides, BuildpacksEnabled: s.cfg.BuildpacksOn,
		NixpacksEnabled: s.cfg.NixpacksOn, ImagePrefix: s.cfg.ImagePrefix})
	if err != nil {
		return nil, fmt.Errorf("detect: %w", err)
	}
	for _, reason := range plan.Reasons {
		fmt.Fprintf(lw, "--> %s\n", reason)
	}
	for _, w := range plan.Warnings {
		fmt.Fprintf(lw, "WARNING: %s\n", w)
	}
	fmt.Fprintf(lw, "==> strategy=%s stack=%s framework=%s\n", plan.Strategy, plan.Stack, plan.Framework)
	res.Plan, res.Config, res.Dockerfile = *plan, *cfg, plan.DockerfileContent

	// 3. Build
	j.setPhase("building")
	hand := filepath.Join(s.cfg.HandoffDir, r.DeploymentID)
	if err := os.MkdirAll(hand, 0o750); err != nil {
		return nil, err
	}
	kind := "oci"
	switch {
	case plan.Strategy == "static" && !plan.Generated:
		kind = "static"
		fmt.Fprintf(lw, "==> packaging static directory %s\n", plan.StaticDir)
		dir, err := safeJoin(root, plan.StaticDir)
		if err != nil {
			return nil, err
		}
		if err := tarDir(dir, filepath.Join(hand, artifact.HandoffStatic)); err != nil {
			return nil, err
		}
	case plan.Strategy == "buildpacks" || plan.Strategy == "nixpacks":
		return nil, fmt.Errorf("%s builds are not available on this node; use a Dockerfile or the built-in templates", plan.Strategy)
	default:
		spec := Spec{ContextDir: root, Output: OutputOCI, Dest: filepath.Join(hand, artifact.HandoffImage),
			BuildArgs: map[string]string{"SOURCE_COMMIT": res.Commit.SHA}, NetworkNone: cfg.Build.NetworkPolicy == policy.NetOffline}
		for k, v := range cfg.Build.Args {
			spec.BuildArgs[k] = v
		}
		for k, v := range r.BuildArgs {
			spec.BuildArgs[k] = v
		}
		if s.cfg.EgressProxy != "" && cfg.Build.NetworkPolicy != policy.NetOffline {
			for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
				spec.BuildArgs[k] = s.cfg.EgressProxy
			}
			spec.BuildArgs["NO_PROXY"] = "localhost,127.0.0.1"
		}
		var caBundle string
		if s.cfg.BuildCABundle != "" {
			if caBundle, err = writeBuildCA(ws, s.cfg.BuildCABundle); err != nil {
				return nil, err
			}
			if plan.Generated {
				plan.DockerfileContent = detect.WithBuildCA(plan.DockerfileContent)
				res.Dockerfile = plan.DockerfileContent
			}
			fmt.Fprintf(lw, "==> trusting the node's build CA bundle (secret %q)\n", detect.BuildCASecretID)
		}
		if plan.Generated {
			gen := filepath.Join(ws, "gen")
			if err := os.MkdirAll(gen, 0o700); err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(gen, "Dockerfile"), []byte(plan.DockerfileContent), 0o600); err != nil {
				return nil, err
			}
			spec.DockerfileDir, spec.Dockerfile = gen, "Dockerfile"
			fmt.Fprintln(lw, "==> generated Dockerfile:")
			for _, l := range strings.Split(strings.TrimSpace(plan.DockerfileContent), "\n") {
				fmt.Fprintf(lw, "    %s\n", l)
			}
		} else {
			df, err := safeJoin(root, plan.Dockerfile)
			if err != nil {
				return nil, err
			}
			spec.DockerfileDir, spec.Dockerfile = filepath.Dir(df), filepath.Base(df)
		}
		if plan.StaticOutput {
			kind = "static"
			spec.Target, spec.Output, spec.Dest = "static", OutputTar, filepath.Join(hand, artifact.HandoffStatic)
		}
		if len(cfg.Build.Secrets) > 0 {
			sdir := filepath.Join(ws, "secrets")
			if err := os.MkdirAll(sdir, 0o700); err != nil {
				return nil, err
			}
			spec.Secrets = map[string]string{}
			for _, name := range cfg.Build.Secrets {
				v, ok := r.BuildSecrets[name]
				if !ok {
					return nil, fmt.Errorf("build secret %s is not available for this environment", name)
				}
				p := filepath.Join(sdir, name)
				if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
					return nil, err
				}
				spec.Secrets[name] = p
			}
		}
		if caBundle != "" {
			if spec.Secrets == nil {
				spec.Secrets = map[string]string{}
			}
			if _, clash := spec.Secrets[detect.BuildCASecretID]; clash {
				return nil, fmt.Errorf("build secret name %q is reserved", detect.BuildCASecretID)
			}
			spec.Secrets[detect.BuildCASecretID] = caBundle
		}
		fmt.Fprintf(lw, "==> building with %s (runtime %s)\n", exec.Name(), firstNonEmpty(r.BuildRuntime, "runc"))
		if err := exec.Build(bctx, spec, lw); err != nil {
			if errors.Is(bctx.Err(), context.DeadlineExceeded) {
				return nil, fmt.Errorf("build exceeded timeout %s", *timeout)
			}
			return nil, err
		}
	}
	lw.Flush()
	res.LeakedSecrets = mask.LeakedIDs()
	if len(res.LeakedSecrets) > 0 {
		fmt.Fprintf(lw, "WARNING: exact values of secrets %v appeared in build output and were masked; rotate them\n", res.LeakedSecrets)
	}

	// 4. Hand off to artifactd (via the shared od-handoff group).
	if err := shareTree(hand); err != nil {
		return nil, err
	}
	j.setPhase("ingesting")
	fmt.Fprintln(lw, "==> validating and importing artifact")
	ing, err := s.cfg.Artifacts.Ingest(ctx, artifact.IngestReq{ProjectID: r.ProjectID, DeploymentID: r.DeploymentID, Kind: kind})
	_ = os.RemoveAll(hand)
	if err != nil {
		return nil, fmt.Errorf("artifact ingest: %w", err)
	}
	for _, w := range ing.Warnings {
		fmt.Fprintf(lw, "WARNING: %s\n", w)
	}
	fmt.Fprintf(lw, "==> artifact %s (%d bytes)\n", ing.Digest, ing.Size)
	res.Artifact = *ing
	return res, nil
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

func redactURL(u string) string {
	if i := strings.Index(u, "@"); i > 0 {
		if j := strings.Index(u, "://"); j > 0 && j < i {
			return u[:j+3] + u[i+1:]
		}
	}
	return u
}

// safeJoin joins rel onto root and ensures the result (after resolving
// symlinks) stays inside root.
func safeJoin(root, rel string) (string, error) {
	if rel == "" {
		rel = "."
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("path %q must be relative", rel)
	}
	p := filepath.Join(root, filepath.Clean(rel))
	rr, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	rp, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("%s: %w", rel, err)
	}
	if rp != rr && !strings.HasPrefix(rp, rr+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q escapes the source tree", rel)
	}
	return rp, nil
}

func readBounded(dir, name string, max int64) ([]byte, error) {
	p, err := safeJoin(dir, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fs.ErrNotExist
		}
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s too large", name)
	}
	return b, nil
}

// tarDir packages regular files and directories under dir (symlinks and
// special files are skipped) into dest.
func tarDir(dir, dest string) error {
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		base := d.Name()
		if d.IsDir() && (base == ".git" || base == "node_modules") {
			return filepath.SkipDir
		}
		if base == policy.FileName || base == ".env" || strings.HasPrefix(base, ".env.") {
			return nil // never publish config or dotenv files as static content
		}
		switch {
		case d.IsDir():
			return tw.WriteHeader(&tar.Header{Name: filepath.ToSlash(rel) + "/", Typeflag: tar.TypeDir, Mode: 0o755})
		case d.Type().IsRegular():
			fi, err := d.Info()
			if err != nil {
				return err
			}
			if err := tw.WriteHeader(&tar.Header{Name: filepath.ToSlash(rel), Typeflag: tar.TypeReg, Mode: 0o644, Size: fi.Size()}); err != nil {
				return err
			}
			src, err := os.Open(p)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, src)
			src.Close()
			return err
		default:
			return nil
		}
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

// extractArchive safely unpacks sources/<deployment>.tar.gz uploaded via
// platformd. Symlinks are permitted only when relative and contained.
func (s *Service) extractArchive(depID, dest string) (string, error) {
	p := filepath.Join(s.cfg.SourcesDir, depID+".tar.gz")
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return "", errors.New("uploaded source not found")
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dest, 0o750); err != nil {
		return "", err
	}
	tr := tar.NewReader(gz)
	var total int64
	count := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		count++
		if count > 200000 {
			return "", errors.New("too many files in archive")
		}
		name := strings.TrimPrefix(path.Clean("/"+strings.ReplaceAll(h.Name, "\\", "/")), "/")
		if name == "" || name == "." {
			continue
		}
		for _, part := range strings.Split(h.Name, "/") {
			if part == ".." {
				return "", fmt.Errorf("archive path %q escapes", h.Name)
			}
		}
		target := filepath.Join(dest, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return "", err
			}
		case tar.TypeReg:
			total += h.Size
			if total > 2<<30 {
				return "", errors.New("archive too large")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return "", err
			}
			mode := os.FileMode(0o640)
			if h.Mode&0o111 != 0 {
				mode = 0o750
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				return "", err
			}
			if _, err := io.Copy(out, io.LimitReader(tr, h.Size)); err != nil {
				out.Close()
				return "", err
			}
			out.Close()
		case tar.TypeSymlink:
			if filepath.IsAbs(h.Linkname) {
				return "", fmt.Errorf("absolute symlink %q not allowed", h.Name)
			}
			resolved := filepath.Clean(filepath.Join(filepath.Dir(target), h.Linkname))
			if resolved != dest && !strings.HasPrefix(resolved, dest+string(os.PathSeparator)) {
				return "", fmt.Errorf("symlink %q escapes the source tree", h.Name)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return "", err
			}
			if err := os.Symlink(h.Linkname, target); err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("archive entry %q has unsupported type", h.Name)
		}
	}
	_ = os.Remove(p)
	return "archive-" + depID, nil
}

func (s *Service) status(j *job, after int64) *Status {
	j.mu.Lock()
	defer j.mu.Unlock()
	st := &Status{State: j.state, Phase: j.phase, NextSeq: j.seq, Result: j.result, Error: j.err}
	for _, l := range j.lines {
		if l.Seq > after {
			st.Lines = append(st.Lines, l)
		}
	}
	if len(st.Lines) > 2000 {
		st.Lines = st.Lines[:2000]
		st.NextSeq = st.Lines[len(st.Lines)-1].Seq
	}
	return st
}

// Status returns progress for a build.
func (s *Service) Status(r StatusReq) (*Status, error) {
	s.mu.Lock()
	j, ok := s.jobs[r.DeploymentID]
	s.mu.Unlock()
	if !ok {
		return nil, ipc.Errorf(ipc.CodeNotFound, "no build for deployment")
	}
	return s.status(j, r.AfterSeq), nil
}

// Cancel stops a build.
func (s *Service) Cancel(depID string) {
	s.mu.Lock()
	j, ok := s.jobs[depID]
	s.mu.Unlock()
	if ok {
		j.cancel()
	}
}

// Forget drops a finished build's state.
func (s *Service) Forget(depID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j, ok := s.jobs[depID]; ok {
		j.mu.Lock()
		st := j.state
		j.mu.Unlock()
		if st != "running" && st != "queued" {
			delete(s.jobs, depID)
		}
	}
}

// Wait blocks until the build finishes (tests, all-in-one mode).
func (s *Service) Wait(depID string) {
	s.mu.Lock()
	j, ok := s.jobs[depID]
	s.mu.Unlock()
	if ok {
		<-j.done
	}
}

func (s *Service) janitor() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		s.mu.Lock()
		for id, j := range s.jobs {
			j.mu.Lock()
			stale := j.state != "running" && j.state != "queued" && time.Since(j.updated) > time.Hour
			j.mu.Unlock()
			if stale {
				delete(s.jobs, id)
			}
		}
		s.mu.Unlock()
	}
}

// PlanReq asks for detection only (import preview, FR-004). The source is
// fetched like a build but nothing is built.
type PlanReq = Req

type PlanResp struct {
	Commit     git.Result    `json:"commit"`
	Plan       detect.Plan   `json:"plan"`
	Dockerfile string        `json:"dockerfile,omitempty"`
	Config     policy.Config `json:"config"`
	Error      string        `json:"error,omitempty"`
}

// Plan fetches and detects without building.
func (s *Service) Plan(ctx context.Context, r PlanReq) (*PlanResp, error) {
	ws, err := os.MkdirTemp(s.cfg.WorkDir, "plan-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(ws)
	src := filepath.Join(ws, "src")
	if r.Source.Kind != "git" {
		return nil, ipc.Errorf(ipc.CodeBadRequest, "plan requires a git source")
	}
	fr, err := s.cfg.Fetch(ctx, src, git.Source{CloneURL: r.Source.CloneURL, SHA: r.Source.SHA, Ref: r.Source.Ref, Token: r.Source.Token, AllowedHosts: r.Source.AllowedHosts})
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeBadRequest, "fetch: %v", err)
	}
	out := &PlanResp{Commit: *fr}
	root, err := safeJoin(src, r.RootDir)
	if err != nil {
		out.Error = err.Error()
		return out, nil
	}
	cfg := policy.Default()
	if r.ConfigOverride != "" {
		cfg, err = policy.Parse([]byte(r.ConfigOverride))
	} else if b, rerr := readBounded(root, policy.FileName, policy.MaxConfigBytes); rerr == nil {
		cfg, err = policy.Parse(b)
	}
	if err != nil {
		out.Error = err.Error()
		return out, nil
	}
	out.Config = *cfg
	plan, err := detect.Detect(root, detect.Options{Config: cfg, Overrides: r.Overrides, BuildpacksEnabled: s.cfg.BuildpacksOn, NixpacksEnabled: s.cfg.NixpacksOn, ImagePrefix: s.cfg.ImagePrefix})
	if err != nil {
		out.Error = err.Error()
		return out, nil
	}
	out.Plan, out.Dockerfile = *plan, plan.DockerfileContent
	return out, nil
}

// Register exposes builderd over IPC. Only platformd may drive builds.
func Register(srv *ipc.Server, s *Service) {
	allowed := []string{identity.Platform}
	ipc.Handle(srv, OpStart, allowed, func(ctx context.Context, _ ipc.Caller, r Req) (*Status, error) { return s.Start(ctx, r) })
	ipc.Handle(srv, OpStatus, allowed, func(_ context.Context, _ ipc.Caller, r StatusReq) (*Status, error) { return s.Status(r) })
	ipc.Handle(srv, OpCancel, allowed, func(_ context.Context, _ ipc.Caller, r IDReq) (Empty, error) {
		s.Cancel(r.DeploymentID)
		return Empty{}, nil
	})
	ipc.Handle(srv, OpForget, allowed, func(_ context.Context, _ ipc.Caller, r IDReq) (Empty, error) {
		s.Forget(r.DeploymentID)
		return Empty{}, nil
	})
	ipc.Handle(srv, OpPlan, allowed, func(ctx context.Context, _ ipc.Caller, r PlanReq) (*PlanResp, error) { return s.Plan(ctx, r) })
}

// Client is the typed builderd client used by platformd.
type Client struct{ C *ipc.Client }

func (c *Client) Start(ctx context.Context, r Req) (*Status, error) {
	return ipc.Call[Req, *Status](ctx, c.C, OpStart, r)
}
func (c *Client) Status(ctx context.Context, id string, after int64) (*Status, error) {
	return ipc.Call[StatusReq, *Status](ctx, c.C, OpStatus, StatusReq{DeploymentID: id, AfterSeq: after})
}
func (c *Client) Cancel(ctx context.Context, id string) error {
	_, err := ipc.Call[IDReq, Empty](ctx, c.C, OpCancel, IDReq{DeploymentID: id})
	return err
}
func (c *Client) Forget(ctx context.Context, id string) error {
	_, err := ipc.Call[IDReq, Empty](ctx, c.C, OpForget, IDReq{DeploymentID: id})
	return err
}
func (c *Client) Plan(ctx context.Context, r PlanReq) (*PlanResp, error) {
	return ipc.Call[PlanReq, *PlanResp](ctx, c.C, OpPlan, r)
}

// systemRootFiles are the usual locations of the host trust store (as in
// crypto/x509); the first one present is used.
var systemRootFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/cert.pem",
}

// writeBuildCA writes a complete trust bundle (host roots + the configured
// extra CAs) into the build workspace: the toolchain variables that use it
// replace their default roots, so it must contain both.
func writeBuildCA(ws, extra string) (string, error) {
	add, err := os.ReadFile(extra)
	if err != nil {
		return "", fmt.Errorf("build CA bundle: %w", err)
	}
	if !bytes.Contains(add, []byte("-----BEGIN CERTIFICATE-----")) {
		return "", fmt.Errorf("build CA bundle %s contains no PEM certificates", extra)
	}
	var b bytes.Buffer
	for _, f := range systemRootFiles {
		if sys, err := os.ReadFile(f); err == nil {
			b.Write(sys)
			break
		}
	}
	if b.Len() > 0 && !bytes.HasSuffix(b.Bytes(), []byte("\n")) {
		b.WriteByte('\n')
	}
	b.Write(add)
	dir := filepath.Join(ws, "ca")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(dir, "bundle.pem")
	return p, os.WriteFile(p, b.Bytes(), 0o600)
}

// shareTree makes a hand-off directory readable by its group: builderd runs
// with umask 0077 and external build tools create files with their own modes.
// Symlinks are never followed.
func shareTree(dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.Chmod(p, 0o750)
		case d.Type().IsRegular():
			return os.Chmod(p, 0o640)
		}
		return nil
	})
}
