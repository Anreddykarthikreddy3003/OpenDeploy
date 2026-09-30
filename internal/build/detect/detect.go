// Package detect inspects a source tree and produces a transparent,
// reviewable build plan (PRD §7.1, FR-004, FR-018).
//
// Detection priority:
//  1. explicit opendeploy.yaml strategy
//  2. user-selected Docker Compose mode (strategy: compose)
//  3. Dockerfile
//  4. Cloud Native Buildpacks (when enabled on the node and `pack` exists)
//  5. Nixpacks (when enabled on the node and `nixpacks` exists)
//  6. built-in hardened templates for common stacks, then static heuristic
//  7. manual build/start wizard (project build overrides)
//
// Every decision is recorded in Plan.Reasons so the dashboard can show why a
// strategy was chosen. The source tree is untrusted: reads are bounded and
// symlinks are never followed outside the tree.
package detect

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/policy"
)

// Plan is the outcome of detection.
type Plan struct {
	Strategy          string   `json:"strategy"` // dockerfile | template | buildpacks | nixpacks | static | compose
	Stack             string   `json:"stack"`
	Framework         string   `json:"framework,omitempty"`
	PackageManager    string   `json:"package_manager,omitempty"`
	Dockerfile        string   `json:"dockerfile,omitempty"` // repo-provided Dockerfile path (relative to context)
	DockerfileContent string   `json:"-"`                    // generated Dockerfile
	Generated         bool     `json:"generated"`
	Context           string   `json:"context"`
	Port              int      `json:"port"`
	StaticOutput      bool     `json:"static_output"`
	StaticDir         string   `json:"static_dir,omitempty"`
	BuildCommand      string   `json:"build_command,omitempty"`
	StartCommand      string   `json:"start_command,omitempty"`
	RuntimeVersion    string   `json:"runtime_version,omitempty"`
	Tmpfs             []string `json:"tmpfs,omitempty"`
	Reasons           []string `json:"reasons"`
	Warnings          []string `json:"warnings,omitempty"`
}

// Options control detection.
type Options struct {
	Config            *policy.Config
	Overrides         Overrides
	BuildpacksEnabled bool
	NixpacksEnabled   bool
	ImagePrefix       string // registry mirror prefix for base images, e.g. "mirror.example.com/"
}

// Overrides are administrator-set values from the manual wizard.
type Overrides struct {
	Strategy     string
	BuildCommand string
	StartCommand string
	OutputDir    string
	Port         int
}

// ErrNeedsWizard is returned when nothing could be inferred.
var ErrNeedsWizard = errors.New("could not detect how to build this project; configure build/start commands or add a Dockerfile")

const maxRead = 1 << 20

// Detect produces a plan for the tree rooted at dir (already the build root).
func Detect(dir string, opt Options) (*Plan, error) {
	cfg := opt.Config
	if cfg == nil {
		cfg = policy.Default()
	}
	t := &tree{root: dir}
	p := &Plan{Context: ".", Port: cfg.Runtime.Port}
	if opt.Overrides.Port > 0 {
		p.Port = opt.Overrides.Port
	}
	strategy := string(cfg.Build.Strategy)
	if opt.Overrides.Strategy != "" && opt.Overrides.Strategy != "auto" {
		strategy = opt.Overrides.Strategy
		p.reason("strategy %q set by project administrator", strategy)
	} else if strategy != "auto" {
		p.reason("strategy %q set in opendeploy.yaml", strategy)
	}
	if cfg.Runtime.Type == policy.WorkloadStatic && strategy == "auto" {
		strategy = "static"
		p.reason("runtime.type is static")
	}

	switch strategy {
	case "compose":
		return nil, errors.New("compose mode is configured per project from the dashboard (services -> workloads); single-image build not applicable")
	case "dockerfile":
		return p, planDockerfile(t, p, cfg, true)
	case "buildpacks":
		if !opt.BuildpacksEnabled {
			return nil, errors.New("buildpacks strategy requested but Cloud Native Buildpacks are not enabled on this node")
		}
		return planBuildpacks(t, p)
	case "nixpacks":
		if !opt.NixpacksEnabled {
			return nil, errors.New("nixpacks strategy requested but Nixpacks is not enabled on this node")
		}
		p.Strategy, p.Stack = "nixpacks", "nixpacks"
		p.reason("Nixpacks generates a Dockerfile that is built with BuildKit")
		return p, nil
	case "static":
		return p, planStatic(t, p, opt, true)
	case "auto":
	default:
		return nil, fmt.Errorf("unknown strategy %q", strategy)
	}

	// 3. Dockerfile
	if err := planDockerfile(t, p, cfg, false); err == nil {
		return p, nil
	}
	// 4-5. Buildpacks / Nixpacks when enabled on this node.
	if opt.BuildpacksEnabled && t.anyExists("package.json", "requirements.txt", "pyproject.toml", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "Gemfile", "composer.json") {
		pl, err := planBuildpacks(t, p)
		if err == nil {
			return pl, nil
		}
	}
	if opt.NixpacksEnabled && !t.exists("index.html") {
		p.Strategy, p.Stack = "nixpacks", "nixpacks"
		p.reason("no Dockerfile; Nixpacks enabled on this node")
		return p, nil
	}
	// 6. Built-in templates.
	for _, d := range detectors {
		ok, err := d(t, p, opt)
		if err != nil {
			return nil, err
		}
		if ok {
			if p.Strategy == "" {
				p.Strategy = "template"
			}
			applyOverrides(p, opt.Overrides)
			if p.Strategy == "template" && p.DockerfileContent == "" {
				return nil, fmt.Errorf("internal: no template generated for %s", p.Stack)
			}
			return p, nil
		}
	}
	if err := planStatic(t, p, opt, false); err == nil {
		return p, nil
	}
	// 7. Manual wizard.
	if opt.Overrides.BuildCommand != "" || opt.Overrides.StartCommand != "" {
		return planManual(p, opt)
	}
	return nil, ErrNeedsWizard
}

func (p *Plan) reason(f string, a ...any) { p.Reasons = append(p.Reasons, fmt.Sprintf(f, a...)) }
func (p *Plan) warn(f string, a ...any)   { p.Warnings = append(p.Warnings, fmt.Sprintf(f, a...)) }

func applyOverrides(p *Plan, o Overrides) {
	if o.StartCommand != "" && !p.StaticOutput {
		p.StartCommand = o.StartCommand
		p.reason("start command overridden by project administrator")
	}
}

func planDockerfile(t *tree, p *Plan, cfg *policy.Config, required bool) error {
	name := cfg.Build.Dockerfile
	if name == "" {
		for _, c := range []string{"Dockerfile", "dockerfile", "Containerfile"} {
			if t.exists(c) {
				name = c
				break
			}
		}
	}
	if name == "" || !t.exists(name) {
		if required {
			return errors.New("strategy dockerfile selected but no Dockerfile found")
		}
		return errors.New("no dockerfile")
	}
	content, err := t.read(name)
	if err != nil {
		return err
	}
	p.Strategy, p.Stack, p.Dockerfile = "dockerfile", "dockerfile", name
	p.reason("found %s in build root", name)
	if port := exposedPort(content); port > 0 && p.Port == 8080 {
		p.Port = port
		p.reason("using EXPOSE %d from Dockerfile", port)
	}
	if regexp.MustCompile(`(?im)--security\s*=\s*insecure|--network\s*=\s*host`).MatchString(content) {
		p.warn("Dockerfile requests insecure/host-network RUN options; these entitlements are denied")
	}
	if regexp.MustCompile(`(?im)^\s*(ARG|ENV)\s+\S*(SECRET|TOKEN|PASSWORD|API_KEY)`).MatchString(content) {
		p.warn("Dockerfile declares secret-like ARG/ENV; use build secrets (RUN --mount=type=secret) instead")
	}
	return nil
}

func exposedPort(dockerfile string) int {
	m := regexp.MustCompile(`(?im)^\s*EXPOSE\s+([0-9]{1,5})`).FindAllStringSubmatch(dockerfile, -1)
	if len(m) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(m[len(m)-1][1])
	if n < 1 || n > 65535 {
		return 0
	}
	return n
}

func planBuildpacks(t *tree, p *Plan) (*Plan, error) {
	p.Strategy, p.Stack = "buildpacks", "buildpacks"
	p.reason("Cloud Native Buildpacks (Paketo) builder selected")
	if proc, ok := procfileWeb(t); ok {
		p.StartCommand = proc
		p.reason("start command from Procfile")
	}
	return p, nil
}

func planStatic(t *tree, p *Plan, opt Options, required bool) error {
	dir := opt.Overrides.OutputDir
	if dir == "" && opt.Config != nil {
		dir = opt.Config.Build.OutputDir
	}
	if dir == "" {
		for _, c := range []string{".", "public", "dist", "build", "_site", "site", "www"} {
			if t.exists(filepath.Join(c, "index.html")) && !t.exists("package.json") {
				dir = c
				break
			}
		}
	}
	if dir == "" {
		if required {
			return errors.New("static strategy requires index.html or build.output_dir")
		}
		return errors.New("not static")
	}
	p.Strategy, p.Stack, p.StaticOutput, p.StaticDir = "static", "static", true, dir
	p.Port = 0
	p.reason("static site: serving %s/ directly from the edge (no application process)", dir)
	return nil
}

func planManual(p *Plan, opt Options) (*Plan, error) {
	if opt.Overrides.StartCommand == "" && opt.Overrides.OutputDir == "" {
		return nil, ErrNeedsWizard
	}
	p.Strategy, p.Stack = "template", "custom"
	p.BuildCommand, p.StartCommand = opt.Overrides.BuildCommand, opt.Overrides.StartCommand
	p.reason("manual build/start commands from project settings")
	if opt.Overrides.OutputDir != "" {
		p.StaticOutput, p.StaticDir, p.Port = true, opt.Overrides.OutputDir, 0
	}
	p.DockerfileContent = renderCustom(p, opt.ImagePrefix)
	p.Generated = true
	return p, nil
}

type detector func(t *tree, p *Plan, opt Options) (bool, error)

var detectors = []detector{detectNode, detectPython, detectGo, detectJava, detectDotnet, detectRuby, detectPHP, detectRust, detectElixir}

// tree is a bounded, symlink-safe view of the source directory.
type tree struct{ root string }

func (t *tree) path(rel string) (string, error) {
	clean := filepath.Clean("/" + rel)
	full := filepath.Join(t.root, clean)
	rp, err := filepath.EvalSymlinks(full)
	if err != nil {
		return "", err
	}
	rootReal, err := filepath.EvalSymlinks(t.root)
	if err != nil {
		return "", err
	}
	if rp != rootReal && !strings.HasPrefix(rp, rootReal+string(os.PathSeparator)) {
		return "", fmt.Errorf("%s escapes the source tree", rel)
	}
	return rp, nil
}

func (t *tree) exists(rel string) bool {
	p, err := t.path(rel)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

func (t *tree) anyExists(rels ...string) bool {
	for _, r := range rels {
		if t.exists(r) {
			return true
		}
	}
	return false
}

func (t *tree) read(rel string) (string, error) {
	p, err := t.path(rel)
	if err != nil {
		return "", err
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", rel)
	}
	b := make([]byte, maxRead)
	n, _ := f.Read(b)
	return string(b[:n]), nil
}

// glob lists entries in dir (relative) matching pattern, sorted.
func (t *tree) glob(dir, pattern string) []string {
	p, err := t.path(dir)
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if ok, _ := filepath.Match(pattern, e.Name()); ok {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out
}

// walkFind finds files named name up to depth levels deep (skipping vendored dirs).
func (t *tree) walkFind(name string, depth int) []string {
	var out []string
	root, err := filepath.EvalSymlinks(t.root)
	if err != nil {
		return nil
	}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			if rel != "." && (strings.Count(rel, string(os.PathSeparator)) >= depth || skipDir(d.Name())) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == name && d.Type().IsRegular() {
			out = append(out, rel)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func skipDir(n string) bool {
	switch n {
	case "node_modules", "vendor", ".git", "target", "build", "dist", "bin", "obj", "_build", "deps", ".venv", "venv":
		return true
	}
	return false
}

func procfileWeb(t *tree) (string, bool) {
	s, err := t.read("Procfile")
	if err != nil {
		return "", false
	}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "web:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "web:")), true
		}
	}
	return "", false
}

func readJSON(t *tree, rel string, v any) error {
	s, err := t.read(rel)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(s), v)
}
