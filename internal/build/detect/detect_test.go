package detect

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/policy"
)

func mktree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func detect(t *testing.T, files map[string]string, opt Options) *Plan {
	t.Helper()
	p, err := Detect(mktree(t, files), opt)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mustContain(t *testing.T, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Errorf("missing %q in:\n%s", sub, s)
		}
	}
}

func TestDockerfileWins(t *testing.T) {
	p := detect(t, map[string]string{"Dockerfile": "FROM alpine\nEXPOSE 3000\n", "package.json": `{}`}, Options{})
	if p.Strategy != "dockerfile" || p.Port != 3000 || p.Generated {
		t.Fatalf("%+v", p)
	}
}

func TestDockerfileSecretWarning(t *testing.T) {
	p := detect(t, map[string]string{"Dockerfile": "FROM alpine\nARG NPM_TOKEN\nRUN --security=insecure ls\n"}, Options{})
	if len(p.Warnings) != 2 {
		t.Fatalf("warnings %v", p.Warnings)
	}
}

func TestNodeExpress(t *testing.T) {
	p := detect(t, map[string]string{
		"package.json":      `{"name":"x","scripts":{"start":"node server.js","build":"tsc"},"dependencies":{"express":"^4"},"engines":{"node":">=20"}}`,
		"package-lock.json": "{}",
	}, Options{})
	if p.Stack != "node" || p.PackageManager != "npm" || p.RuntimeVersion != "20" || p.StaticOutput {
		t.Fatalf("%+v", p)
	}
	mustContain(t, p.DockerfileContent, "npm ci", "npm run build", "USER 10001:10001", `"exec npm run start"`, "node:20-bookworm-slim")
}

func TestNodeNextPnpm(t *testing.T) {
	p := detect(t, map[string]string{
		"package.json":   `{"scripts":{"build":"next build","start":"next start"},"dependencies":{"next":"14","react":"18"}}`,
		"pnpm-lock.yaml": "",
	}, Options{})
	if p.Framework != "next" || p.PackageManager != "pnpm" {
		t.Fatalf("%+v", p)
	}
	mustContain(t, p.DockerfileContent, "pnpm install --frozen-lockfile", "pnpm run build")
	if len(p.Tmpfs) == 0 {
		t.Fatal("next cache tmpfs missing")
	}
}

func TestNodeViteStatic(t *testing.T) {
	p := detect(t, map[string]string{
		"package.json": `{"scripts":{"dev":"vite","build":"vite build"},"devDependencies":{"vite":"5"}}`,
		"yarn.lock":    "",
	}, Options{})
	if !p.StaticOutput || p.StaticDir != "dist" || p.Port != 0 {
		t.Fatalf("%+v", p)
	}
	mustContain(t, p.DockerfileContent, "FROM scratch AS static", "COPY --from=build /app/dist/ /", "yarn install --frozen-lockfile")
}

func TestNodeCRAStartIsDevServer(t *testing.T) {
	p := detect(t, map[string]string{
		"package.json": `{"scripts":{"start":"react-scripts start","build":"react-scripts build"},"dependencies":{"react-scripts":"5"}}`,
	}, Options{})
	if !p.StaticOutput || p.StaticDir != "build" {
		t.Fatalf("%+v", p)
	}
	if len(p.Warnings) == 0 {
		t.Fatal("missing lockfile warning")
	}
}

func TestPythonFastAPI(t *testing.T) {
	p := detect(t, map[string]string{
		"requirements.txt": "fastapi==0.110\n",
		"app/main.py":      "from fastapi import FastAPI\napi = FastAPI()\n",
		".python-version":  "3.11.4\n",
	}, Options{})
	if p.Framework != "fastapi" || p.RuntimeVersion != "3.11" {
		t.Fatalf("%+v", p)
	}
	mustContain(t, p.DockerfileContent, "uvicorn app.main:api", "pip install uvicorn", "python:3.11-slim-bookworm", "USER 10001")
}

func TestPythonDjango(t *testing.T) {
	p := detect(t, map[string]string{
		"requirements.txt":   "Django>=5\ngunicorn\n",
		"manage.py":          "",
		"mysite/wsgi.py":     "",
		"mysite/settings.py": "",
	}, Options{})
	if p.Framework != "django" {
		t.Fatalf("%+v", p)
	}
	mustContain(t, p.DockerfileContent, "gunicorn mysite.wsgi:application", "collectstatic")
	if strings.Contains(p.DockerfileContent, "pip install gunicorn") {
		t.Fatal("gunicorn already present; should not be added")
	}
}

func TestPythonFlaskPoetry(t *testing.T) {
	p := detect(t, map[string]string{"pyproject.toml": "[tool.poetry.dependencies]\nflask = \"^3\"\n", "poetry.lock": "", "app.py": "from flask import Flask\napp = Flask(__name__)\n"}, Options{})
	if p.Framework != "flask" || p.PackageManager != "poetry" {
		t.Fatalf("%+v", p)
	}
	mustContain(t, p.DockerfileContent, "gunicorn app:app", "poetry install")
}

func TestProcfileOverrides(t *testing.T) {
	p := detect(t, map[string]string{"requirements.txt": "x", "Procfile": "web: python -m myapp --port $PORT\nworker: celery\n"}, Options{})
	if p.StartCommand != "python -m myapp --port $PORT" {
		t.Fatalf("%q", p.StartCommand)
	}
}

func TestGoCmd(t *testing.T) {
	p := detect(t, map[string]string{
		"go.mod":              "module example.com/svc\n\ngo 1.22.1\n",
		"cmd/svc/main.go":     "package main\nfunc main(){}\n",
		"cmd/migrate/main.go": "package main\nfunc main(){}\n",
		"internal/x/x.go":     "package x\n",
	}, Options{})
	if p.RuntimeVersion != "1.22" || !strings.Contains(p.BuildCommand, "./cmd/svc") {
		t.Fatalf("%+v", p)
	}
	mustContain(t, p.DockerfileContent, "distroless/static-debian12:nonroot", "USER 65532:65532", "CGO_ENABLED=0")
}

func TestGoAmbiguous(t *testing.T) {
	_, err := Detect(mktree(t, map[string]string{"go.mod": "module a\n", "cmd/a1/main.go": "package main", "cmd/b1/main.go": "package main"}), Options{})
	if err == nil {
		t.Fatal("ambiguous commands must require overrides")
	}
}

func TestJavaSpringMaven(t *testing.T) {
	p := detect(t, map[string]string{"pom.xml": "<project><properties><java.version>17</java.version></properties><parent>org.springframework.boot</parent></project>", "mvnw": ""}, Options{})
	if p.Framework != "spring-boot" || p.RuntimeVersion != "17" {
		t.Fatalf("%+v", p)
	}
	mustContain(t, p.DockerfileContent, "./mvnw", "eclipse-temurin:17-jre", "-Dserver.port=$PORT")
}

func TestJavaGradleKts(t *testing.T) {
	p := detect(t, map[string]string{"build.gradle.kts": "java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }"}, Options{})
	if p.PackageManager != "gradle" || p.RuntimeVersion != "21" {
		t.Fatalf("%+v", p)
	}
}

func TestDotnet(t *testing.T) {
	p := detect(t, map[string]string{"src/Api/Api.csproj": `<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net9.0</TargetFramework></PropertyGroup></Project>`, "src/Lib/Lib.csproj": `<Project Sdk="Microsoft.NET.Sdk"></Project>`}, Options{})
	if p.RuntimeVersion != "9.0" || !strings.Contains(p.StartCommand, "Api.dll") {
		t.Fatalf("%+v", p)
	}
}

func TestRubyRails(t *testing.T) {
	p := detect(t, map[string]string{"Gemfile": "ruby \"3.2.2\"\ngem 'rails'\n", "config/application.rb": ""}, Options{})
	if p.Framework != "rails" || p.RuntimeVersion != "3.2" {
		t.Fatalf("%+v", p)
	}
}

func TestPHPLaravel(t *testing.T) {
	p := detect(t, map[string]string{"composer.json": `{"require":{"php":"^8.2","laravel/framework":"^11"}}`, "public/index.php": ""}, Options{})
	if p.Framework != "laravel" || p.RuntimeVersion != "8.2" {
		t.Fatalf("%+v", p)
	}
	mustContain(t, p.DockerfileContent, "/var/www/app/public", "Listen ${PORT}")
}

func TestRust(t *testing.T) {
	p := detect(t, map[string]string{"Cargo.toml": "[package]\nname = \"web-svc\"\n[dependencies]\naxum = \"0.7\"\n", "Cargo.lock": ""}, Options{})
	mustContain(t, p.DockerfileContent, "cp target/release/web-svc /out/app", "--locked")
}

func TestElixir(t *testing.T) {
	p := detect(t, map[string]string{"mix.exs": "def project do [app: :my_app, deps: [{:phoenix, \"~> 1.7\"}]] end"}, Options{})
	if p.Framework != "phoenix" {
		t.Fatalf("%+v", p)
	}
	mustContain(t, p.DockerfileContent, "_build/prod/rel/my_app")
}

func TestStaticSite(t *testing.T) {
	p := detect(t, map[string]string{"public/index.html": "<h1>hi</h1>"}, Options{})
	if p.Strategy != "static" || p.StaticDir != "public" {
		t.Fatalf("%+v", p)
	}
}

func TestNeedsWizard(t *testing.T) {
	_, err := Detect(mktree(t, map[string]string{"README.md": "hi"}), Options{})
	if !errors.Is(err, ErrNeedsWizard) {
		t.Fatalf("got %v", err)
	}
	p, err := Detect(mktree(t, map[string]string{"README.md": "hi"}), Options{Overrides: Overrides{BuildCommand: "make", StartCommand: "./server"}})
	if err != nil || p.Stack != "custom" {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestExplicitStrategyFromConfig(t *testing.T) {
	cfg := policy.Default()
	cfg.Build.Strategy = policy.StrategyDockerfile
	if _, err := Detect(mktree(t, map[string]string{"package.json": "{}"}), Options{Config: cfg}); err == nil {
		t.Fatal("dockerfile strategy without Dockerfile must fail")
	}
	cfg.Build.Strategy = policy.StrategyBuildpacks
	if _, err := Detect(mktree(t, map[string]string{"package.json": "{}"}), Options{Config: cfg}); err == nil {
		t.Fatal("buildpacks when disabled must fail")
	}
}

// Symlinks pointing outside the tree must not be followed (untrusted source).
func TestSymlinkEscape(t *testing.T) {
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "package.json"), []byte(`{"scripts":{"start":"node x"}}`), 0o644)
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "package.json"), filepath.Join(dir, "package.json")); err != nil {
		t.Skip(err)
	}
	if _, err := Detect(dir, Options{}); !errors.Is(err, ErrNeedsWizard) {
		t.Fatalf("symlinked file outside tree was read: %v", err)
	}
}

func TestImagePrefix(t *testing.T) {
	if got := withPrefix("mirror.gcr.io", "node:22-bookworm-slim"); got != "mirror.gcr.io/library/node:22-bookworm-slim" {
		t.Fatal(got)
	}
	if got := withPrefix("mirror.gcr.io", "mcr.microsoft.com/dotnet/sdk:8.0"); got != "mcr.microsoft.com/dotnet/sdk:8.0" {
		t.Fatal(got)
	}
	if got := withPrefix("m.io/", "oven/bun:1"); got != "m.io/oven/bun:1" {
		t.Fatal(got)
	}
}
