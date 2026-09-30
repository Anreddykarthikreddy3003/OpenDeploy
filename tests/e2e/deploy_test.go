//go:build e2e

// Package e2e deploys real applications through the full OpenDeploy stack:
// BuildKit (Docker adapter) builds, artifactd validation, the hardened
// Docker runtime, layered health checks, generation-safe promotion and a
// real Caddy edge. Requires Docker and a caddy binary on PATH.
package e2e

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/testcap"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/allinone"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/services"
)

type client struct {
	t    *testing.T
	base string
	hc   *http.Client
	csrf string
}

func (c *client) do(method, path, ctype string, body io.Reader, out any) int {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.base+path, body)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	req.Header.Set("X-CSRF-Token", c.csrf)
	res, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if out != nil {
		_ = json.Unmarshal(b, out)
	}
	if res.StatusCode >= 400 {
		c.t.Logf("%s %s -> %d %s", method, path, res.StatusCode, b)
	}
	return res.StatusCode
}

func (c *client) json(method, path string, body, out any) int {
	b, _ := json.Marshal(body)
	return c.do(method, path, "application/json", bytes.NewReader(b), out)
}

func tarGz(t *testing.T, dir string) *bytes.Buffer {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		fi, _ := d.Info()
		h, _ := tar.FileInfoHeader(fi, "")
		h.Name = filepath.ToSlash(rel)
		if d.IsDir() {
			h.Name += "/"
		}
		_ = tw.WriteHeader(h)
		if d.Type().IsRegular() {
			b, _ := os.ReadFile(p)
			_, _ = tw.Write(b)
		}
		return nil
	})
	tw.Close()
	gz.Close()
	return &buf
}

func TestDeployRealApps(t *testing.T) {
	caddy, err := exec.LookPath("caddy")
	if err != nil {
		testcap.Blocked(t, "caddy not on PATH")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		testcap.Blocked(t, "docker daemon unavailable")
	}
	ctx := context.Background()
	var log *slog.Logger
	if os.Getenv("E2E_VERBOSE") != "" {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	s, err := allinone.Start(ctx, allinone.Options{DataDir: t.TempDir(), CaddyBin: caddy, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := bootstrap(t, s)

	apps := []struct{ name, dir, want string }{
		{"static", "fixtures/static", "hello from static"},
		{"node", "fixtures/node", "hello from node e2e"},
		{"go", "fixtures/go", "hello from go"},
		{"python", "fixtures/python", "hello from python"},
		{"java", "fixtures/java", "hello from java"},
	}
	if only := os.Getenv("E2E_ONLY"); only != "" {
		var keep = apps[:0]
		for _, a := range apps {
			if strings.Contains(","+only+",", ","+a.name+",") {
				keep = append(keep, a)
			}
		}
		apps = keep
	}
	for _, a := range apps {
		a := a
		t.Run(a.name, func(t *testing.T) {
			c.t = t
			env := map[string]string{}
			if a.name == "node" {
				env["GREETING"] = "e2e"
			}
			deployDir(t, c, a.name, a.dir, env)
			host := a.name + ".od.test"
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", s.Node.Ingress.HTTPPort), nil)
			req.Host = host
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode != 200 || !strings.Contains(string(body), a.want) {
				t.Fatalf("GET %s -> %d %q", host, res.StatusCode, body)
			}
		})
	}
}

// bootstrap creates the owner account on a fresh stack and returns a
// logged-in API client.
func bootstrap(t *testing.T, s *allinone.Stack) *client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, base: "http://" + s.APIAddr, hc: &http.Client{Jar: jar, Timeout: 5 * time.Minute}}
	tok, _ := os.ReadFile(services.BootstrapTokenPath(s.Node))
	var sess struct {
		CSRFToken string `json:"csrf_token"`
	}
	if c.json("POST", "/api/v2/auth/bootstrap", map[string]string{"token": strings.TrimSpace(string(tok)), "email": "o@example.com", "password": "correct horse battery"}, &sess) != 201 {
		t.Fatal("bootstrap")
	}
	c.csrf = sess.CSRFToken
	return c
}

// deployDir creates a project, uploads dir as its source and waits for the
// deployment to succeed. It returns the project ID.
func deployDir(t *testing.T, c *client, name, dir string, env map[string]string) string {
	t.Helper()
	var created struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
	}
	if c.json("POST", "/api/v2/projects", map[string]any{"name": name, "env": env}, &created) != 201 {
		t.Fatal("create project")
	}
	var dep struct {
		ID string `json:"id"`
	}
	if code := c.do("POST", "/api/v2/projects/"+created.Project.ID+"/deployments/upload", "application/gzip", tarGz(t, dir), &dep); code != 202 {
		t.Fatalf("upload %d", code)
	}
	deadline := time.Now().Add(15 * time.Minute)
	var st string
	for time.Now().Before(deadline) {
		var out struct {
			Deployment struct {
				Status string `json:"status"`
				Error  string `json:"error"`
			} `json:"deployment"`
		}
		c.json("GET", "/api/v2/deployments/"+dep.ID, nil, &out)
		st = out.Deployment.Status
		if st == "SUCCEEDED" || st == "FAILED" {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if st != "SUCCEEDED" {
		var logs []struct {
			Line string `json:"line"`
		}
		c.json("GET", "/api/v2/deployments/"+dep.ID+"/logs", nil, &logs)
		for _, l := range logs {
			t.Log(l.Line)
		}
		t.Fatalf("deployment ended in %s", st)
	}
	return created.Project.ID
}
