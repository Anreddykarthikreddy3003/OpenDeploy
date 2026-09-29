//go:build pkginstall

// Package pkginstall checks a node installed from the deb/rpm package on a
// real systemd host: every unit is up under its own identity, the dashboard
// is served, and apps deploy through rootless BuildKit, containerd and the
// Caddy edge. CI runs it after `dpkg -i` (see .github/workflows/package.yml).
package pkginstall

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/testcap"
	"io"
	"io/fs"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/auth"
)

// loopbackJar treats the loopback API as a secure context, as browsers do:
// the session is a Secure __Host- cookie even on http://127.0.0.1.
type loopbackJar struct{ http.CookieJar }

func secureURL(u *url.URL) *url.URL {
	c := *u
	c.Scheme = "https"
	return &c
}
func (j loopbackJar) SetCookies(u *url.URL, cs []*http.Cookie) {
	j.CookieJar.SetCookies(secureURL(u), cs)
}
func (j loopbackJar) Cookies(u *url.URL) []*http.Cookie { return j.CookieJar.Cookies(secureURL(u)) }

var units = []string{"hostd", "auditd", "secretd", "artifactd", "buildkitd", "builderd", "runtimed", "caddy", "routemgr", "egressd", "platformd"}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

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
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		h, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(rel)
		if d.IsDir() {
			h.Name += "/"
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if d.Type().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			_, err = tw.Write(b)
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()
	return &buf
}

func journal(t *testing.T, unit string) {
	out, _ := exec.Command("journalctl", "--no-pager", "-n", "80", "-u", "opendeploy-"+unit+".service").CombinedOutput()
	t.Logf("journal %s:\n%s", unit, out)
}

func TestInstalledNode(t *testing.T) {
	if os.Geteuid() != 0 {
		testcap.Blocked(t, "run as root on a host where the package is installed")
	}
	api := env("OPENDEPLOY_URL", "http://127.0.0.1:8080")

	t.Run("units", func(t *testing.T) {
		deadline := time.Now().Add(90 * time.Second)
		for _, u := range units {
			for {
				out, _ := exec.Command("systemctl", "is-active", "opendeploy-"+u+".service").Output()
				if strings.TrimSpace(string(out)) == "active" {
					break
				}
				if time.Now().After(deadline) {
					journal(t, u)
					t.Fatalf("opendeploy-%s is %s", u, strings.TrimSpace(string(out)))
				}
				time.Sleep(time.Second)
			}
		}
		// SC-10: services run under their own identities, only hostd as root.
		for _, u := range units {
			out, err := exec.Command("systemctl", "show", "-p", "User", "--value", "opendeploy-"+u+".service").Output()
			if err != nil {
				t.Fatal(err)
			}
			user := strings.TrimSpace(string(out))
			if (u == "hostd") != (user == "root") {
				t.Errorf("opendeploy-%s runs as %q", u, user)
			}
		}
	})

	t.Run("dashboard", func(t *testing.T) {
		deadline := time.Now().Add(60 * time.Second)
		for {
			res, err := http.Get(api + "/healthz")
			if err == nil && res.StatusCode == 200 {
				res.Body.Close()
				break
			}
			if time.Now().After(deadline) {
				journal(t, "platformd")
				t.Fatalf("platformd never became healthy: %v", err)
			}
			time.Sleep(time.Second)
		}
		res, err := http.Get(api + "/")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 || !strings.Contains(string(b), `id="root"`) || res.Header.Get("Content-Security-Policy") == "" {
			t.Fatalf("dashboard: %d csp=%q", res.StatusCode, res.Header.Get("Content-Security-Policy"))
		}
	})

	t.Run("deploy", func(t *testing.T) {
		tok, err := exec.Command("opendeployctl", "admin", "bootstrap-token").Output()
		if err != nil {
			t.Fatalf("bootstrap token: %v", err)
		}
		jar, _ := cookiejar.New(nil)
		c := &client{t: t, base: api, hc: &http.Client{Jar: loopbackJar{jar}, Timeout: 5 * time.Minute}}
		var sess struct {
			CSRFToken string `json:"csrf_token"`
		}
		if c.json("POST", "/api/v2/auth/bootstrap", map[string]string{"token": strings.TrimSpace(string(tok)),
			"email": "owner@example.com", "password": "correct horse battery staple"}, &sess) != 201 {
			t.Fatal("bootstrap")
		}
		c.csrf = sess.CSRFToken
		if _, err := os.Stat("/var/lib/opendeploy/platformd/bootstrap-token"); !os.IsNotExist(err) {
			t.Fatalf("spent bootstrap token still on disk: %v", err)
		}
		// Owners must enroll MFA before using the API (packaged nodes).
		var totp struct {
			Secret string `json:"secret"`
		}
		if c.json("POST", "/api/v2/auth/totp/enroll", nil, &totp) != 200 || totp.Secret == "" {
			t.Fatal("totp enroll")
		}
		code, _ := auth.TOTPCode(totp.Secret, time.Now())
		if c.json("POST", "/api/v2/auth/totp/confirm", map[string]string{"code": code}, nil) != 200 {
			t.Fatal("totp confirm")
		}
		domain := env("OPENDEPLOY_BASE_DOMAIN", "od.test")
		deployApp := func(t *testing.T, name, dir, want string) {
			c.t = t
			var created struct {
				Project struct {
					ID string `json:"id"`
				} `json:"project"`
			}
			if c.json("POST", "/api/v2/projects", map[string]any{"name": name}, &created) != 201 {
				t.Fatal("create project")
			}
			var dep struct {
				ID string `json:"id"`
			}
			if code := c.do("POST", "/api/v2/projects/"+created.Project.ID+"/deployments/upload", "application/gzip", tarGz(t, dir), &dep); code != 202 {
				t.Fatalf("upload %d", code)
			}
			var st string
			for deadline := time.Now().Add(15 * time.Minute); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
				var out struct {
					Deployment struct {
						Status string `json:"status"`
					} `json:"deployment"`
				}
				c.json("GET", "/api/v2/deployments/"+dep.ID, nil, &out)
				if st = out.Deployment.Status; st == "SUCCEEDED" || st == "FAILED" {
					break
				}
			}
			if st != "SUCCEEDED" {
				var logs []struct {
					Line string `json:"line"`
				}
				c.json("GET", "/api/v2/deployments/"+dep.ID+"/logs", nil, &logs)
				for _, l := range logs {
					t.Log(l.Line)
				}
				for _, u := range []string{"builderd", "buildkitd", "runtimed", "platformd"} {
					journal(t, u)
				}
				t.Fatalf("deployment ended in %s", st)
			}
			req, _ := http.NewRequest("GET", "http://127.0.0.1:80/", nil)
			req.Host = fmt.Sprintf("%s.%s", name, env("OPENDEPLOY_BASE_DOMAIN", "od.test"))
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode != 200 || !strings.Contains(string(body), want) {
				t.Fatalf("GET %s -> %d %q", req.Host, res.StatusCode, body)
			}
		}
		for _, a := range []struct{ name, dir, want string }{
			{"static", "../e2e/fixtures/static", "hello from static"},
			{"node", "../e2e/fixtures/node", "hello from node"},
		} {
			t.Run(a.name, func(t *testing.T) { deployApp(t, a.name, a.dir, a.want) })
		}

		// Chaos: Tier-0 services die or restart underneath a serving node.
		// Apps must keep (or quickly resume) serving without intervention,
		// and the node must still deploy afterwards.
		t.Run("chaos", func(t *testing.T) {
			c.t = t
			host := "static." + domain
			serving := func() bool {
				req, _ := http.NewRequest("GET", "http://127.0.0.1:80/", nil)
				req.Host = host
				res, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
				if err != nil {
					return false
				}
				b, _ := io.ReadAll(res.Body)
				res.Body.Close()
				return res.StatusCode == 200 && strings.Contains(string(b), "hello from static")
			}
			waitFor := func(what string, cond func() bool) {
				t.Helper()
				for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
					if cond() {
						return
					}
				}
				for _, u := range []string{"caddy", "routemgr", "platformd"} {
					journal(t, u)
				}
				t.Fatalf("%s: did not recover within 90s", what)
			}
			healthy := func() bool {
				res, err := (&http.Client{Timeout: 3 * time.Second}).Get(api + "/healthz")
				if err != nil {
					return false
				}
				res.Body.Close()
				return res.StatusCode == 200
			}
			systemctl := func(args ...string) {
				t.Helper()
				if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
					t.Fatalf("systemctl %v: %v %s", args, err, out)
				}
			}
			if !serving() {
				t.Fatal("static app not deployed; the deploy/static subtest must pass first")
			}
			// Caddy restarts on its own and comes back with only its
			// bootstrap config: routemgr's watchdog reloads the routes.
			systemctl("restart", "opendeploy-caddy.service")
			waitFor("app after Caddy restart", serving)
			// The control plane is killed; apps keep serving throughout.
			systemctl("kill", "--signal=KILL", "opendeploy-platformd.service")
			if !serving() {
				t.Fatal("app stopped serving when platformd died")
			}
			waitFor("platformd after SIGKILL", healthy)
			// routemgr restarts: it restores last-known-good at start.
			systemctl("restart", "opendeploy-routemgr.service")
			waitFor("app after routemgr restart", serving)
			// Whole node restart (e.g. host reboot of the services).
			systemctl("restart", "opendeploy.target")
			waitFor("API after full restart", healthy)
			waitFor("app after full restart", serving)
			// Sessions survive restarts and the node still deploys.
			deployApp(t, "static-after-chaos", "../e2e/fixtures/static", "hello from static")
		})
	})
}
