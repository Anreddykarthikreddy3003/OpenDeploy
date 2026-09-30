package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/build/detect"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/policy"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/router"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/schema"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/services"
)

// Version is set at link time.
var Version = "dev"

type command struct {
	name, args, help string
	run              func(ctx context.Context, args []string) error
}

var commands []command

func init() {
	commands = []command{
		{"login", "--url URL --token TOKEN", "store credentials for this node", cmdLogin},
		{"whoami", "", "show the authenticated user", cmdWhoami},
		{"projects", "", "list projects", cmdProjects},
		{"create", "NAME --repo URL [--branch B] [--root DIR] [--no-deploy]", "create a project from a public Git URL", cmdCreate},
		{"status", "PROJECT", "environments, URLs and current deployments", cmdStatus},
		{"deployments", "PROJECT [--env NAME]", "list deployments", cmdDeployments},
		{"deploy", "PROJECT [--env NAME] [--branch B | --sha SHA] [--no-follow]", "deploy from Git and follow the build", cmdDeploy},
		{"upload", "PROJECT [DIR] [--env NAME] [--no-follow]", "deploy a local directory (no Git needed)", cmdUpload},
		{"logs", "DEPLOYMENT [-f]", "build logs of a deployment", cmdLogs},
		{"runtime-logs", "PROJECT [--env NAME] [--tail N]", "runtime output of the serving deployment", cmdRuntimeLogs},
		{"rollback", "DEPLOYMENT", "roll back to a previous deployment (no rebuild)", simpleAction("rollback")},
		{"cancel", "DEPLOYMENT", "cancel a running deployment", simpleAction("cancel")},
		{"promote", "DEPLOYMENT", "promote a READY deployment", simpleAction("promote")},
		{"env", "list|set|rm PROJECT [KEY=VALUE...|KEY] [--env NAME] [--scope environment|project|preview]", "manage environment variables", cmdEnv},
		{"domains", "list|add|verify PROJECT|DOMAIN [HOST] [--env NAME]", "manage custom domains", cmdDomains},
		{"plan", "[DIR]", "show how a local directory would be built (offline detection)", cmdPlan},
		{"admin", "bootstrap-token|caddy-config [--config PATH]", "node admin helpers (run on the node)", cmdAdmin},
		{"restore", "[--from DIR] [--id ID|latest] --master-key FILE [--signer B64] [--list] [--force]", "restore a node from an encrypted backup (services stopped)", cmdRestore},
		{"doctor", "", "check host capabilities for OpenDeploy", cmdDoctor},
		{"dev", "[--port 8080] [--data DIR]", "run a single-process development node with the dashboard", cmdDev},
		{"version", "", "print the version", func(context.Context, []string) error {
			fmt.Printf("opendeployctl %s schema=%d\n", Version, schema.Version)
			return nil
		}},
	}
}

// Main runs the CLI and returns the exit code.
func Main(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage()
		return 0
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	for _, c := range commands {
		if c.name == args[0] {
			if err := c.run(ctx, args[1:]); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return 0
				}
				fmt.Fprintln(os.Stderr, "error:", err)
				return 1
			}
			return 0
		}
	}
	fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
	usage()
	return 2
}

func usage() {
	fmt.Println("opendeployctl — OpenDeploy command-line client\n\nUsage:")
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	for _, c := range commands {
		fmt.Fprintf(w, "  %s %s\t%s\n", c.name, c.args, c.help)
	}
	w.Flush()
	fmt.Println("\nEnvironment: OPENDEPLOY_URL, OPENDEPLOY_TOKEN override the stored login.")
}

// parse separates flags from positional arguments (flags may follow them).
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) > 0 {
			pos = append(pos, args[0])
			args = args[1:]
		}
	}
	return pos, nil
}

func table(rows [][]string) {
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	for _, r := range rows {
		fmt.Fprintln(w, strings.Join(r, "\t"))
	}
	w.Flush()
}

func short(s string, n int) string {
	s = strings.SplitN(s, "\n", 2)[0]
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

// ---- API shapes (subset) -------------------------------------------------------

type project struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	RepoFullName     string `json:"repo_full_name"`
	ProductionBranch string `json:"production_branch"`
	TrustClass       string `json:"trust_class"`
	URL              string `json:"url"`
}

type deployment struct {
	ID            string `json:"id"`
	EnvironmentID string `json:"environment_id"`
	Generation    int64  `json:"generation"`
	Trigger       string `json:"trigger"`
	CommitSHA     string `json:"commit_sha"`
	CommitMessage string `json:"commit_message"`
	Branch        string `json:"branch"`
	Status        string `json:"status"`
	Error         string `json:"error"`
	CreatedAt     string `json:"created_at"`
}

type envSummary struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	Kind    string      `json:"kind"`
	Branch  string      `json:"branch"`
	URL     string      `json:"url"`
	Domains []string    `json:"domains"`
	Current *deployment `json:"current_deployment"`
	Latest  *deployment `json:"latest_deployment"`
}

func terminal(s string) bool {
	switch s {
	case "SUCCEEDED", "FAILED", "SUPERSEDED", "CANCELLED":
		return true
	}
	return false
}

// resolveProject accepts a project name or ID.
func resolveProject(ctx context.Context, c *Client, ref string) (*project, error) {
	var ps []project
	if err := c.Do(ctx, "GET", "/api/v2/projects", nil, &ps); err != nil {
		return nil, err
	}
	for i := range ps {
		if ps[i].ID == ref || ps[i].Name == ref {
			return &ps[i], nil
		}
	}
	return nil, fmt.Errorf("project %q not found", ref)
}

// ---- commands -----------------------------------------------------------------------

func cmdLogin(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	u := fs.String("url", "", "node URL, e.g. https://opendeploy.example.com")
	tok := fs.String("token", "", "API token (odt_...); '-' reads it from stdin")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *tok == "-" {
		b, _ := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		*tok = strings.TrimSpace(string(b))
	}
	if *u == "" || !strings.HasPrefix(*tok, "odt_") {
		return errors.New("--url and an odt_ --token are required")
	}
	if pu, err := url.Parse(*u); err != nil || (pu.Scheme != "https" && pu.Scheme != "http") {
		return errors.New("invalid --url")
	} else if pu.Scheme == "http" && !strings.HasPrefix(pu.Host, "127.0.0.1") && !strings.HasPrefix(pu.Host, "localhost") && !strings.HasPrefix(pu.Host, "[::1]") {
		fmt.Fprintln(os.Stderr, "warning: sending an API token over plain HTTP to a non-loopback host")
	}
	c := &Client{Base: strings.TrimSuffix(*u, "/"), Token: *tok, HC: &http.Client{Timeout: 30 * time.Second}}
	var me struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
		Token string `json:"token"`
	}
	if err := c.Do(ctx, "GET", "/api/v2/auth/me", nil, &me); err != nil {
		return fmt.Errorf("token check failed: %w", err)
	}
	if err := (&Profile{URL: c.Base, Token: *tok}).Save(); err != nil {
		return err
	}
	fmt.Printf("Logged in to %s as %s (token %q). Credentials saved to %s\n", c.Base, me.User.Email, me.Token, configPath())
	return nil
}

func cmdWhoami(ctx context.Context, _ []string) error {
	c, err := NewClient()
	if err != nil {
		return err
	}
	var me map[string]any
	if err := c.Do(ctx, "GET", "/api/v2/auth/me", nil, &me); err != nil {
		return err
	}
	u, _ := me["user"].(map[string]any)
	fmt.Printf("%v (%v) via token %v at %s\n", u["email"], u["role"], me["token"], c.Base)
	return nil
}

func cmdProjects(ctx context.Context, _ []string) error {
	c, err := NewClient()
	if err != nil {
		return err
	}
	var ps []project
	if err := c.Do(ctx, "GET", "/api/v2/projects", nil, &ps); err != nil {
		return err
	}
	rows := [][]string{{"NAME", "REPOSITORY", "BRANCH", "TRUST", "URL"}}
	for _, p := range ps {
		rows = append(rows, []string{p.Name, p.RepoFullName, p.ProductionBranch, p.TrustClass, p.URL})
	}
	table(rows)
	return nil
}

func cmdCreate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	repo := fs.String("repo", "", "public Git HTTPS URL (omit for an upload-only project)")
	branch := fs.String("branch", "", "production branch")
	root := fs.String("root", "", "root directory within the repository")
	noDeploy := fs.Bool("no-deploy", false, "do not deploy immediately")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: create NAME --repo URL")
	}
	c, err := NewClient()
	if err != nil {
		return err
	}
	deploy := !*noDeploy
	var out struct {
		Project    project     `json:"project"`
		Deployment *deployment `json:"deployment"`
	}
	if err := c.Do(ctx, "POST", "/api/v2/projects", map[string]any{"name": pos[0], "clone_url": *repo, "production_branch": *branch, "root_dir": *root, "deploy_now": deploy}, &out); err != nil {
		return err
	}
	fmt.Printf("Created project %s (%s)\n", out.Project.Name, out.Project.ID)
	if out.Deployment != nil {
		return follow(ctx, c, out.Deployment.ID)
	}
	return nil
}

func cmdStatus(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: status PROJECT")
	}
	c, err := NewClient()
	if err != nil {
		return err
	}
	p, err := resolveProject(ctx, c, args[0])
	if err != nil {
		return err
	}
	var d struct {
		Environments []envSummary `json:"environments"`
	}
	if err := c.Do(ctx, "GET", "/api/v2/projects/"+p.ID, nil, &d); err != nil {
		return err
	}
	rows := [][]string{{"ENVIRONMENT", "BRANCH", "SERVING", "LATEST", "URL"}}
	for _, e := range d.Environments {
		cur, latest := "-", "-"
		if e.Current != nil {
			cur = fmt.Sprintf("#%d %s", e.Current.Generation, short(e.Current.CommitSHA, 8))
		}
		if e.Latest != nil {
			latest = fmt.Sprintf("#%d %s", e.Latest.Generation, e.Latest.Status)
		}
		urls := append([]string{e.URL}, e.Domains...)
		rows = append(rows, []string{e.Name, e.Branch, cur, latest, strings.Join(urls, " ")})
	}
	table(rows)
	return nil
}

func cmdDeployments(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("deployments", flag.ContinueOnError)
	env := fs.String("env", "", "environment name")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: deployments PROJECT")
	}
	c, err := NewClient()
	if err != nil {
		return err
	}
	p, err := resolveProject(ctx, c, pos[0])
	if err != nil {
		return err
	}
	q := "?limit=30"
	if *env != "" {
		q += "&environment=" + url.QueryEscape(*env)
	}
	var ds []deployment
	if err := c.Do(ctx, "GET", "/api/v2/projects/"+p.ID+"/deployments"+q, nil, &ds); err != nil {
		return err
	}
	rows := [][]string{{"ID", "GEN", "STATUS", "TRIGGER", "COMMIT", "MESSAGE", "CREATED"}}
	for _, d := range ds {
		rows = append(rows, []string{d.ID, fmt.Sprint(d.Generation), d.Status, d.Trigger, short(d.CommitSHA, 8), short(d.CommitMessage, 50), d.CreatedAt[:min(19, len(d.CreatedAt))]})
	}
	table(rows)
	return nil
}

func cmdDeploy(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	env := fs.String("env", "production", "environment")
	branch := fs.String("branch", "", "branch to deploy")
	sha := fs.String("sha", "", "exact commit SHA")
	noFollow := fs.Bool("no-follow", false, "do not stream the build")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: deploy PROJECT")
	}
	c, err := NewClient()
	if err != nil {
		return err
	}
	p, err := resolveProject(ctx, c, pos[0])
	if err != nil {
		return err
	}
	var d deployment
	if err := c.Do(ctx, "POST", "/api/v2/projects/"+p.ID+"/deployments", map[string]string{"environment": *env, "branch": *branch, "sha": *sha}, &d); err != nil {
		return err
	}
	fmt.Printf("Deployment %s (generation %d) queued\n", d.ID, d.Generation)
	if *noFollow {
		return nil
	}
	return follow(ctx, c, d.ID)
}

func cmdUpload(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("upload", flag.ContinueOnError)
	env := fs.String("env", "production", "environment")
	noFollow := fs.Bool("no-follow", false, "do not stream the build")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 || len(pos) > 2 {
		return errors.New("usage: upload PROJECT [DIR]")
	}
	dir := "."
	if len(pos) == 2 {
		dir = pos[1]
	}
	c, err := NewClient()
	if err != nil {
		return err
	}
	p, err := resolveProject(ctx, c, pos[0])
	if err != nil {
		return err
	}
	pr, pw := io.Pipe()
	var count int
	go func() {
		n, err := writeSourceArchive(pw, dir)
		count = n
		pw.CloseWithError(err)
	}()
	var d deployment
	if err := c.Upload(ctx, "/api/v2/projects/"+p.ID+"/deployments/upload?environment="+url.QueryEscape(*env), pr, &d); err != nil {
		return err
	}
	fmt.Printf("Uploaded %d files; deployment %s (generation %d) queued\n", count, d.ID, d.Generation)
	if *noFollow {
		return nil
	}
	return follow(ctx, c, d.ID)
}

// ignored returns whether a relative path is excluded from uploads.
func ignored(rel string, patterns []string) bool {
	base := filepath.Base(rel)
	for _, p := range patterns {
		p = strings.TrimSuffix(p, "/")
		if ok, _ := filepath.Match(p, base); ok {
			return true
		}
		if ok, _ := filepath.Match(p, rel); ok {
			return true
		}
	}
	return false
}

// writeSourceArchive tars dir (regular files, dirs and in-tree symlinks),
// skipping VCS metadata, dependency folders and .opendeployignore patterns.
func writeSourceArchive(w io.Writer, dir string) (int, error) {
	patterns := []string{".git", "node_modules", ".venv", "__pycache__", ".DS_Store", ".env", ".env.*", "*.pem", "*.key"}
	if b, err := os.ReadFile(filepath.Join(dir, ".opendeployignore")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				patterns = append(patterns, l)
			}
		}
	}
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	n := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		if ignored(filepath.ToSlash(rel), patterns) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		link := ""
		if info.Mode()&os.ModeSymlink != 0 {
			if link, err = os.Readlink(p); err != nil {
				return err
			}
		} else if !info.Mode().IsRegular() && !info.IsDir() {
			return nil
		}
		h, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(rel)
		h.Uid, h.Gid, h.Uname, h.Gname = 0, 0, "", ""
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, f)
			f.Close()
			if err != nil {
				return err
			}
			n++
		}
		return nil
	})
	if err != nil {
		return n, err
	}
	if err := tw.Close(); err != nil {
		return n, err
	}
	return n, gz.Close()
}

// follow streams build logs and status until the deployment finishes.
func follow(ctx context.Context, c *Client, id string) error {
	final := ""
	err := c.SSE(ctx, "/api/v2/deployments/"+id+"/events", func(ev string, data []byte) bool {
		switch ev {
		case "log":
			var l struct {
				Line string `json:"line"`
			}
			if json.Unmarshal(data, &l) == nil {
				fmt.Println(l.Line)
			}
		case "status":
			var s struct {
				To      string `json:"to"`
				Message string `json:"message"`
			}
			if json.Unmarshal(data, &s) == nil {
				fmt.Fprintf(os.Stderr, "==> %s %s\n", s.To, s.Message)
				if terminal(s.To) {
					final = s.To
					return false
				}
			}
		}
		return true
	})
	if err != nil && ctx.Err() == nil {
		return err
	}
	if final == "" {
		// Stream ended: read the final state.
		var d struct {
			Deployment deployment `json:"deployment"`
			URL        string     `json:"url"`
		}
		if err := c.Do(context.Background(), "GET", "/api/v2/deployments/"+id, nil, &d); err == nil {
			final = d.Deployment.Status
		}
	}
	var d struct {
		Deployment deployment `json:"deployment"`
		URL        string     `json:"url"`
	}
	_ = c.Do(context.Background(), "GET", "/api/v2/deployments/"+id, nil, &d)
	switch final {
	case "SUCCEEDED":
		fmt.Printf("\nDeployed: %s\n", d.URL)
		return nil
	case "":
		return nil
	default:
		if d.Deployment.Error != "" {
			return fmt.Errorf("deployment %s: %s", strings.ToLower(final), d.Deployment.Error)
		}
		return fmt.Errorf("deployment %s", strings.ToLower(final))
	}
}

func cmdLogs(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	f := fs.Bool("f", false, "follow until the deployment finishes")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: logs DEPLOYMENT [-f]")
	}
	c, err := NewClient()
	if err != nil {
		return err
	}
	if *f {
		return follow(ctx, c, pos[0])
	}
	var lines []struct {
		Line string `json:"line"`
	}
	if err := c.Do(ctx, "GET", "/api/v2/deployments/"+pos[0]+"/logs", nil, &lines); err != nil {
		return err
	}
	for _, l := range lines {
		fmt.Println(l.Line)
	}
	return nil
}

func cmdRuntimeLogs(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("runtime-logs", flag.ContinueOnError)
	env := fs.String("env", "production", "environment")
	tail := fs.Int("tail", 200, "lines per workload")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: runtime-logs PROJECT")
	}
	c, err := NewClient()
	if err != nil {
		return err
	}
	p, err := resolveProject(ctx, c, pos[0])
	if err != nil {
		return err
	}
	var d struct {
		Environments []envSummary `json:"environments"`
	}
	if err := c.Do(ctx, "GET", "/api/v2/projects/"+p.ID, nil, &d); err != nil {
		return err
	}
	for _, e := range d.Environments {
		if e.Name != *env {
			continue
		}
		var lines []struct {
			Workload string `json:"workload"`
			Time     string `json:"time"`
			Text     string `json:"text"`
		}
		if err := c.Do(ctx, "GET", fmt.Sprintf("/api/v2/environments/%s/logs?tail=%d", e.ID, *tail), nil, &lines); err != nil {
			return err
		}
		for _, l := range lines {
			fmt.Printf("%s %s | %s\n", l.Time, l.Workload, l.Text)
		}
		return nil
	}
	return fmt.Errorf("environment %q not found", *env)
}

func simpleAction(action string) func(context.Context, []string) error {
	return func(ctx context.Context, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("usage: %s DEPLOYMENT", action)
		}
		c, err := NewClient()
		if err != nil {
			return err
		}
		var out map[string]any
		if err := c.Do(ctx, "POST", "/api/v2/deployments/"+args[0]+"/"+action, map[string]any{}, &out); err != nil {
			return err
		}
		if id, ok := out["id"].(string); ok && id != args[0] {
			fmt.Printf("%s: new deployment %s (generation %v)\n", action, id, out["generation"])
			return follow(ctx, c, id)
		}
		fmt.Println(action, "requested")
		return nil
	}
}

func cmdEnv(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("env", flag.ContinueOnError)
	env := fs.String("env", "production", "environment")
	scope := fs.String("scope", "environment", "environment | project | preview")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 2 {
		return errors.New("usage: env list|set|rm PROJECT ...")
	}
	c, err := NewClient()
	if err != nil {
		return err
	}
	p, err := resolveProject(ctx, c, pos[1])
	if err != nil {
		return err
	}
	q := "scope=" + url.QueryEscape(*scope)
	if *scope == "environment" {
		q += "&environment=" + url.QueryEscape(*env)
	}
	switch pos[0] {
	case "list", "ls":
		var ms []struct {
			Name      string `json:"name"`
			Version   int64  `json:"version"`
			Sensitive bool   `json:"sensitive"`
			CreatedAt string `json:"created_at"`
		}
		if err := c.Do(ctx, "GET", "/api/v2/projects/"+p.ID+"/secrets?"+q, nil, &ms); err != nil {
			return err
		}
		rows := [][]string{{"NAME", "VERSION", "SENSITIVE", "UPDATED"}}
		for _, m := range ms {
			rows = append(rows, []string{m.Name, fmt.Sprint(m.Version), fmt.Sprint(m.Sensitive), m.CreatedAt})
		}
		table(rows)
	case "set":
		if len(pos) < 3 {
			return errors.New("usage: env set PROJECT KEY=VALUE... (VALUE '-' reads stdin)")
		}
		for _, kv := range pos[2:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || !policy.ValidEnvName(k) {
				return fmt.Errorf("invalid assignment %q", kv)
			}
			if v == "-" {
				b, _ := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
				v = strings.TrimRight(string(b), "\n")
			}
			if err := c.Do(ctx, "PUT", "/api/v2/projects/"+p.ID+"/secrets", map[string]any{"scope": *scope, "environment": *env, "name": k, "value": v, "sensitive": true}, nil); err != nil {
				return err
			}
			fmt.Println("set", k)
		}
		fmt.Println("Redeploy to apply the new values to running workloads.")
	case "rm", "unset":
		for _, k := range pos[2:] {
			if err := c.Do(ctx, "DELETE", "/api/v2/projects/"+p.ID+"/secrets?"+q+"&name="+url.QueryEscape(k), nil, nil); err != nil {
				return err
			}
			fmt.Println("removed", k)
		}
	default:
		return fmt.Errorf("unknown env action %q", pos[0])
	}
	return nil
}

func cmdDomains(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("domains", flag.ContinueOnError)
	env := fs.String("env", "production", "environment")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 2 {
		return errors.New("usage: domains list|add PROJECT [HOST] | domains verify DOMAIN_ID")
	}
	c, err := NewClient()
	if err != nil {
		return err
	}
	type instr struct {
		TXTName  string `json:"txt_name"`
		TXTValue string `json:"txt_value"`
		Routing  struct {
			IPs   []string `json:"ips"`
			Hosts []string `json:"hosts"`
		} `json:"routing"`
		Note string `json:"note"`
	}
	type dom struct {
		ID           string `json:"id"`
		Hostname     string `json:"hostname"`
		Status       string `json:"status"`
		TLSStatus    string `json:"tls_status"`
		Instructions *instr `json:"instructions"`
	}
	printInstr := func(d dom) {
		if d.Instructions == nil {
			return
		}
		i := d.Instructions
		fmt.Printf("\nPublish at your DNS provider, then run `opendeployctl domains verify %s`:\n", d.ID)
		fmt.Printf("  TXT    %s\n         %q\n", i.TXTName, i.TXTValue)
		for _, h := range i.Routing.Hosts {
			fmt.Printf("  CNAME  %s -> %s\n", d.Hostname, h)
		}
		for _, ip := range i.Routing.IPs {
			fmt.Printf("  A/AAAA %s -> %s\n", d.Hostname, ip)
		}
		if i.Note != "" {
			fmt.Println(" ", i.Note)
		}
	}
	switch pos[0] {
	case "list", "ls":
		p, err := resolveProject(ctx, c, pos[1])
		if err != nil {
			return err
		}
		var ds []dom
		if err := c.Do(ctx, "GET", "/api/v2/projects/"+p.ID+"/domains", nil, &ds); err != nil {
			return err
		}
		rows := [][]string{{"ID", "HOST", "STATUS", "TLS"}}
		for _, d := range ds {
			rows = append(rows, []string{d.ID, d.Hostname, d.Status, d.TLSStatus})
		}
		table(rows)
	case "add":
		if len(pos) != 3 {
			return errors.New("usage: domains add PROJECT HOST")
		}
		p, err := resolveProject(ctx, c, pos[1])
		if err != nil {
			return err
		}
		var d dom
		if err := c.Do(ctx, "POST", "/api/v2/projects/"+p.ID+"/domains", map[string]string{"hostname": pos[2], "environment": *env}, &d); err != nil {
			return err
		}
		fmt.Printf("Claim %s created for %s\n", d.ID, d.Hostname)
		printInstr(d)
	case "verify":
		var out struct {
			Domain dom `json:"domain"`
			Check  struct {
				Ownership string `json:"ownership"`
			} `json:"check"`
		}
		err := c.Do(ctx, "POST", "/api/v2/domains/"+pos[1]+"/verify", map[string]any{}, &out)
		if err != nil {
			return err
		}
		fmt.Printf("%s is attached (%s). HTTPS will be provisioned automatically.\n", out.Domain.Hostname, out.Check.Ownership)
	default:
		return fmt.Errorf("unknown domains action %q", pos[0])
	}
	return nil
}

func cmdPlan(_ context.Context, args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	var cfg *policy.Config
	if b, err := os.ReadFile(filepath.Join(dir, "opendeploy.yaml")); err == nil {
		c, err := policy.Parse(b)
		if err != nil {
			return fmt.Errorf("opendeploy.yaml: %w", err)
		}
		cfg = c
	}
	p, err := detect.Detect(dir, detect.Options{Config: cfg})
	if err != nil {
		return err
	}
	fmt.Printf("Strategy:  %s\nStack:     %s %s\nPort:      %d\n", p.Strategy, p.Stack, p.Framework, p.Port)
	if p.StaticOutput {
		fmt.Printf("Static:    %s\n", p.StaticDir)
	}
	if p.BuildCommand != "" {
		fmt.Printf("Build:     %s\n", p.BuildCommand)
	}
	if p.StartCommand != "" {
		fmt.Printf("Start:     %s\n", p.StartCommand)
	}
	for _, r := range p.Reasons {
		fmt.Println("  -", r)
	}
	for _, w := range p.Warnings {
		fmt.Println("  !", w)
	}
	if p.Generated && p.DockerfileContent != "" {
		fmt.Println("\n--- generated Dockerfile ---")
		fmt.Print(p.DockerfileContent)
	}
	return nil
}

func cmdAdmin(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	cfgPath := fs.String("config", config.DefaultPath, "node configuration")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || (pos[0] != "bootstrap-token" && pos[0] != "caddy-config") {
		return errors.New("usage: admin bootstrap-token|caddy-config [--config PATH]")
	}
	n, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if pos[0] == "caddy-config" {
		// Bootstrap config for the edge: admin API on the private socket
		// only; routemgr pushes the full configuration.
		fmt.Println(string(router.BootstrapConfig(n.Ingress.CaddyAdmin)))
		return nil
	}
	b, err := os.ReadFile(services.BootstrapTokenPath(n))
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("no bootstrap token: the owner account already exists (or platformd has not started yet)")
	}
	if err != nil {
		return fmt.Errorf("%w (run as root or the platformd user)", err)
	}
	fmt.Println(strings.TrimSpace(string(b)))
	return nil
}
