package platform

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/model"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/network"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/policy"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/runtime"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/secrets"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// ensureEnvNetwork creates the environment network and applies egress policy.
func (p *Platform) ensureEnvNetwork(ctx context.Context, proj *store.Project, env *store.Environment, cfg *policy.Config) (*runtime.NetworkInfo, error) {
	ni, err := p.Runtime.EnsureNetwork(ctx, runtime.NetworkSpec{EnvironmentID: env.ID, ProjectID: proj.ID, Kind: env.Kind})
	if err != nil {
		return nil, fmt.Errorf("environment network: %w", err)
	}
	pol := network.EnvPolicy{EnvironmentID: env.ID, ProjectID: proj.ID, Kind: env.Kind, Bridge: ni.Bridge, Subnet: ni.Subnet, Gateway: ni.Gateway,
		Internet: cfg.Egress.Internet == nil || *cfg.Egress.Internet, AllowHosts: cfg.Egress.AllowHosts}
	if env.Kind != "preview" && !env.PRFromFork {
		// Private-network egress is an administrator decision recorded in the
		// project's config override; the repository cannot enable it for
		// previews or forks.
		pol.AllowPrivate = cfg.Egress.AllowPrivateNetworks && proj.ConfigOverride != ""
	}
	if pol.Bridge != "" && pol.Subnet != "" {
		if err := p.Egress.Apply(ctx, pol); err != nil {
			return nil, fmt.Errorf("egress policy: %w", err)
		}
	}
	return ni, nil
}

func (p *Platform) startCandidate(ctx context.Context, d *store.Deployment, proj *store.Project, env *store.Environment) error {
	art, err := p.Store.GetArtifact(ctx, d.ArtifactID)
	if err != nil {
		return fmt.Errorf("artifact: %w", err)
	}
	if art.Kind == "static" {
		p.logf(ctx, d.ID, "deploy", "static artifact %s: no application process to start", art.Digest)
		return p.transition(ctx, d, model.StatusHealthChecking, "static artifact")
	}
	n, err := p.ensureDeploymentWorkloads(ctx, d, proj, env, true)
	if err != nil {
		return err
	}
	return p.transition(ctx, d, model.StatusHealthChecking, fmt.Sprintf("%d replica(s) started", n))
}

// ensureDeploymentWorkloads (re)starts every workload of a deployment. It is
// idempotent: running workloads are left alone, missing or exited ones are
// started again with the same identity. Used for candidates and by the
// reconciler to restore desired state after reboot.
func (p *Platform) ensureDeploymentWorkloads(ctx context.Context, d *store.Deployment, proj *store.Project, env *store.Environment, verbose bool) (int, error) {
	s, err := p.snapshot(d)
	if err != nil {
		return 0, err
	}
	art, err := p.Store.GetArtifact(ctx, d.ArtifactID)
	if err != nil {
		return 0, fmt.Errorf("artifact: %w", err)
	}
	cfg := &s.Config
	if _, err := p.ensureEnvNetwork(ctx, proj, env, cfg); err != nil {
		return 0, err
	}
	env2, err := p.ensureBackingServices(ctx, d, proj, env, cfg)
	if err != nil {
		return 0, err
	}
	mounts, err := p.volumeMounts(ctx, proj, env, cfg)
	if err != nil {
		return 0, err
	}
	var resolved map[string]string
	if p.Secrets != nil {
		r, err := p.Secrets.Resolve(ctx, secrets.ResolveReq{ProjectID: proj.ID, EnvironmentID: env.ID, EnvKind: env.Kind,
			TrustClass: d.TrustClass, Purpose: "runtime", FromFork: env.PRFromFork})
		if err != nil {
			return 0, fmt.Errorf("secrets: %w", err)
		}
		resolved = r.Values
	}
	mem, err := policy.ParseMemory(cfg.Resources.Memory)
	if err != nil {
		return 0, err
	}
	replicas := cfg.Runtime.Replicas
	if env.Kind == "preview" && replicas > 1 {
		replicas = 1
	}
	port := s.Plan.Port
	if cfg.Runtime.Type != policy.WorkloadWeb {
		port = 0
	} else if port == 0 {
		port = cfg.Runtime.Port
	}
	envVars := map[string]string{
		"OPENDEPLOY":             "1",
		"OPENDEPLOY_PROJECT":     proj.Name,
		"OPENDEPLOY_ENVIRONMENT": env.Name,
		"OPENDEPLOY_DEPLOYMENT":  d.ID,
		"OPENDEPLOY_COMMIT_SHA":  d.CommitSHA,
	}
	if env.GeneratedHostname != "" {
		envVars["OPENDEPLOY_URL"] = p.PublicURL(env.GeneratedHostname)
	}
	for k, v := range env2 {
		envVars[k] = v
	}
	if cfg.Egress.Internet != nil && !*cfg.Egress.Internet && len(cfg.Egress.AllowHosts) > 0 {
		// Allowlist-only egress goes through egressd's proxy on the gateway.
		if ni, err := p.Runtime.EnsureNetwork(ctx, runtime.NetworkSpec{EnvironmentID: env.ID, ProjectID: proj.ID, Kind: env.Kind}); err == nil && ni.Gateway != "" {
			proxy := "http://" + net.JoinHostPort(ni.Gateway, strconv.Itoa(p.egressProxyPort()))
			for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
				envVars[k] = proxy
			}
		}
	}
	if cfg.Runtime.SecretEnv == nil || *cfg.Runtime.SecretEnv {
		for k, v := range resolved {
			if runtimeEnvNameOK(k) {
				envVars[k] = v
			}
		}
	}
	for i := 0; i < replicas; i++ {
		w, err := p.Store.EnsureWorkload(ctx, d.ID, env.ID, "web", i, d.RuntimeClass)
		if err != nil {
			return 0, err
		}
		if cur, err := p.Runtime.Inspect(ctx, w.ID); err == nil && cur.State == "running" {
			if cur.Endpoint != w.Endpoint {
				_ = p.Store.UpdateWorkload(ctx, w.ID, w.State, cur.RuntimeID, cur.Endpoint)
			}
			continue
		}
		spec := runtime.Spec{ID: w.ID, ProjectID: proj.ID, EnvironmentID: env.ID, DeploymentID: d.ID, Service: "web", Kind: "app",
			Image: art.ImageRef, Runtime: d.RuntimeClass, Command: cfg.Runtime.Command, Env: envVars, SecretFiles: resolved,
			Port: port, MemoryBytes: mem, CPU: cfg.Resources.CPU, PIDs: cfg.Resources.PIDs,
			ReadOnlyRoot: cfg.Runtime.ReadOnlyRoot == nil || *cfg.Runtime.ReadOnlyRoot,
			Tmpfs:        append(append([]string{}, cfg.Runtime.TmpfsPaths...), s.Plan.Tmpfs...), Volumes: mounts, Network: env.ID,
			Capabilities: decisionCaps(s), Replica: i}
		if verbose {
			p.logf(ctx, d.ID, "deploy", "starting replica %d (%s, runtime %s)", i, w.ID, d.RuntimeClass)
		}
		rw, err := p.Runtime.Start(ctx, spec)
		if err != nil {
			_ = p.Store.UpdateWorkload(ctx, w.ID, "failed", "", "")
			return 0, fmt.Errorf("start replica %d: %w", i, err)
		}
		st := "running"
		if w.State == "healthy" {
			st = "healthy"
		}
		if err := p.Store.UpdateWorkload(ctx, w.ID, st, rw.RuntimeID, rw.Endpoint); err != nil {
			return 0, err
		}
	}
	return replicas, nil
}

func (p *Platform) egressProxyPort() int {
	_, port, err := net.SplitHostPort(p.Node.Egress.ProxyListen)
	if err != nil {
		return 3128
	}
	n, _ := strconv.Atoi(port)
	return n
}

func runtimeEnvNameOK(k string) bool {
	if k == "" || len(k) > 128 {
		return false
	}
	for i, c := range k {
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	switch strings.ToUpper(k) {
	case "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PORT":
		return false
	}
	return true
}

func decisionCaps(s *Snapshot) []string {
	if s.Decision == nil {
		return nil
	}
	return s.Decision.Capabilities
}

func (p *Platform) PublicURL(host string) string {
	if p.Node.Ingress.Mode == "lan" {
		if p.Node.Ingress.HTTPPort == 80 {
			return "http://" + host
		}
		return "http://" + net.JoinHostPort(host, strconv.Itoa(p.Node.Ingress.HTTPPort))
	}
	return "https://" + host
}

func (p *Platform) volumeMounts(ctx context.Context, proj *store.Project, env *store.Environment, cfg *policy.Config) ([]runtime.VolumeMount, error) {
	var out []runtime.VolumeMount
	if env.Kind == "preview" && len(cfg.Volumes) > 0 {
		// Previews get their own ephemeral volumes (never production data).
		p.Log.Info("preview uses isolated volumes", "env", env.ID)
	}
	for _, v := range cfg.Volumes {
		vol, err := p.Store.EnsureVolume(ctx, proj.ID, env.ID, v.Name, v.Mount, v.Backup)
		if err != nil {
			return nil, err
		}
		out = append(out, runtime.VolumeMount{VolumeID: vol.ID, Target: v.Mount})
	}
	return out, nil
}

// Backing service templates (PRD §8, §14.1): private to the environment
// network, never published, credentials generated and stored in secretd.
type template struct {
	image   string
	port    int
	dataDir string
	envKey  string
	mkEnv   func(user, pass, db string) map[string]string
	mkURL   func(host, user, pass, db string, port int) string
	uid     int
	tmpfs   []string
	mem     int64
}

var templates = map[string]template{
	"postgres": {image: runtime.TemplateImages["postgres"], port: 5432, dataDir: "/var/lib/postgresql/data", envKey: "DATABASE_URL", uid: 999,
		tmpfs: []string{"/var/run/postgresql"}, mem: 512 << 20,
		mkEnv: func(u, pw, db string) map[string]string {
			return map[string]string{"POSTGRES_USER": u, "POSTGRES_PASSWORD": pw, "POSTGRES_DB": db, "PGDATA": "/var/lib/postgresql/data/pgdata"}
		},
		mkURL: func(h, u, pw, db string, port int) string {
			return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", u, pw, h, port, db)
		}},
	"mysql": {image: runtime.TemplateImages["mysql"], port: 3306, dataDir: "/var/lib/mysql", envKey: "DATABASE_URL", uid: 999,
		tmpfs: []string{"/var/run/mysqld"}, mem: 768 << 20,
		mkEnv: func(u, pw, db string) map[string]string {
			return map[string]string{"MYSQL_USER": u, "MYSQL_PASSWORD": pw, "MYSQL_DATABASE": db, "MYSQL_RANDOM_ROOT_PASSWORD": "yes"}
		},
		mkURL: func(h, u, pw, db string, port int) string {
			return fmt.Sprintf("mysql://%s:%s@%s:%d/%s", u, pw, h, port, db)
		}},
	"redis": {image: runtime.TemplateImages["redis"], port: 6379, dataDir: "/data", envKey: "REDIS_URL", uid: 999, mem: 256 << 20,
		mkEnv: func(_, pw, _ string) map[string]string { return map[string]string{"REDIS_PASSWORD": pw} },
		mkURL: func(h, _, pw, _ string, port int) string { return fmt.Sprintf("redis://:%s@%s:%d/0", pw, h, port) }},
}

func randomSecret(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// ensureBackingServices starts the environment's backing services and
// returns connection env vars for the application.
func (p *Platform) ensureBackingServices(ctx context.Context, d *store.Deployment, proj *store.Project, env *store.Environment, cfg *policy.Config) (map[string]string, error) {
	out := map[string]string{}
	for _, sv := range cfg.Services {
		t, ok := templates[sv.Template]
		if !ok {
			return nil, fmt.Errorf("unsupported service template %q", sv.Template)
		}
		volName := sv.Volume
		if volName == "" {
			volName = sv.Name + "-data"
		}
		vol, err := p.Store.EnsureVolume(ctx, proj.ID, env.ID, volName, t.dataDir, "daily")
		if err != nil {
			return nil, err
		}
		credName := "OPENDEPLOY_SVC_" + strings.ToUpper(strings.ReplaceAll(sv.Name, "-", "_")) + "_PASSWORD"
		pass, err := p.serviceCredential(ctx, proj, env, credName)
		if err != nil {
			return nil, err
		}
		row := &store.ServiceRow{ProjectID: proj.ID, EnvironmentID: env.ID, Name: sv.Name, Template: sv.Template, Version: t.image,
			RuntimeClass: "runc", DesiredState: "running", VolumeID: vol.ID, CredentialsSecret: credName}
		if err := p.Store.UpsertService(ctx, row); err != nil {
			return nil, err
		}
		// Backing services are tracked by the services table (not deployment
		// workloads) and keep a stable runtime identity across deployments.
		wid := "wkl_" + strings.TrimPrefix(row.ID, "svc_")
		cmd := []string(nil)
		if sv.Template == "redis" {
			cmd = []string{"redis-server", "--requirepass", pass, "--appendonly", "yes", "--protected-mode", "yes"}
		}
		spec := runtime.Spec{ID: wid, ProjectID: proj.ID, EnvironmentID: env.ID, DeploymentID: d.ID, Service: sv.Name, Kind: "backing",
			Image: t.image, Runtime: "runc", Command: cmd, Env: t.mkEnv("app", pass, "app"), Port: t.port, MemoryBytes: t.mem, CPU: 1, PIDs: 512,
			ReadOnlyRoot: false, Tmpfs: t.tmpfs, Volumes: []runtime.VolumeMount{{VolumeID: vol.ID, Target: t.dataDir, OwnerUID: t.uid}}, Network: env.ID}
		rw, err := p.Runtime.Start(ctx, spec)
		if err != nil {
			return nil, fmt.Errorf("start service %s: %w", sv.Name, err)
		}
		_ = p.Store.SetServiceRuntime(ctx, row.ID, rw.RuntimeID, rw.Endpoint)
		key := t.envKey
		if len(cfg.Services) > 1 {
			key = strings.ToUpper(strings.ReplaceAll(sv.Name, "-", "_")) + "_URL"
		}
		out[key] = t.mkURL(sv.Name, "app", pass, "app", t.port)
		p.logf(ctx, d.ID, "deploy", "backing service %s (%s) ready on the private environment network as %s", sv.Name, sv.Template, key)
	}
	return out, nil
}

func (p *Platform) serviceCredential(ctx context.Context, proj *store.Project, env *store.Environment, name string) (string, error) {
	if p.Secrets == nil {
		return "", errors.New("secretd unavailable")
	}
	ref := secrets.Ref{Scope: secrets.ScopeEnvironment, ProjectID: proj.ID, EnvironmentID: env.ID, Name: name}
	metas, err := p.Secrets.List(ctx, secrets.ListReq{Scope: ref.Scope, ProjectID: ref.ProjectID, EnvironmentID: ref.EnvironmentID})
	if err != nil {
		return "", err
	}
	for _, m := range metas {
		if m.Name == name {
			r, err := p.Secrets.Reveal(ctx, secrets.RevealReq{ID: m.ID, ProjectID: proj.ID, Actor: secrets.Actor{Type: "service", ID: "platformd"}, Reason: "backing service credential"})
			if err != nil {
				return "", err
			}
			return r.Value, nil
		}
	}
	pass := randomSecret(24)
	if _, err := p.Secrets.Set(ctx, secrets.SetReq{Ref: ref, Value: pass, Sensitive: true, Actor: secrets.Actor{Type: "service", ID: "platformd"}}); err != nil {
		return "", err
	}
	return pass, nil
}

// ---------------------------------------------------------------- health

// HealthResult reports layered health evidence (SC-17).
type HealthResult struct {
	Startup   bool     `json:"startup"`
	Readiness bool     `json:"readiness"`
	Smoke     []string `json:"smoke"`
	Stable    bool     `json:"stable"`
}

func (p *Platform) checkHealth(ctx context.Context, d *store.Deployment, env *store.Environment) error {
	s, err := p.snapshot(d)
	if err != nil {
		return err
	}
	art, err := p.Store.GetArtifact(ctx, d.ArtifactID)
	if err != nil {
		return err
	}
	if art.Kind != "static" {
		ws, err := p.Store.WorkloadsForDeployment(ctx, d.ID)
		if err != nil {
			return err
		}
		if len(ws) == 0 {
			return errors.New("no workloads for candidate")
		}
		for _, w := range ws {
			if err := p.probeWorkload(ctx, d, w, &s.Config); err != nil {
				p.appendWorkloadLogs(ctx, d.ID, w.ID)
				return err
			}
			_ = p.Store.UpdateWorkload(ctx, w.ID, "healthy", "", "")
		}
	}
	auto := s.Config.Release.AutoPromote == nil || *s.Config.Release.AutoPromote
	if d.Trigger == "rollback" {
		auto = true // an explicit rollback is a promotion request
	}
	if !auto {
		return p.transition(ctx, d, model.StatusReady, "healthy; awaiting manual promotion")
	}
	return p.promote(ctx, d)
}

func (p *Platform) appendWorkloadLogs(ctx context.Context, depID, wid string) {
	lines, err := p.Runtime.Logs(ctx, wid, 50, time.Time{})
	if err != nil || len(lines) == 0 {
		return
	}
	out := make([]string, 0, len(lines)+1)
	out = append(out, "---- last application output ----")
	for _, l := range lines {
		out = append(out, "["+l.Stream+"] "+l.Text)
	}
	_ = p.Store.AppendLogs(ctx, depID, "runtime", out)
}

func (p *Platform) probeWorkload(ctx context.Context, d *store.Deployment, w *store.WorkloadRow, cfg *policy.Config) error {
	grace := 60 * time.Second
	if cfg.Health.Startup != nil && cfg.Health.Startup.Grace.Duration > 0 {
		grace = cfg.Health.Startup.Grace.Duration
	}
	deadline := time.Now().Add(grace)
	// Worker processes: must stay running without restarts.
	if cfg.Runtime.Type != policy.WorkloadWeb || w.Endpoint == "" {
		if cfg.Runtime.Type == policy.WorkloadWeb {
			return errors.New("web workload has no network endpoint")
		}
		time.Sleep(minDur(10*time.Second, grace))
		rw, err := p.Runtime.Inspect(ctx, w.ID)
		if err != nil {
			return err
		}
		if rw.State != "running" || rw.Restarts > 0 {
			return fmt.Errorf("worker is %s (restarts %d, exit %d)", rw.State, rw.Restarts, rw.ExitCode)
		}
		return nil
	}
	// 1. Startup: the process accepts connections (or answers the startup path).
	startupPath := ""
	if cfg.Health.Startup != nil {
		startupPath = cfg.Health.Startup.Path
	}
	p.logf(ctx, d.ID, "deploy", "health: waiting up to %s for %s to start", grace, w.ID)
	for {
		if err := p.checkRunning(ctx, w.ID); err != nil {
			return err
		}
		var ok bool
		if startupPath != "" {
			code, _, err := p.httpProbe(ctx, w.Endpoint, "GET", startupPath)
			ok = err == nil && code >= 200 && code < 400
		} else {
			c, err := net.DialTimeout("tcp", w.Endpoint, 2*time.Second)
			if err == nil {
				c.Close()
				ok = true
			}
		}
		if ok {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("startup check failed: %s did not accept connections within %s", w.Endpoint, grace)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	// 2. Readiness: configured path must return 2xx; without one, the root
	// must answer without a server error. Two consecutive passes required.
	path, strict := "/", false
	if cfg.Health.Readiness != nil && cfg.Health.Readiness.Path != "" {
		path, strict = cfg.Health.Readiness.Path, true
	}
	passes := 0
	for attempt := 0; attempt < 30 && passes < 2; attempt++ {
		code, _, err := p.httpProbe(ctx, w.Endpoint, "GET", path)
		good := err == nil && ((strict && code >= 200 && code < 300) || (!strict && code > 0 && code < 500))
		if good {
			passes++
		} else {
			passes = 0
			if time.Now().After(deadline.Add(30 * time.Second)) {
				return fmt.Errorf("readiness check %s failed (status %d, err %v)", path, code, err)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if passes < 2 {
		return fmt.Errorf("readiness check %s did not stabilise", path)
	}
	p.logf(ctx, d.ID, "deploy", "health: readiness %s ok", path)
	// 3. Smoke tests from opendeploy.yaml.
	for _, sm := range cfg.Health.Smoke {
		method, target, _ := strings.Cut(sm.Request, " ")
		code, body, err := p.httpProbe(ctx, w.Endpoint, method, target)
		if err != nil {
			return fmt.Errorf("smoke %q: %v", sm.Name, err)
		}
		if code != sm.ExpectStatus {
			return fmt.Errorf("smoke %q: got status %d, want %d", sm.Name, code, sm.ExpectStatus)
		}
		if sm.ExpectBody != "" && !strings.Contains(body, sm.ExpectBody) {
			return fmt.Errorf("smoke %q: body does not contain expected text", sm.Name)
		}
		p.logf(ctx, d.ID, "deploy", "health: smoke %q passed", sm.Name)
	}
	// 4. Stability: not crash-looping.
	return p.checkRunning(ctx, w.ID)
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func (p *Platform) checkRunning(ctx context.Context, wid string) error {
	rw, err := p.Runtime.Inspect(ctx, wid)
	if err != nil {
		return fmt.Errorf("inspect workload: %w", err)
	}
	if rw.State != "running" {
		msg := fmt.Sprintf("workload exited (code %d)", rw.ExitCode)
		if rw.OOMKilled {
			msg += " — killed for exceeding its memory limit"
		}
		return errors.New(msg)
	}
	if rw.Restarts > 0 {
		return fmt.Errorf("workload restarted %d time(s) during health checks", rw.Restarts)
	}
	return nil
}

func (p *Platform) httpProbe(ctx context.Context, endpoint, method, path string) (int, string, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+endpoint+path, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "OpenDeploy-Health/1")
	resp, err := p.HealthClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, string(b), nil
}
