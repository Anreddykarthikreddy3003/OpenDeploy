// Package router implements routemgr: the owner of edge policy. It renders
// the complete Caddy configuration from a typed route table, loads it
// through Caddy's admin API on a Unix socket (never TCP, PRD §9.1, [R12]),
// verifies that Caddy accepted it and that each route answers with the
// expected deployment, and keeps the last-known-good configuration for
// reboot and failed-promotion recovery (PRD §11.3, §18.1).
package router

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Route kinds.
const (
	KindProxy    = "proxy"
	KindStatic   = "static"
	KindRedirect = "redirect"
)

// TLS modes.
const (
	TLSACME     = "acme"
	TLSInternal = "internal"
	TLSNone     = "none"
)

// Route maps hostnames to a deployment.
type Route struct {
	EnvironmentID string     `json:"environment_id"`
	ProjectID     string     `json:"project_id"`
	DeploymentID  string     `json:"deployment_id"`
	Hosts         []string   `json:"hosts"`
	Kind          string     `json:"kind"`
	Upstreams     []string   `json:"upstreams,omitempty"`
	StaticDigest  string     `json:"static_digest,omitempty"`
	StaticDir     string     `json:"-"` // resolved by routemgr from artifactd
	SPA           bool       `json:"spa,omitempty"`
	RedirectTo    string     `json:"redirect_to,omitempty"`
	TLS           string     `json:"tls"`
	BasicAuth     *BasicAuth `json:"basic_auth,omitempty"`
	MaxBodyBytes  int64      `json:"max_body_bytes,omitempty"`
	MaxConns      int        `json:"max_conns,omitempty"`
}

// BasicAuth protects preview environments (optional access auth, §12).
type BasicAuth struct {
	User       string `json:"user"`
	BcryptHash string `json:"bcrypt_hash"`
}

// Table is the full desired edge state.
type Table struct {
	Routes []Route `json:"routes"`
}

// Options are node-level edge settings.
type Options struct {
	AdminSocket  string
	HTTPPort     int
	HTTPSPort    int
	VerifyListen string // loopback-only verification server, e.g. 127.0.0.1:18080
	ACMEEmail    string
	ACMECA       string
	ACMECARoot   string // PEM file trusted for the ACME directory's HTTPS
	MaxBodyBytes int64
	MaxConns     int
	StateDir     string
	LANOnly      bool // lan ingress: plain HTTP unless TLS=internal
}

var hostRE = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
var upstreamRE = regexp.MustCompile(`^[0-9a-fA-F.:\[\]]+:[0-9]{1,5}$`)

// Validate checks a route before rendering.
func (r *Route) Validate() error {
	if len(r.Hosts) == 0 {
		return errors.New("route has no hosts")
	}
	for _, h := range r.Hosts {
		if !hostRE.MatchString(h) || len(h) > 253 {
			return fmt.Errorf("invalid host %q", h)
		}
	}
	switch r.Kind {
	case KindProxy:
		if len(r.Upstreams) == 0 {
			return errors.New("proxy route has no upstreams")
		}
		for _, u := range r.Upstreams {
			if !upstreamRE.MatchString(u) {
				return fmt.Errorf("invalid upstream %q", u)
			}
			host, _, err := net.SplitHostPort(u)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
				// Upstreams are workload IPs on project networks, never host
				// loopback (which would expose control-plane listeners).
				return fmt.Errorf("upstream %q is not a workload address", u)
			}
		}
	case KindStatic:
		if r.StaticDir == "" {
			return errors.New("static route has no directory")
		}
	case KindRedirect:
		if !strings.HasPrefix(r.RedirectTo, "https://") && !strings.HasPrefix(r.RedirectTo, "http://") {
			return errors.New("redirect target must be absolute http(s)")
		}
	default:
		return fmt.Errorf("unknown kind %q", r.Kind)
	}
	switch r.TLS {
	case TLSACME, TLSInternal, TLSNone:
	default:
		return fmt.Errorf("invalid tls mode %q", r.TLS)
	}
	return nil
}

// Render produces the full Caddy JSON configuration.
func Render(t Table, o Options) ([]byte, error) {
	routes := append([]Route(nil), t.Routes...)
	sort.Slice(routes, func(i, j int) bool { return routes[i].EnvironmentID < routes[j].EnvironmentID })
	hostOwner := map[string]string{}
	var tlsRoutes, plainRoutes, verify []any
	var acmeHosts, internalHosts, plainHosts []string
	for i := range routes {
		r := &routes[i]
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("route %s: %w", r.EnvironmentID, err)
		}
		for _, h := range r.Hosts {
			if prev, dup := hostOwner[h]; dup && prev != r.EnvironmentID {
				return nil, fmt.Errorf("host %s claimed by both %s and %s", h, prev, r.EnvironmentID)
			}
			hostOwner[h] = r.EnvironmentID
			switch r.TLS {
			case TLSACME:
				acmeHosts = append(acmeHosts, h)
			case TLSInternal:
				internalHosts = append(internalHosts, h)
			default:
				plainHosts = append(plainHosts, h)
			}
		}
		if r.TLS == TLSNone {
			plainRoutes = append(plainRoutes, renderRoute(r, o, false))
		} else {
			tlsRoutes = append(tlsRoutes, renderRoute(r, o, false))
		}
		verify = append(verify, renderRoute(r, o, true))
	}
	// Each server ends with a catch-all 404 carrying a unique @id: its
	// presence tells the routemgr watchdog that our configuration (and not
	// Caddy's bootstrap config) is loaded.
	notFound := func(name string) map[string]any {
		return map[string]any{"@id": DefaultRouteID(name), "handle": []any{map[string]any{"handler": "static_response", "status_code": 404,
			"body": "No OpenDeploy deployment is configured for this host.\n", "headers": map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}}}}}
	}

	server := func(name, listen string, rs []any) map[string]any {
		return map[string]any{
			"listen":              []string{listen},
			"routes":              append(rs, notFound(name)),
			"max_header_bytes":    64 << 10,
			"read_header_timeout": "10s",
			"read_timeout":        "60s",
			"idle_timeout":        "120s",
		}
	}
	servers := map[string]any{}
	// Plain-HTTP hosts (LAN mode) are served on the HTTP port. Caddy's
	// automatic HTTPS also uses this server for ACME HTTP-01 challenges and
	// HTTP->HTTPS redirects of TLS hosts.
	servers["http"] = server("http", fmt.Sprintf(":%d", o.HTTPPort), plainRoutes)
	if len(tlsRoutes) > 0 {
		srv := server("https", fmt.Sprintf(":%d", o.HTTPSPort), tlsRoutes)
		srv["logs"] = map[string]any{}
		servers["https"] = srv
	}
	if o.VerifyListen != "" {
		v := server("verify", o.VerifyListen, verify)
		v["automatic_https"] = map[string]any{"disable": true}
		servers["verify"] = v
	}
	apps := map[string]any{"http": map[string]any{"http_port": o.HTTPPort, "https_port": o.HTTPSPort, "servers": servers}}
	var policies []any
	if len(acmeHosts) > 0 {
		sort.Strings(acmeHosts)
		issuer := map[string]any{"module": "acme"}
		if o.ACMEEmail != "" {
			issuer["email"] = o.ACMEEmail
		}
		if o.ACMECA != "" {
			issuer["ca"] = o.ACMECA
		}
		if o.ACMECARoot != "" {
			issuer["trusted_roots_pem_files"] = []string{o.ACMECARoot}
		}
		policies = append(policies, map[string]any{"subjects": acmeHosts, "issuers": []any{issuer}})
	}
	if len(internalHosts) > 0 {
		sort.Strings(internalHosts)
		policies = append(policies, map[string]any{"subjects": internalHosts, "issuers": []any{map[string]any{"module": "internal"}}})
	}
	if len(policies) > 0 {
		apps["tls"] = map[string]any{"automation": map[string]any{"policies": policies}}
	}
	cfg := map[string]any{
		"admin": map[string]any{
			"listen":         adminListen(o.AdminSocket),
			"enforce_origin": false,
			"config":         map[string]any{"persist": false},
		},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "WARN"}}},
		"apps":    apps,
	}
	return json.Marshal(cfg)
}

func renderRoute(r *Route, o Options, verify bool) map[string]any {
	var handlers []any
	maxBody := r.MaxBodyBytes
	if maxBody == 0 {
		maxBody = o.MaxBodyBytes
	}
	if maxBody > 0 {
		handlers = append(handlers, map[string]any{"handler": "request_body", "max_size": maxBody})
	}
	hdr := map[string][]string{
		"X-Content-Type-Options": {"nosniff"},
		"Referrer-Policy":        {"strict-origin-when-cross-origin"},
		"-Server":                nil,
	}
	if verify {
		hdr["X-Opendeploy-Deployment"] = []string{r.DeploymentID}
	}
	handlers = append(handlers, map[string]any{"handler": "headers", "response": map[string]any{"set": filterSet(hdr), "delete": []string{"Server", "X-Powered-By"}, "deferred": true}})
	if r.BasicAuth != nil && !verify {
		handlers = append(handlers, map[string]any{"handler": "authentication", "providers": map[string]any{"http_basic": map[string]any{
			"hash":     map[string]any{"algorithm": "bcrypt"},
			"accounts": []any{map[string]any{"username": r.BasicAuth.User, "password": r.BasicAuth.BcryptHash}},
			"realm":    "OpenDeploy preview",
		}}})
	}
	switch r.Kind {
	case KindProxy:
		ups := make([]any, len(r.Upstreams))
		for i, u := range r.Upstreams {
			ups[i] = map[string]any{"dial": u}
		}
		maxConns := r.MaxConns
		if maxConns == 0 {
			maxConns = o.MaxConns
		}
		tr := map[string]any{"protocol": "http", "dial_timeout": "5s", "response_header_timeout": "120s"}
		if maxConns > 0 {
			tr["max_conns_per_host"] = maxConns
		}
		handlers = append(handlers, map[string]any{
			"handler":        "reverse_proxy",
			"upstreams":      ups,
			"transport":      tr,
			"load_balancing": map[string]any{"selection_policy": map[string]any{"policy": "round_robin"}, "retries": 1},
			"health_checks":  map[string]any{"passive": map[string]any{"fail_duration": "10s", "max_fails": 3, "unhealthy_status": []int{502, 503, 504}}},
			"headers":        map[string]any{"request": map[string]any{"delete": []string{"X-Opendeploy-Internal"}}},
		})
	case KindStatic:
		var sub []any
		if r.SPA {
			sub = append(sub, map[string]any{"handle": []any{map[string]any{"handler": "rewrite", "uri": "{http.matchers.file.relative}"}},
				"match": []any{map[string]any{"file": map[string]any{"root": r.StaticDir, "try_files": []string{"{http.request.uri.path}", "{http.request.uri.path}/index.html", "/index.html"}}}}})
		} else {
			sub = append(sub, map[string]any{"handle": []any{map[string]any{"handler": "rewrite", "uri": "{http.matchers.file.relative}"}},
				"match": []any{map[string]any{"file": map[string]any{"root": r.StaticDir, "try_files": []string{"{http.request.uri.path}", "{http.request.uri.path}.html", "{http.request.uri.path}/index.html"}}}}})
		}
		sub = append(sub, map[string]any{"handle": []any{map[string]any{"handler": "encode", "encodings": map[string]any{"gzip": map[string]any{}, "zstd": map[string]any{}}},
			map[string]any{"handler": "file_server", "root": r.StaticDir, "hide": []string{".*"}, "canonical_uris": false,
				"pass_thru": false}}})
		handlers = append(handlers, map[string]any{"handler": "subroute", "routes": sub})
	case KindRedirect:
		handlers = append(handlers, map[string]any{"handler": "static_response", "status_code": 308, "headers": map[string][]string{"Location": {r.RedirectTo + "{http.request.uri}"}}})
	}
	return map[string]any{
		"@id":      prefixID(verify) + r.EnvironmentID,
		"match":    []any{map[string]any{"host": r.Hosts}},
		"handle":   []any{map[string]any{"handler": "subroute", "routes": []any{map[string]any{"handle": handlers}}}},
		"terminal": true,
	}
}

func prefixID(verify bool) string {
	if verify {
		return "verify-"
	}
	return "route-"
}

func filterSet(h map[string][]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range h {
		if !strings.HasPrefix(k, "-") && v != nil {
			out[k] = v
		}
	}
	return out
}

// Digest is the sha256 of a rendered configuration.
func Digest(cfg []byte) string {
	s := sha256.Sum256(cfg)
	return "sha256:" + hex.EncodeToString(s[:])
}

// Caddy talks to the admin API over a Unix socket.
type Caddy struct {
	hc *http.Client
}

func NewCaddy(socket string) *Caddy {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}
	return &Caddy{hc: &http.Client{Transport: tr, Timeout: 60 * time.Second}}
}

// Load replaces Caddy's configuration atomically (Caddy rolls back on error).
func (c *Caddy) Load(ctx context.Context, cfg []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://caddy/load", bytes.NewReader(cfg))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("caddy rejected config: %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// RouteIDs returns the @id values of all loaded routes across servers. A
// Caddy running only its bootstrap config (no http app) has none.
func (c *Caddy) RouteIDs(ctx context.Context) (map[string]bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://caddy/config/", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("caddy config: %s", resp.Status)
	}
	var cfg struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						ID string `json:"@id"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&cfg); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, srv := range cfg.Apps.HTTP.Servers {
		for _, r := range srv.Routes {
			if r.ID != "" {
				out[r.ID] = true
			}
		}
	}
	return out, nil
}

// Manager applies tables with verification and last-known-good tracking.
type Manager struct {
	Caddy *Caddy
	Opt   Options
	// Resolve maps static artifact digests to directories when reloading
	// last-known-good (directories are never persisted or accepted from
	// callers).
	Resolve StaticResolver
	mu      sync.Mutex
	current Table
	digest  string
	HTTP    *http.Client
}

// NewManager creates a manager and loads the last-known-good table from
// StateDir if present.
func NewManager(c *Caddy, o Options) *Manager {
	m := &Manager{Caddy: c, Opt: o, HTTP: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if b, err := os.ReadFile(filepath.Join(o.StateDir, "last-known-good.json")); err == nil {
		_ = json.Unmarshal(b, &m.current)
	}
	return m
}

// Current returns the applied table and digest.
func (m *Manager) Current() (Table, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current, m.digest
}

// ApplyResult reports an apply.
type ApplyResult struct {
	Digest   string            `json:"digest"`
	Verified map[string]string `json:"verified"` // environment -> deployment answering
}

// Apply renders, loads and verifies the table. verifyEnvs lists
// environments whose route must answer with its declared deployment via the
// loopback verification server. On verification failure the previous
// configuration is restored and an error returned.
func (m *Manager) Apply(ctx context.Context, t Table, verifyEnvs []string) (*ApplyResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, err := Render(t, m.Opt)
	if err != nil {
		return nil, err
	}
	if err := m.Caddy.Load(ctx, cfg); err != nil {
		return nil, err
	}
	res := &ApplyResult{Digest: Digest(cfg), Verified: map[string]string{}}
	ids, err := m.Caddy.RouteIDs(ctx)
	if err == nil {
		for _, r := range t.Routes {
			if !ids["route-"+r.EnvironmentID] {
				err = fmt.Errorf("route %s missing after load", r.EnvironmentID)
				break
			}
		}
	}
	if err == nil {
		for _, env := range verifyEnvs {
			var r *Route
			for i := range t.Routes {
				if t.Routes[i].EnvironmentID == env {
					r = &t.Routes[i]
				}
			}
			if r == nil {
				err = fmt.Errorf("verify: no route for %s", env)
				break
			}
			got, verr := m.verifyRoute(ctx, r)
			if verr != nil {
				err = verr
				break
			}
			res.Verified[env] = got
		}
	}
	if err != nil {
		// Restore last-known-good.
		if prev, rerr := Render(m.current, m.Opt); rerr == nil {
			_ = m.Caddy.Load(ctx, prev)
		}
		return nil, err
	}
	m.current, m.digest = t, res.Digest
	if m.Opt.StateDir != "" {
		b, _ := json.Marshal(t)
		_ = os.MkdirAll(m.Opt.StateDir, 0o700)
		tmp := filepath.Join(m.Opt.StateDir, "last-known-good.json.tmp")
		if os.WriteFile(tmp, b, 0o600) == nil {
			_ = os.Rename(tmp, filepath.Join(m.Opt.StateDir, "last-known-good.json"))
		}
	}
	return res, nil
}

// verifyRoute requests the route through the loopback verification server
// and checks that the expected deployment answered and that the response is
// not a gateway error.
func (m *Manager) verifyRoute(ctx context.Context, r *Route) (string, error) {
	if m.Opt.VerifyListen == "" {
		return r.DeploymentID, nil
	}
	host := r.Hosts[0]
	if strings.HasPrefix(host, "*.") {
		host = "verify" + host[1:]
	}
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+m.Opt.VerifyListen+"/", nil)
		if err != nil {
			return "", err
		}
		req.Host = host
		resp, err := m.HTTP.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			got := resp.Header.Get("X-Opendeploy-Deployment")
			switch {
			case got != r.DeploymentID:
				lastErr = fmt.Errorf("verify %s: answered by %q, expected %q", host, got, r.DeploymentID)
			case resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504:
				lastErr = fmt.Errorf("verify %s: edge returned %d", host, resp.StatusCode)
			default:
				return got, nil
			}
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(time.Duration(200*(attempt+1)) * time.Millisecond):
		}
	}
	return "", lastErr
}

// resolveStatic fills in static directories missing from t (a table loaded
// from last-known-good). Called with m.mu held.
func (m *Manager) resolveStatic(ctx context.Context, t *Table) error {
	for i := range t.Routes {
		r := &t.Routes[i]
		if r.Kind != KindStatic || r.StaticDir != "" {
			continue
		}
		if m.Resolve == nil {
			return fmt.Errorf("route %s: static resolver unavailable", r.EnvironmentID)
		}
		dir, err := m.Resolve(ctx, r.StaticDigest)
		if err != nil {
			return fmt.Errorf("route %s: static artifact %s: %w", r.EnvironmentID, r.StaticDigest, err)
		}
		r.StaticDir = dir
	}
	return nil
}

// DefaultRouteID is the @id of a server's catch-all route.
func DefaultRouteID(server string) string { return "od-default-" + server }

// EnsureLoaded reloads the last-known-good table when Caddy is not serving
// it, e.g. after Caddy restarted on its own (crash, OOM, package upgrade)
// and came back with only its bootstrap configuration. It reports whether
// a reload was needed.
func (m *Manager) EnsureLoaded(ctx context.Context) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids, err := m.Caddy.RouteIDs(ctx)
	if err != nil {
		return false, err
	}
	missing := !ids[DefaultRouteID("http")]
	for _, r := range m.current.Routes {
		if !ids["route-"+r.EnvironmentID] {
			missing = true
		}
	}
	if !missing {
		return false, nil
	}
	if err := m.resolveStatic(ctx, &m.current); err != nil {
		return false, err
	}
	cfg, err := Render(m.current, m.Opt)
	if err != nil {
		return false, err
	}
	if err := m.Caddy.Load(ctx, cfg); err != nil {
		return false, err
	}
	m.digest = Digest(cfg)
	return true, nil
}

// Watch keeps Caddy serving the last-known-good table until ctx ends.
func (m *Manager) Watch(ctx context.Context, every time.Duration, log func(msg string, args ...any)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			reloaded, err := m.EnsureLoaded(ctx)
			if reloaded {
				log("edge configuration was missing from Caddy (restart?); reloaded last-known-good")
			} else if err != nil && ctx.Err() == nil {
				log("edge watchdog: caddy unreachable", "err", err)
			}
		}
	}
}

// Restore reloads the last-known-good table (boot recovery).
func (m *Manager) Restore(ctx context.Context) error {
	m.mu.Lock()
	err := m.resolveStatic(ctx, &m.current)
	t := m.current
	m.mu.Unlock()
	if err != nil {
		return err
	}
	cfg, err := Render(t, m.Opt)
	if err != nil {
		return err
	}
	if err := m.Caddy.Load(ctx, cfg); err != nil {
		return err
	}
	m.mu.Lock()
	m.digest = Digest(cfg)
	m.mu.Unlock()
	return nil
}

// BootstrapConfig is the minimal config Caddy starts with (admin socket
// only, no public routes) before routemgr restores last-known-good.
func BootstrapConfig(adminSocket string) []byte {
	b, _ := json.Marshal(map[string]any{"admin": map[string]any{"listen": adminListen(adminSocket), "config": map[string]any{"persist": false}}})
	return b
}

// PortString formats a port for listeners.
func PortString(p int) string { return strconv.Itoa(p) }

// adminListen is Caddy's admin address: a unix socket whose mode lets the
// od-caddy group (routemgr) connect. Caddy 2.8+ otherwise creates it 0200.
func adminListen(sock string) string { return "unix/" + sock + "|0660" }
