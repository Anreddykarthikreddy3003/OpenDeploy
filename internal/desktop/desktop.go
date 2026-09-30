// Package desktop runs the OpenDeploy data plane on Windows and macOS hosts
// (PRD §3.3, FR-002). Build and runtime semantics are Linux-only, so these
// hosts run the complete Linux node inside a managed guest: a WSL2 distro on
// Windows, an Apple Virtualization.framework VM on macOS. The host side is
// deliberately small: it provisions and supervises the guest, forwards the
// loopback ports and reports status. Everything security-relevant (trust
// classes, sandboxing, secrets, audit) happens inside the guest exactly as
// on a Linux server.
package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Guest is a managed Linux data plane.
type Guest interface {
	// Kind is "wsl2" or "vz".
	Kind() string
	// Ensure provisions the guest on first use (import the distro, unpack
	// the VM disk). It is idempotent.
	Ensure(ctx context.Context) error
	// Start boots the guest and returns once it is running. The returned
	// channel receives the reason when the guest stops.
	Start(ctx context.Context) (<-chan error, error)
	// Stop shuts the guest down gracefully, forcing it after the timeout.
	Stop(ctx context.Context, timeout time.Duration) error
	// BootstrapToken reads the one-time owner token from the running guest
	// ("" once the owner account exists).
	BootstrapToken(ctx context.Context) (string, error)
}

// Config holds host settings.
type Config struct {
	ImageDir  string // read-only guest images shipped with the package
	DataDir   string // host state: VM disk / WSL install dir, logs, status
	APIPort   int    // dashboard/API port exposed on host loopback
	HTTPPort  int
	HTTPSPort int
	CPUs      int
	MemoryMiB int
	DiskGiB   int
}

// Defaults fills unset fields.
func (c *Config) Defaults() {
	if c.APIPort == 0 {
		c.APIPort = 8080
	}
	if c.HTTPPort == 0 {
		c.HTTPPort = 80
	}
	if c.HTTPSPort == 0 {
		c.HTTPSPort = 443
	}
	if c.CPUs == 0 {
		c.CPUs = 4
	}
	if c.MemoryMiB == 0 {
		c.MemoryMiB = 6144
	}
	if c.DiskGiB == 0 {
		c.DiskGiB = 64
	}
}

// Status is written to <DataDir>/status.json for `opendeploy-desktop status`.
type Status struct {
	Guest   string    `json:"guest"`
	State   string    `json:"state"` // provisioning | starting | running | restarting | stopped | error
	Message string    `json:"message,omitempty"`
	Restart int       `json:"restarts"`
	Updated time.Time `json:"updated"`
}

// TokenPath is where the supervisor publishes the owner bootstrap token for
// the local administrator (the directory is admin/service-only).
func TokenPath(dataDir string) string { return filepath.Join(dataDir, "bootstrap-token") }

// StatusPath is where the supervisor publishes its status.
func StatusPath(dataDir string) string { return filepath.Join(dataDir, "status.json") }

// ReadStatus reads the published status.
func ReadStatus(dataDir string) (*Status, error) {
	b, err := os.ReadFile(StatusPath(dataDir))
	if err != nil {
		return nil, err
	}
	var s Status
	return &s, json.Unmarshal(b, &s)
}

// Supervisor keeps the guest running and healthy.
type Supervisor struct {
	Guest   Guest
	Config  Config
	Log     *slog.Logger
	Healthy func(ctx context.Context) error // default: GET /healthz on the API port
	// ReadyTimeout bounds how long a booting guest may take to serve the API.
	ReadyTimeout time.Duration
	MaxBackoff   time.Duration

	mu     sync.Mutex
	status Status
}

func (s *Supervisor) setStatus(state, msg string) {
	// The file is updated under the lock so it never lags (or overtakes)
	// the in-memory status.
	s.mu.Lock()
	s.status.Guest, s.status.State, s.status.Message, s.status.Updated = s.Guest.Kind(), state, msg, time.Now().UTC()
	b, _ := json.MarshalIndent(s.status, "", "  ")
	tmp := StatusPath(s.Config.DataDir) + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, StatusPath(s.Config.DataDir))
	}
	s.mu.Unlock()
	s.Log.Info("data plane", "state", state, "message", msg)
}

// Status returns the current status.
func (s *Supervisor) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// HealthCheck probes the node API through the host loopback port.
func HealthCheck(port int) func(ctx context.Context) error {
	hc := &http.Client{Timeout: 5 * time.Second}
	return func(ctx context.Context) error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/healthz", port), nil)
		res, err := hc.Do(req)
		if err != nil {
			return err
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("healthz: %s", res.Status)
		}
		return nil
	}
}

// Run supervises the guest until ctx is cancelled, then stops it.
func (s *Supervisor) Run(ctx context.Context) error {
	s.Config.Defaults()
	if s.Log == nil {
		s.Log = slog.Default()
	}
	if s.Healthy == nil {
		s.Healthy = HealthCheck(s.Config.APIPort)
	}
	if s.ReadyTimeout == 0 {
		s.ReadyTimeout = 10 * time.Minute
	}
	if s.MaxBackoff == 0 {
		s.MaxBackoff = time.Minute
	}
	if err := os.MkdirAll(s.Config.DataDir, 0o755); err != nil {
		return err
	}
	backoff := time.Second
	for {
		s.setStatus("provisioning", "")
		err := s.Guest.Ensure(ctx)
		var done <-chan error
		if err == nil {
			s.setStatus("starting", "")
			done, err = s.Guest.Start(ctx)
		}
		if err == nil {
			started := time.Now()
			err = s.watch(ctx, done)
			if time.Since(started) > 10*time.Minute {
				backoff = time.Second // it ran fine for a while: restart promptly
			}
		}
		if ctx.Err() != nil {
			s.setStatus("stopping", "")
			stopCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			serr := s.Guest.Stop(stopCtx, 60*time.Second)
			cancel()
			s.setStatus("stopped", errString(serr))
			return nil
		}
		s.mu.Lock()
		s.status.Restart++
		s.mu.Unlock()
		s.setStatus("restarting", errString(err))
		select {
		case <-ctx.Done():
			continue // loop once more to run the stop path
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > s.MaxBackoff {
			backoff = s.MaxBackoff
		}
	}
}

// watch waits for the guest to become healthy and then for it to exit.
// A guest that never becomes ready is stopped and restarted.
func (s *Supervisor) watch(ctx context.Context, done <-chan error) error {
	deadline := time.Now().Add(s.ReadyTimeout)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	ready := false
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-done:
			if err == nil {
				err = errors.New("guest exited")
			}
			return err
		case <-tick.C:
			err := s.Healthy(ctx)
			switch {
			case err == nil && !ready:
				ready, failures = true, 0
				s.setStatus("running", "")
				s.publishToken(ctx)
			case err == nil:
				failures = 0
			case ready:
				// The node restarts its own services (updates, crashes);
				// only report prolonged unavailability.
				if failures++; failures == 15 {
					s.setStatus("degraded", err.Error())
				}
			case time.Now().After(deadline):
				_ = s.Guest.Stop(ctx, 30*time.Second)
				return fmt.Errorf("guest did not become ready within %s: %w", s.ReadyTimeout, err)
			}
		}
	}
}

// publishToken copies the guest's bootstrap token to the host data dir (or
// removes a stale copy once the owner exists).
func (s *Supervisor) publishToken(ctx context.Context) {
	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tok, err := s.Guest.BootstrapToken(tctx)
	if err != nil {
		s.Log.Debug("bootstrap token unavailable", "err", err)
		return
	}
	p := TokenPath(s.Config.DataDir)
	if tok == "" {
		_ = os.Remove(p)
		return
	}
	_ = os.WriteFile(p, []byte(tok+"\n"), 0o600)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
