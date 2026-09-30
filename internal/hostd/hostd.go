// Package hostd implements opendeploy-hostd, the only root component of the
// control plane (PRD §4.1, SC-10). It exposes exactly the closed operation
// set in internal/hostops over IPC to platformd; every parameter is an enum
// or validated identifier, and every command it runs has fixed arguments.
package hostd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/hostops"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/update"
)

// Host holds hostd's dependencies.
type Host struct {
	Node    *config.Node
	Version string
	Log     *slog.Logger
	Audit   audit.Sink
	// Systemctl runs `systemctl <verb> <unit>` (replaceable in tests).
	Systemctl func(ctx context.Context, verb, unit string) (string, error)
	// Healthy checks platform readiness after an update.
	Healthy func(ctx context.Context) error
	Slots   *update.Slots
	// Readiness bounds the post-update health gate (default 3 minutes).
	Readiness time.Duration

	mu    sync.Mutex
	state hostops.UpdateState
}

// New returns a Host with production defaults.
func New(n *config.Node, version string, log *slog.Logger, sink audit.Sink) *Host {
	if log == nil {
		log = slog.Default()
	}
	h := &Host{Node: n, Version: version, Log: log, Audit: sink, Slots: &update.Slots{Dir: n.Update.SlotsDir}}
	h.Systemctl = systemctl
	h.Healthy = func(ctx context.Context) error {
		c := &http.Client{Timeout: 5 * time.Second}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+n.API.Listen+"/readyz", nil)
		res, err := c.Do(req)
		if err != nil {
			return err
		}
		res.Body.Close()
		if res.StatusCode != 200 {
			return fmt.Errorf("platform readiness: %s", res.Status)
		}
		return nil
	}
	h.state.Operation = "idle"
	return h
}

// Init records the running release in the slot state (called at startup).
func (h *Host) Init() error {
	return h.Slots.RecordActive(h.Version, store.SchemaVersion)
}

func systemctl(ctx context.Context, verb, unit string) (string, error) {
	switch verb {
	case "restart", "start", "stop", "show":
	default:
		return "", fmt.Errorf("verb %q not allowed", verb)
	}
	args := []string{verb, unit}
	if verb == "show" {
		args = []string{"show", "--property=ActiveState,SubState", unit}
	}
	c, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "/usr/bin/systemctl", args...).CombinedOutput()
	return string(out), err
}

func (h *Host) audit(ctx context.Context, action, result string, d map[string]string) {
	if h.Audit == nil {
		return
	}
	_, _ = h.Audit.Append(ctx, audit.Event{ActorType: audit.ActorService, ActorID: identity.Host, Action: action, ResourceType: "host", Result: result, Details: d})
}

// Register exposes the closed operation set to platformd only.
func Register(srv *ipc.Server, h *Host) {
	p := []string{identity.Platform}
	ipc.Handle(srv, hostops.OpInfo, p, func(ctx context.Context, _ ipc.Caller, _ hostops.Empty) (*hostops.Info, error) {
		return h.Info(), nil
	})
	ipc.Handle(srv, hostops.OpServiceStatus, p, func(ctx context.Context, _ ipc.Caller, r hostops.ServiceReq) (*hostops.ServiceStatus, error) {
		if err := r.Validate(); err != nil {
			return nil, ipc.Errorf(ipc.CodeBadRequest, "%v", err)
		}
		return h.ServiceStatus(ctx, r.Service)
	})
	ipc.Handle(srv, hostops.OpServiceRestart, p, func(ctx context.Context, _ ipc.Caller, r hostops.ServiceReq) (hostops.Empty, error) {
		if err := r.Validate(); err != nil {
			return hostops.Empty{}, ipc.Errorf(ipc.CodeBadRequest, "%v", err)
		}
		_, err := h.Systemctl(ctx, "restart", hostops.Units[r.Service])
		h.audit(ctx, "host.service.restart", result(err), map[string]string{"target": r.Service})
		return hostops.Empty{}, err
	})
	ipc.Handle(srv, hostops.OpFirewallApply, p, func(ctx context.Context, _ ipc.Caller, r hostops.FirewallReq) (hostops.Empty, error) {
		if err := r.Validate(); err != nil {
			return hostops.Empty{}, ipc.Errorf(ipc.CodeBadRequest, "%v", err)
		}
		err := h.ApplyFirewall(ctx, r)
		h.audit(ctx, "host.firewall.apply", result(err), nil)
		return hostops.Empty{}, err
	})
	ipc.Handle(srv, hostops.OpUpdateStage, p, func(ctx context.Context, _ ipc.Caller, r hostops.UpdateStageReq) (*hostops.UpdateState, error) {
		if err := r.Validate(); err != nil {
			return nil, ipc.Errorf(ipc.CodeBadRequest, "%v", err)
		}
		err := h.Stage(ctx, r.Channel, r.Version)
		h.audit(ctx, "update.stage", result(err), map[string]string{"update_version": r.Version, "reason": errString(err)})
		if err != nil {
			return nil, ipc.Errorf(ipc.CodeConflict, "%v", err)
		}
		st := h.State()
		return &st, nil
	})
	ipc.Handle(srv, hostops.OpUpdateCommit, p, func(ctx context.Context, _ ipc.Caller, r hostops.UpdateCommitReq) (*hostops.UpdateState, error) {
		if err := r.Validate(); err != nil {
			return nil, ipc.Errorf(ipc.CodeBadRequest, "%v", err)
		}
		if err := h.CommitAsync(r.Version); err != nil {
			return nil, ipc.Errorf(ipc.CodeConflict, "%v", err)
		}
		st := h.State()
		return &st, nil
	})
	ipc.Handle(srv, hostops.OpUpdateRollback, p, func(ctx context.Context, _ ipc.Caller, _ hostops.Empty) (*hostops.UpdateState, error) {
		err := h.Rollback(ctx)
		h.audit(ctx, "update.rollback", result(err), nil)
		if err != nil {
			return nil, ipc.Errorf(ipc.CodeConflict, "%v", err)
		}
		st := h.State()
		return &st, nil
	})
	ipc.Handle(srv, hostops.OpSupportBundle, p, func(ctx context.Context, _ ipc.Caller, _ hostops.Empty) (*hostops.SupportBundle, error) {
		b, err := h.SupportBundle(ctx)
		h.audit(ctx, "host.support_bundle", result(err), nil)
		return b, err
	})
	ipc.Handle(srv, hostops.OpDataPlaneStatus, p, func(ctx context.Context, _ ipc.Caller, _ hostops.Empty) (*hostops.DataPlaneStatus, error) {
		return &hostops.DataPlaneStatus{State: "running", Message: "native Linux data plane"}, nil
	})
	ipc.Handle(srv, hostops.OpDataPlaneStart, p, func(ctx context.Context, _ ipc.Caller, _ hostops.Empty) (*hostops.DataPlaneStatus, error) {
		return &hostops.DataPlaneStatus{State: "running", Message: "native Linux data plane is always on"}, nil
	})
	ipc.Handle(srv, hostops.OpDataPlaneStop, p, func(ctx context.Context, _ ipc.Caller, _ hostops.Empty) (*hostops.DataPlaneStatus, error) {
		return nil, ipc.Errorf(ipc.CodeBadRequest, "the native data plane is stopped with the host service manager")
	})
}

func result(err error) string {
	if err != nil {
		return audit.Failure
	}
	return audit.Success
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// ServiceStatus reports a unit's state.
func (h *Host) ServiceStatus(ctx context.Context, svc string) (*hostops.ServiceStatus, error) {
	out, err := h.Systemctl(ctx, "show", hostops.Units[svc])
	if err != nil {
		return nil, err
	}
	st := &hostops.ServiceStatus{Service: svc}
	for _, line := range splitLines(out) {
		if v, ok := cutPrefix(line, "ActiveState="); ok {
			st.Active = v
		} else if v, ok := cutPrefix(line, "SubState="); ok {
			st.Sub = v
		}
	}
	return st, nil
}

// State returns the update state.
func (h *Host) State() hostops.UpdateState {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.state
	if ss, err := h.Slots.State(); err == nil {
		st.ActiveSlot, st.Versions, st.Staged = ss.Active, ss.Versions, ss.Staged
	}
	return st
}

func (h *Host) setOp(op, msg string) {
	h.mu.Lock()
	h.state.Operation, h.state.Message = op, msg
	h.mu.Unlock()
}

func (h *Host) platform() string { return runtime.GOOS + "-" + runtime.GOARCH }

func (h *Host) tufClient() (*update.Client, error) {
	u := h.Node.Update
	if u.RepositoryURL == "" || u.TrustedRoot == "" {
		return nil, errors.New("updates are not configured")
	}
	root, err := os.ReadFile(u.TrustedRoot)
	if err != nil {
		return nil, err
	}
	return &update.Client{MetadataURL: u.RepositoryURL + "/metadata", TargetsURL: u.RepositoryURL + "/targets", TrustedRoot: root,
		CacheDir: filepath.Join(h.Node.ServiceDir(identity.Host), "tuf")}, nil
}

// Stage verifies (independently of platformd) and stages a release.
func (h *Host) Stage(ctx context.Context, channel, version string) error {
	h.setOp("staging", version)
	c, err := h.tufClient()
	if err != nil {
		h.setOp("failed", err.Error())
		return err
	}
	rel, err := c.Check(channel)
	if err == nil && rel.Version != version && "v"+rel.Version != version {
		err = fmt.Errorf("the verified %s release is %s, not %s", channel, rel.Version, version)
	}
	if err == nil {
		err = update.Permit(h.Version, rel)
	}
	var tarball string
	if err == nil {
		dl := filepath.Join(h.Node.ServiceDir(identity.Host), "downloads")
		tarball, err = c.Fetch(rel, h.platform(), dl)
		if tarball != "" {
			defer os.Remove(tarball)
		}
	}
	if err == nil {
		_, err = h.Slots.Stage(rel.Version, rel.SchemaVersion, tarball)
	}
	if err != nil {
		h.setOp("failed", err.Error())
		return err
	}
	h.setOp("staged", rel.Version)
	return nil
}

// CommitAsync activates the staged release in the background (it restarts
// platformd, the caller) and records the outcome.
func (h *Host) CommitAsync(version string) error {
	ss, err := h.Slots.State()
	if err != nil {
		return err
	}
	if ss.Staged == "" || (ss.Versions[ss.Staged] != version && "v"+ss.Versions[ss.Staged] != version) {
		return fmt.Errorf("version %s is not staged", version)
	}
	h.setOp("applying", version)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		ready := h.Readiness
		if ready <= 0 {
			ready = 3 * time.Minute
		}
		err := h.Slots.Apply(ctx, update.Hooks{Restart: h.restartAll, Healthy: h.Healthy}, ready)
		switch {
		case err == nil:
			h.setOp("applied", version)
		case errors.Is(err, update.ErrRolledBack):
			h.setOp("rolled_back", err.Error())
		default:
			h.setOp("failed", err.Error())
		}
		h.audit(ctx, "update.apply", result(err), map[string]string{"update_version": version, "reason": errString(err)})
		if err != nil {
			h.Log.Error("update failed", "version", version, "err", err)
		}
	}()
	return nil
}

// Rollback activates the previous slot.
func (h *Host) Rollback(ctx context.Context) error {
	ss, err := h.Slots.State()
	if err != nil {
		return err
	}
	if ss.Previous == "" {
		return errors.New("no previous release to roll back to")
	}
	if err := h.Slots.Activate(ss.Previous); err != nil {
		return err
	}
	h.setOp("rolled_back", "manual rollback")
	return h.restartAll(ctx)
}

// restartAll restarts every managed unit in dependency order (auditd and
// secretd first so dependants reconnect to fresh servers).
func (h *Host) restartAll(ctx context.Context) error {
	order := []string{"auditd", "secretd", "artifactd", "egressd", "runtimed", "builderd", "routemgr", "relay", "platformd"}
	var errs []error
	for _, s := range order {
		if _, err := h.Systemctl(ctx, "restart", hostops.Units[s]); err != nil && s != "relay" {
			errs = append(errs, fmt.Errorf("%s: %w", s, err))
		}
	}
	return errors.Join(errs...)
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func cutPrefix(s, p string) (string, bool) {
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):], true
	}
	return "", false
}

func sortedUnits() []string {
	out := make([]string, 0, len(hostops.Units))
	for k := range hostops.Units {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
