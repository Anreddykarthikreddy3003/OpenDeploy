package runtime

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

// IPC operations. There is intentionally no exec/attach/copy operation.
const (
	OpCapabilities  = "runtime.capabilities"
	OpNetworkEnsure = "runtime.network.ensure"
	OpNetworkRemove = "runtime.network.remove"
	OpStart         = "runtime.start"
	OpStop          = "runtime.stop"
	OpRemove        = "runtime.remove"
	OpInspect       = "runtime.inspect"
	OpList          = "runtime.list"
	OpLogs          = "runtime.logs"
)

// AuthSource provides registry pull credentials (artifactd).
type AuthSource func(ctx context.Context) (RegistryAuth, error)

// Service validates requests and drives a Backend.
type Service struct {
	Backend  Backend
	Registry string // artifactd registry host:port
	Auth     AuthSource
	Audit    audit.Sink

	mu    sync.Mutex
	caps  *Capabilities
	capAt time.Time
}

func (s *Service) capabilities(ctx context.Context) (*Capabilities, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.caps != nil && time.Since(s.capAt) < time.Minute {
		return s.caps, nil
	}
	c, err := s.Backend.Capabilities(ctx)
	if err != nil {
		return nil, err
	}
	s.caps, s.capAt = c, time.Now()
	return c, nil
}

// Start validates and starts a workload.
func (s *Service) Start(ctx context.Context, sp Spec) (*Workload, error) {
	caps, err := s.capabilities(ctx)
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeUnavailable, "runtime backend: %v", err)
	}
	if err := sp.Validate(s.Registry, caps.Runtimes); err != nil {
		s.audit(ctx, "workload.start", sp, audit.Denied, err.Error())
		return nil, ipc.Errorf(ipc.CodeBadRequest, "%v", err)
	}
	for _, c := range sp.Capabilities {
		if c != "host-network" && !caps.Devices[c] {
			s.audit(ctx, "workload.start", sp, audit.Denied, "host lacks "+c)
			return nil, ipc.Errorf(ipc.CodeForbidden, "host lacks capability %q", c)
		}
	}
	var auth RegistryAuth
	if sp.Kind == "app" && s.Auth != nil {
		auth, err = s.Auth(ctx)
		if err != nil {
			return nil, ipc.Errorf(ipc.CodeUnavailable, "registry credentials: %v", err)
		}
	}
	w, err := s.Backend.Start(ctx, &sp, auth)
	if err != nil {
		s.audit(ctx, "workload.start", sp, audit.Failure, err.Error())
		return nil, err
	}
	s.audit(ctx, "workload.start", sp, audit.Success, "")
	return w, nil
}

func (s *Service) audit(ctx context.Context, action string, sp Spec, result, reason string) {
	if s.Audit == nil {
		return
	}
	d := map[string]string{"deployment_id": sp.DeploymentID, "runtime": sp.Runtime, "environment_id": sp.EnvironmentID}
	if len(sp.Capabilities) > 0 {
		d["capability"] = strings.Join(sp.Capabilities, ",")
	}
	if reason != "" {
		d["reason"] = trunc(reason, 500)
	}
	_, _ = s.Audit.Append(ctx, audit.Event{ActorType: audit.ActorService, ActorID: identity.Runtime, Action: action,
		ResourceType: "workload", ResourceID: sp.ID, ProjectID: sp.ProjectID, Result: result, Details: d})
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

type IDReq struct {
	ID      string `json:"id"`
	Timeout int    `json:"timeout_seconds,omitempty"`
}

type ListReq struct {
	EnvironmentID string `json:"environment_id,omitempty"`
	ProjectID     string `json:"project_id,omitempty"`
	DeploymentID  string `json:"deployment_id,omitempty"`
}

type LogsReq struct {
	ID    string `json:"id"`
	Tail  int    `json:"tail"`
	Since string `json:"since,omitempty"`
}

type EnvReq struct {
	EnvironmentID string `json:"environment_id"`
}

type Empty struct{}

func checkWorkloadID(id string) error {
	if !ids.HasPrefix(id, "wkl") {
		return ipc.Errorf(ipc.CodeBadRequest, "invalid workload id")
	}
	return nil
}

func mapErr(err error) error {
	if errors.Is(err, ErrNotFound) {
		return ipc.Errorf(ipc.CodeNotFound, "workload not found")
	}
	return err
}

// Register exposes runtimed over IPC; only platformd may call it.
func Register(srv *ipc.Server, s *Service) {
	p := []string{identity.Platform}
	ipc.Handle(srv, OpCapabilities, []string{identity.Platform, identity.Host}, func(ctx context.Context, _ ipc.Caller, _ Empty) (*Capabilities, error) {
		return s.capabilities(ctx)
	})
	ipc.Handle(srv, OpNetworkEnsure, p, func(ctx context.Context, _ ipc.Caller, n NetworkSpec) (*NetworkInfo, error) {
		if !ids.HasPrefix(n.EnvironmentID, "env") || !ids.HasPrefix(n.ProjectID, "prj") {
			return nil, ipc.Errorf(ipc.CodeBadRequest, "invalid ids")
		}
		return s.Backend.EnsureNetwork(ctx, n)
	})
	ipc.Handle(srv, OpNetworkRemove, p, func(ctx context.Context, _ ipc.Caller, r EnvReq) (Empty, error) {
		if !ids.HasPrefix(r.EnvironmentID, "env") {
			return Empty{}, ipc.Errorf(ipc.CodeBadRequest, "invalid id")
		}
		return Empty{}, s.Backend.RemoveNetwork(ctx, r.EnvironmentID)
	})
	ipc.Handle(srv, OpStart, p, func(ctx context.Context, _ ipc.Caller, sp Spec) (*Workload, error) { return s.Start(ctx, sp) })
	ipc.Handle(srv, OpStop, p, func(ctx context.Context, _ ipc.Caller, r IDReq) (Empty, error) {
		if err := checkWorkloadID(r.ID); err != nil {
			return Empty{}, err
		}
		t := time.Duration(r.Timeout) * time.Second
		if t <= 0 || t > 5*time.Minute {
			t = 20 * time.Second
		}
		return Empty{}, mapErr(s.Backend.Stop(ctx, r.ID, t))
	})
	ipc.Handle(srv, OpRemove, p, func(ctx context.Context, _ ipc.Caller, r IDReq) (Empty, error) {
		if err := checkWorkloadID(r.ID); err != nil {
			return Empty{}, err
		}
		return Empty{}, mapErr(s.Backend.Remove(ctx, r.ID))
	})
	ipc.Handle(srv, OpInspect, p, func(ctx context.Context, _ ipc.Caller, r IDReq) (*Workload, error) {
		if err := checkWorkloadID(r.ID); err != nil {
			return nil, err
		}
		w, err := s.Backend.Inspect(ctx, r.ID)
		return w, mapErr(err)
	})
	ipc.Handle(srv, OpList, p, func(ctx context.Context, _ ipc.Caller, r ListReq) ([]Workload, error) {
		f := map[string]string{}
		if r.EnvironmentID != "" {
			f["environment"] = r.EnvironmentID
		}
		if r.ProjectID != "" {
			f["project"] = r.ProjectID
		}
		if r.DeploymentID != "" {
			f["deployment"] = r.DeploymentID
		}
		return s.Backend.List(ctx, f)
	})
	ipc.Handle(srv, OpLogs, p, func(ctx context.Context, _ ipc.Caller, r LogsReq) ([]LogLine, error) {
		if err := checkWorkloadID(r.ID); err != nil {
			return nil, err
		}
		var since time.Time
		if r.Since != "" {
			since, _ = time.Parse(time.RFC3339Nano, r.Since)
		}
		l, err := s.Backend.Logs(ctx, r.ID, r.Tail, since)
		return l, mapErr(err)
	})
}

// Client is the typed runtimed client.
type Client struct{ C *ipc.Client }

func (c *Client) Capabilities(ctx context.Context) (*Capabilities, error) {
	return ipc.Call[Empty, *Capabilities](ctx, c.C, OpCapabilities, Empty{})
}
func (c *Client) EnsureNetwork(ctx context.Context, n NetworkSpec) (*NetworkInfo, error) {
	return ipc.Call[NetworkSpec, *NetworkInfo](ctx, c.C, OpNetworkEnsure, n)
}
func (c *Client) RemoveNetwork(ctx context.Context, envID string) error {
	_, err := ipc.Call[EnvReq, Empty](ctx, c.C, OpNetworkRemove, EnvReq{EnvironmentID: envID})
	return err
}
func (c *Client) Start(ctx context.Context, s Spec) (*Workload, error) {
	return ipc.Call[Spec, *Workload](ctx, c.C, OpStart, s)
}
func (c *Client) Stop(ctx context.Context, id string, timeout time.Duration) error {
	_, err := ipc.Call[IDReq, Empty](ctx, c.C, OpStop, IDReq{ID: id, Timeout: int(timeout.Seconds())})
	return err
}
func (c *Client) Remove(ctx context.Context, id string) error {
	_, err := ipc.Call[IDReq, Empty](ctx, c.C, OpRemove, IDReq{ID: id})
	return err
}
func (c *Client) Inspect(ctx context.Context, id string) (*Workload, error) {
	return ipc.Call[IDReq, *Workload](ctx, c.C, OpInspect, IDReq{ID: id})
}
func (c *Client) List(ctx context.Context, r ListReq) ([]Workload, error) {
	return ipc.Call[ListReq, []Workload](ctx, c.C, OpList, r)
}
func (c *Client) Logs(ctx context.Context, id string, tail int, since time.Time) ([]LogLine, error) {
	r := LogsReq{ID: id, Tail: tail}
	if !since.IsZero() {
		r.Since = since.Format(time.RFC3339Nano)
	}
	return ipc.Call[LogsReq, []LogLine](ctx, c.C, OpLogs, r)
}

// Fake is an in-memory Backend for tests and for exercising orchestration
// without a container engine. Workloads "listen" at the address returned by
// EndpointFor (tests usually point it at an httptest server).
type Fake struct {
	mu          sync.Mutex
	W           map[string]*Workload
	Specs       map[string]Spec
	Networks    map[string]bool
	Runtimes    map[string]bool
	EndpointFor func(s *Spec) string
	FailStart   func(s *Spec) error
}

func NewFake() *Fake {
	return &Fake{W: map[string]*Workload{}, Specs: map[string]Spec{}, Networks: map[string]bool{}, Runtimes: map[string]bool{RuntimeRunc: true}}
}

func (f *Fake) Name() string { return "fake" }
func (f *Fake) Capabilities(context.Context) (*Capabilities, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rt := map[string]bool{}
	for k, v := range f.Runtimes {
		rt[k] = v
	}
	return &Capabilities{Backend: "fake", Runtimes: rt, Devices: map[string]bool{}}, nil
}
func (f *Fake) EnsureNetwork(_ context.Context, n NetworkSpec) (*NetworkInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Networks[n.EnvironmentID] = true
	return &NetworkInfo{ID: n.EnvironmentID, Name: NetworkName(n.EnvironmentID)}, nil
}
func (f *Fake) RemoveNetwork(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.Networks, id)
	return nil
}
func (f *Fake) Start(_ context.Context, s *Spec, _ RegistryAuth) (*Workload, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailStart != nil {
		if err := f.FailStart(s); err != nil {
			return nil, err
		}
	}
	if w, ok := f.W[s.ID]; ok {
		w.State = "running"
		return w, nil
	}
	if !f.Networks[s.EnvironmentID] {
		return nil, fmt.Errorf("network for %s missing", s.EnvironmentID)
	}
	ep := ""
	if f.EndpointFor != nil {
		ep = f.EndpointFor(s)
	}
	w := &Workload{ID: s.ID, RuntimeID: "fake-" + s.ID, State: "running", Endpoint: ep, Labels: s.Labels(), StartedAt: time.Now().UTC().Format(time.RFC3339)}
	f.W[s.ID] = w
	f.Specs[s.ID] = *s
	cp := *w
	return &cp, nil
}
func (f *Fake) Stop(_ context.Context, id string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if w, ok := f.W[id]; ok {
		w.State = "exited"
	}
	return nil
}
func (f *Fake) Remove(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.W, id)
	delete(f.Specs, id)
	return nil
}
func (f *Fake) Inspect(_ context.Context, id string) (*Workload, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w, ok := f.W[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *w
	return &cp, nil
}
func (f *Fake) List(_ context.Context, filter map[string]string) ([]Workload, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Workload
	for _, w := range f.W {
		match := true
		for k, v := range filter {
			if w.Labels["org.opendeploy."+k] != v {
				match = false
			}
		}
		if match {
			out = append(out, *w)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (f *Fake) Logs(_ context.Context, id string, _ int, _ time.Time) ([]LogLine, error) {
	return []LogLine{{Stream: "stdout", Text: "fake log for " + id}}, nil
}

// Running returns the number of running workloads (tests).
func (f *Fake) Running() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, w := range f.W {
		if w.State == "running" {
			n++
		}
	}
	return n
}
