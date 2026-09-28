// Package platform is platformd's orchestration core: the durable
// deployment state machine, generation-safe promotion, layered health
// evidence, the reconciler, GitHub event ingress and route computation
// (PRD §6, §11, §16, §18). It depends on the other Tier-0 services only
// through narrow interfaces so they can run as separate identities.
package platform

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/artifact"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/build/builder"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/domains"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/network"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/relay"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/router"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/runtime"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/secrets"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// Builder is the builderd surface used by platformd.
type Builder interface {
	Start(ctx context.Context, r builder.Req) (*builder.Status, error)
	Status(ctx context.Context, id string, after int64) (*builder.Status, error)
	Cancel(ctx context.Context, id string) error
	Forget(ctx context.Context, id string) error
	Plan(ctx context.Context, r builder.PlanReq) (*builder.PlanResp, error)
}

// Runtime is the runtimed surface.
type Runtime interface {
	Capabilities(ctx context.Context) (*runtime.Capabilities, error)
	EnsureNetwork(ctx context.Context, n runtime.NetworkSpec) (*runtime.NetworkInfo, error)
	RemoveNetwork(ctx context.Context, envID string) error
	Start(ctx context.Context, s runtime.Spec) (*runtime.Workload, error)
	Stop(ctx context.Context, id string, timeout time.Duration) error
	Remove(ctx context.Context, id string) error
	Inspect(ctx context.Context, id string) (*runtime.Workload, error)
	List(ctx context.Context, r runtime.ListReq) ([]runtime.Workload, error)
	Logs(ctx context.Context, id string, tail int, since time.Time) ([]runtime.LogLine, error)
}

// Router is the routemgr surface.
type Router interface {
	Apply(ctx context.Context, t router.Table, verify []string) (*router.ApplyResult, error)
	Current(ctx context.Context) (*router.CurrentResp, error)
}

// Artifacts is the artifactd surface.
type Artifacts interface {
	GC(ctx context.Context, r artifact.GCReq) (*artifact.GCResp, error)
}

// AuditReader reads the audit chain (auditd).
type AuditReader interface {
	Query(ctx context.Context, q audit.Query) ([]audit.Event, error)
	Verify(ctx context.Context) (audit.VerifyResult, error)
}

// Deps wires the platform to its collaborators.
type Deps struct {
	Store       *store.Store
	Node        *config.Node
	Builder     Builder
	Runtime     Runtime
	Router      Router
	Artifacts   Artifacts
	Secrets     secrets.Broker
	Audit       audit.Sink
	AuditReader AuditReader
	Egress      network.Enforcer
	GitHub      *GitHubProvider
	Log         *slog.Logger
	// HealthClient probes workloads; tests may replace it.
	HealthClient *http.Client
	// DNS verifies domain claims against authoritative servers (tests
	// replace it).
	DNS domains.Verifier
	// TLSProbe inspects the edge certificate for a domain (tests replace it).
	TLSProbe TLSProbe
	// Host is the privileged host agent (nil in dev / single-process mode).
	Host HostAgent
	// Backups exports per-service state for backups.
	Backups BackupExporters
	// Relay reports the relay tunnel (relay ingress mode only).
	Relay interface {
		Status(ctx context.Context) (*relay.Status, error)
	}
	// InsecureNoNetworkPolicy allows deployments without egress enforcement.
	// Only honoured in dev mode.
	InsecureNoNetworkPolicy bool
}

// Platform is the orchestrator.
type Platform struct {
	Deps
	Events *Bus
	nodeID string

	capMu    sync.Mutex
	caps     *HostCaps
	capsAt   time.Time
	workerID string
}

// New creates a platform.
func New(d Deps) *Platform {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Audit == nil {
		d.Audit = audit.Nop{}
	}
	if d.HealthClient == nil {
		d.HealthClient = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	}
	if d.Egress == nil {
		d.Egress = network.Nop{}
	}
	if d.DNS == nil {
		d.DNS = domains.NewResolver(d.Node.Ingress.DNSResolver)
	}
	host, _ := os.Hostname()
	return &Platform{Deps: d, Events: NewBus(), nodeID: "node_" + host, workerID: ids.New("wrk")}
}

// Job kinds.
const (
	JobDeploy        = "deploy"
	JobPromote       = "promote"
	JobEnvTeardown   = "env.teardown"
	JobProjectDelete = "project.delete"
	JobDomainCheck   = "domain.check"
	JobBackup        = "backup"
)

// Run starts workers and the reconciler until ctx is done.
func (p *Platform) Run(ctx context.Context) {
	workers := p.Node.Build.MaxConcurrent + 2
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.worker(ctx)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.reconcileLoop(ctx)
	}()
	wg.Wait()
}

// ErrRetry signals a transient condition; the job is re-queued with backoff.
var ErrRetry = errors.New("retry later")

// PermanentError marks failures that must not be retried.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

func (p *Platform) worker(ctx context.Context) {
	kinds := []string{JobDeploy, JobPromote, JobEnvTeardown, JobProjectDelete, JobDomainCheck, JobBackup}
	for {
		if ctx.Err() != nil {
			return
		}
		if p.Store.DB.Degraded() != "" {
			sleep(ctx, 10*time.Second)
			continue
		}
		job, err := p.Store.ClaimJob(ctx, p.workerID, kinds, 2*time.Minute)
		if err != nil {
			p.Log.Error("claim job", "err", err)
			sleep(ctx, 2*time.Second)
			continue
		}
		if job == nil {
			sleep(ctx, 500*time.Millisecond)
			continue
		}
		p.runJob(ctx, job)
	}
}

func (p *Platform) runJob(ctx context.Context, job *store.Job) {
	jctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Keep the lease alive while the job runs.
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-jctx.Done():
				return
			case <-t.C:
				_ = p.Store.ExtendLease(context.Background(), job.ID, 2*time.Minute)
			}
		}
	}()
	err := p.dispatch(jctx, job)
	if ctx.Err() != nil {
		return // shutting down; lease expiry re-queues the job
	}
	if err == nil {
		_ = p.Store.CompleteJob(ctx, job.ID)
		return
	}
	var pe *PermanentError
	dead, ferr := p.Store.FailJob(ctx, job.ID, err.Error(), errors.As(err, &pe))
	if ferr != nil {
		p.Log.Error("record job failure", "job", job.ID, "err", ferr)
	}
	if dead {
		p.Log.Error("job failed permanently", "job", job.ID, "kind", job.Kind, "err", err)
	} else {
		p.Log.Warn("job will retry", "job", job.ID, "kind", job.Kind, "err", err)
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// Bus is a small in-process pub/sub for live UI updates (SSE).
type Bus struct {
	mu   sync.Mutex
	subs map[string]map[chan Event]struct{}
}

// Event is a notification; Topic is "deployment:<id>" or "project:<id>".
type Event struct {
	Topic string `json:"topic"`
	Type  string `json:"type"` // status | log | workload | domain
	Data  any    `json:"data"`
}

func NewBus() *Bus { return &Bus{subs: map[string]map[chan Event]struct{}{}} }

// Subscribe returns a channel of events for topic and an unsubscribe func.
func (b *Bus) Subscribe(topic string) (<-chan Event, func()) {
	ch := make(chan Event, 256)
	b.mu.Lock()
	if b.subs[topic] == nil {
		b.subs[topic] = map[chan Event]struct{}{}
	}
	b.subs[topic][ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs[topic], ch)
		if len(b.subs[topic]) == 0 {
			delete(b.subs, topic)
		}
		b.mu.Unlock()
	}
}

// Publish delivers without blocking (slow subscribers drop events).
func (b *Bus) Publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs[e.Topic] {
		select {
		case ch <- e:
		default:
		}
	}
}
