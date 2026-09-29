package platform

import (
	"context"
	"errors"
	"testing"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/network"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/trust"
)

type egressStub struct {
	network.Nop
	st  *network.Status
	err error
}

func (e *egressStub) Status(context.Context) (*network.Status, error) { return e.st, e.err }

// Network policy is fail-closed either way, but an enforcer that is only
// unreachable (egressd restarting) must make the deploy retry, not fail it
// for good; a node that answers "not enforcing" is a permanent verdict.
func TestDecideRetriesWhileEgressdIsUnreachable(t *testing.T) {
	h := newHarness(t)
	h.p.InsecureNoNetworkPolicy = false
	eg := &egressStub{err: ipc.Errorf(ipc.CodeUnavailable, "dial unix /run/opendeploy/egressd.sock: connect: no such file or directory")}
	h.p.Egress = eg
	ctx := context.Background()
	_, err := h.p.decide(ctx, h.prj, h.env, nil)
	if !errors.Is(err, trust.ErrNoNetworkPolicy) || !isTransient(err) {
		t.Fatalf("unreachable egressd: %v (transient=%v), want a retryable fail-closed error", err, isTransient(err))
	}
	// Not cached: once egressd answers, the next attempt proceeds.
	eg.err, eg.st = nil, &network.Status{Enforcing: true}
	if _, err := h.p.decide(ctx, h.prj, h.env, nil); err != nil {
		t.Fatalf("after egressd came back: %v", err)
	}
	// An enforcer that answers but does not enforce is a verdict.
	h.p.caps = nil
	eg.st = &network.Status{Enforcing: false, Message: "nftables unavailable"}
	_, err = h.p.decide(ctx, h.prj, h.env, nil)
	if !errors.Is(err, trust.ErrNoNetworkPolicy) || isTransient(err) {
		t.Fatalf("non-enforcing node: %v (transient=%v), want a permanent refusal", err, isTransient(err))
	}
}
