package api

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestReadinessProbeSharedAndNeverUnprobed(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	s := &Server{Ready: func(ctx context.Context) map[string]string {
		calls.Add(1)
		<-release
		if ctx.Err() != nil {
			return map[string]string{"x": "cancelled"}
		}
		return map[string]string{}
	}}
	first := make(chan map[string]string)
	go func() { first <- s.readiness() }()
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	// While the first probe runs, others neither probe again nor report
	// ready without a result.
	if got := s.readiness(); len(got) == 0 {
		t.Fatal("reported ready before any probe finished")
	}
	close(release)
	if got := <-first; len(got) != 0 {
		t.Fatalf("first probe: %v", got)
	}
	if got := s.readiness(); len(got) != 0 || calls.Load() != 1 {
		t.Fatalf("cached result %v after %d probes", got, calls.Load())
	}
}
