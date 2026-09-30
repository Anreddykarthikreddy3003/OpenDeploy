package platform

import (
	"context"
	"errors"
	"testing"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/hostops"
)

type bundleHost struct{ calls int }

func (h *bundleHost) ApplyUpdate(context.Context, string, string) error { return nil }
func (h *bundleHost) SupportBundle(context.Context) (*hostops.SupportBundle, error) {
	h.calls++
	return &hostops.SupportBundle{Path: "/var/lib/opendeploy/support/support-x.tar.gz", SHA256: "ab"}, nil
}

type updateOnlyHost struct{}

func (updateOnlyHost) ApplyUpdate(context.Context, string, string) error { return nil }

func TestSupportBundleNeedsHostd(t *testing.T) {
	p := &Platform{}
	if _, err := p.SupportBundle(context.Background()); !errors.Is(err, ErrNoHostAgent) {
		t.Fatalf("without hostd: %v", err)
	}
	p.Host = updateOnlyHost{}
	if _, err := p.SupportBundle(context.Background()); !errors.Is(err, ErrNoHostAgent) {
		t.Fatalf("host without bundles: %v", err)
	}
	h := &bundleHost{}
	p.Host = h
	if b, err := p.SupportBundle(context.Background()); err != nil || b.SHA256 != "ab" || h.calls != 1 {
		t.Fatalf("bundle: %+v %v", b, err)
	}
}
