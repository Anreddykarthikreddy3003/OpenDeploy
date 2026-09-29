package platform

import (
	"context"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/hostops"
)

type supportBundler interface {
	SupportBundle(ctx context.Context) (*hostops.SupportBundle, error)
}

// SupportBundle asks hostd for a redacted diagnostics archive (node
// configuration, service status and recent logs; secrets are redacted).
func (p *Platform) SupportBundle(ctx context.Context) (*hostops.SupportBundle, error) {
	sb, ok := p.Host.(supportBundler)
	if p.Host == nil || !ok {
		return nil, ErrNoHostAgent
	}
	return sb.SupportBundle(ctx)
}
