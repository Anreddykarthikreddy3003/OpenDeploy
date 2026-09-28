package platform

// Hooks implemented in later milestones (previews M4, domains M5,
// backups M7). They are defined here so the orchestrator compiles and
// behaves safely (no preview auth, no-op checks) until then.

import (
	"context"
	"errors"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/router"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// DNSResolver resolves TXT and address records for domain claims.
type DNSResolver interface {
	TXT(ctx context.Context, name string) ([]string, error)
}

type netDNS struct{ server string }

func (n *netDNS) TXT(ctx context.Context, name string) ([]string, error) {
	return nil, errors.New("dns resolver not implemented yet")
}

func (p *Platform) previewAuth(ctx context.Context, env *store.Environment) *router.BasicAuth {
	return nil
}

func (p *Platform) checkDomainTLS(ctx context.Context, domainID string) error { return nil }

func (p *Platform) runBackupJob(ctx context.Context, job *store.Job) error {
	return &PermanentError{errors.New("backups are not configured")}
}
