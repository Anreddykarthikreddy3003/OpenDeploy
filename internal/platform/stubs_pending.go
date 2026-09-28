package platform

// Hooks implemented in a later milestone (backups M7). Defined here so the
// orchestrator compiles and fails safe until then.

import (
	"context"
	"errors"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

func (p *Platform) runBackupJob(ctx context.Context, job *store.Job) error {
	return &PermanentError{errors.New("backups are not configured")}
}
