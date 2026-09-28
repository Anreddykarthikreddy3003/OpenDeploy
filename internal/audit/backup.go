package audit

import (
	"context"
	"os"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/backup"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

// OpSnapshot exports a consistent audit DB copy for a backup.
const OpSnapshot = "audit.snapshot"

type SnapshotReq struct {
	BackupID string `json:"backup_id"`
}

type SnapshotResp struct {
	File string `json:"file"`
}

// Snapshot writes a consistent copy of the audit DB into dir.
func (s *Store) Snapshot(ctx context.Context, dir string) (string, error) {
	return s.db.Snapshot(ctx, dir, "backup")
}

// RegisterBackup exposes the snapshot op to the backup coordinator.
func RegisterBackup(srv *ipc.Server, st *Store, staging string) {
	ipc.Handle(srv, OpSnapshot, []string{identity.Platform}, func(ctx context.Context, _ ipc.Caller, r SnapshotReq) (*SnapshotResp, error) {
		dst, err := backup.StagingFile(staging, r.BackupID, "audit.db")
		if err != nil {
			return nil, ipc.Errorf(ipc.CodeBadRequest, "%v", err)
		}
		tmp, err := os.MkdirTemp(staging, ".audit-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp)
		p, err := st.Snapshot(ctx, tmp)
		if err != nil {
			return nil, err
		}
		if err := os.Rename(p, dst); err != nil {
			return nil, err
		}
		_ = os.Chmod(dst, 0o640)
		return &SnapshotResp{File: dst}, nil
	})
}

// Snapshot asks auditd for a backup snapshot.
func (c *Client) Snapshot(ctx context.Context, backupID string) (string, error) {
	r, err := ipc.Call[SnapshotReq, *SnapshotResp](ctx, c.C, OpSnapshot, SnapshotReq{BackupID: backupID})
	if err != nil {
		return "", err
	}
	return r.File, nil
}
