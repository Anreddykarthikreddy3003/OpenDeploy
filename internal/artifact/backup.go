package artifact

import (
	"context"
	"os"
	"path/filepath"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/backup"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

// OpBackupExport tars the artifact store (retained images and static
// builds; garbage collection keeps it to what rollbacks can reach).
const OpBackupExport = "artifact.backup_export"

type BackupExportReq struct {
	BackupID string `json:"backup_id"`
}

type BackupExportResp struct {
	File string `json:"file"`
}

// RegisterBackup exposes the export op to the backup coordinator.
func RegisterBackup(srv *ipc.Server, st *Store, staging string) {
	ipc.Handle(srv, OpBackupExport, []string{identity.Platform}, func(ctx context.Context, _ ipc.Caller, r BackupExportReq) (*BackupExportResp, error) {
		dst, err := backup.StagingFile(staging, r.BackupID, "artifacts.tar")
		if err != nil {
			return nil, ipc.Errorf(ipc.CodeBadRequest, "%v", err)
		}
		tmp := filepath.Join(staging, ".tmp-"+filepath.Base(dst))
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, err
		}
		err = backup.TarDir(f, st.Root, func(rel string) bool { return rel == "tmp" })
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(tmp)
			return nil, err
		}
		if err := os.Rename(tmp, dst); err != nil {
			return nil, err
		}
		return &BackupExportResp{File: dst}, nil
	})
}

// BackupExport asks artifactd to export its store.
func (c *Client) BackupExport(ctx context.Context, backupID string) (string, error) {
	r, err := ipc.Call[BackupExportReq, *BackupExportResp](ctx, c.C, OpBackupExport, BackupExportReq{BackupID: backupID})
	if err != nil {
		return "", err
	}
	return r.File, nil
}
