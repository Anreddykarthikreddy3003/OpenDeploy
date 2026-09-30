package runtime

import (
	"context"
	"os"
	"path/filepath"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/backup"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

// OpVolumeExport tars persistent volumes for a backup (crash-consistent;
// database templates should also run their own dump hooks).
const OpVolumeExport = "runtime.volume_export"

type VolumeExportReq struct {
	BackupID  string   `json:"backup_id"`
	VolumeIDs []string `json:"volume_ids"`
}

type VolumeExportResp struct {
	Files map[string]string `json:"files"` // volume id -> staged file
}

// RegisterBackup exposes volume export to the backup coordinator.
func RegisterBackup(srv *ipc.Server, volumesDir, staging string) {
	ipc.Handle(srv, OpVolumeExport, []string{identity.Platform}, func(ctx context.Context, _ ipc.Caller, r VolumeExportReq) (*VolumeExportResp, error) {
		out := &VolumeExportResp{Files: map[string]string{}}
		for _, id := range r.VolumeIDs {
			if !ids.HasPrefix(id, "vol") {
				return nil, ipc.Errorf(ipc.CodeBadRequest, "invalid volume id %q", id)
			}
			src := filepath.Join(volumesDir, id)
			if _, err := os.Stat(src); err != nil {
				continue // never materialised
			}
			dst, err := backup.StagingFile(staging, r.BackupID, "volume-"+id+".tar")
			if err != nil {
				return nil, ipc.Errorf(ipc.CodeBadRequest, "%v", err)
			}
			tmp := filepath.Join(staging, ".tmp-"+filepath.Base(dst))
			f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
			if err != nil {
				return nil, err
			}
			err = backup.TarDir(f, src, nil)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err == nil {
				err = backup.Shared(tmp) // platformd reads it via od-backup
			}
			if err != nil {
				os.Remove(tmp)
				return nil, err
			}
			if err := os.Rename(tmp, dst); err != nil {
				return nil, err
			}
			out.Files[id] = dst
		}
		return out, nil
	})
}

// VolumeExport asks runtimed to export volumes.
func (c *Client) VolumeExport(ctx context.Context, backupID string, volumeIDs []string) (map[string]string, error) {
	r, err := ipc.Call[VolumeExportReq, *VolumeExportResp](ctx, c.C, OpVolumeExport, VolumeExportReq{BackupID: backupID, VolumeIDs: volumeIDs})
	if err != nil {
		return nil, err
	}
	return r.Files, nil
}
