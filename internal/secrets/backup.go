package secrets

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/backup"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

// OpBackupExport seals secretd's state (ciphertext DB + key ring) with the
// backup's data key. The coordinator (platformd) never sees the KEKs in
// plaintext; only a holder of the backup master key can open the bundle.
const OpBackupExport = "secrets.backup_export"

type BackupExportReq struct {
	BackupID string `json:"backup_id"`
	DEK      []byte `json:"dek"`
}

type BackupExportResp struct {
	File string `json:"file"`
}

func bundleAAD(id string) string { return "secrets-bundle:" + id }

// ExportBundle returns the sealed bundle bytes.
func (s *Store) ExportBundle(ctx context.Context, backupID string, dek []byte) ([]byte, error) {
	tmp, err := os.MkdirTemp("", "secrets-backup-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	snap, err := s.Snapshot(ctx, tmp)
	if err != nil {
		return nil, err
	}
	db, err := os.ReadFile(snap)
	if err != nil {
		return nil, err
	}
	kr, err := s.ExportKeyRing()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, b := range map[string][]byte{"keyring.json": kr, "secrets.db": db} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return backup.Wrap(dek, buf.Bytes(), bundleAAD(backupID))
}

// OpenBundle reverses ExportBundle (used by offline restore).
func OpenBundle(sealed, dek []byte, backupID string) (keyring, db []byte, err error) {
	plain, err := backup.Unwrap(dek, sealed, bundleAAD(backupID))
	if err != nil {
		return nil, nil, err
	}
	tr := tar.NewReader(bytes.NewReader(plain))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		b, err := io.ReadAll(io.LimitReader(tr, 1<<30))
		if err != nil {
			return nil, nil, err
		}
		switch h.Name {
		case "keyring.json":
			keyring = b
		case "secrets.db":
			db = b
		}
	}
	if keyring == nil || db == nil {
		return nil, nil, fmt.Errorf("secrets bundle incomplete")
	}
	return keyring, db, nil
}

// RegisterBackup exposes the export op to the backup coordinator.
func RegisterBackup(srv *ipc.Server, s *Service, staging string) {
	ipc.Handle(srv, OpBackupExport, []string{identity.Platform}, func(ctx context.Context, _ ipc.Caller, r BackupExportReq) (*BackupExportResp, error) {
		if len(r.DEK) != 32 {
			return nil, ipc.Errorf(ipc.CodeBadRequest, "data key must be 32 bytes")
		}
		dst, err := backup.StagingFile(staging, r.BackupID, "secrets.sealed")
		if err != nil {
			return nil, ipc.Errorf(ipc.CodeBadRequest, "%v", err)
		}
		sealed, err := s.Store.ExportBundle(ctx, r.BackupID, r.DEK)
		if err != nil {
			return nil, err
		}
		tmp := filepath.Join(staging, ".tmp-"+filepath.Base(dst))
		if err := os.WriteFile(tmp, sealed, 0o640); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, dst); err != nil {
			return nil, err
		}
		s.audit(ctx, Actor{Type: audit.ActorService, ID: identity.Platform}, "secrets.backup_export", "", r.BackupID, audit.Success, nil)
		return &BackupExportResp{File: dst}, nil
	})
}

// BackupExport asks secretd for the sealed bundle.
func (c *Client) BackupExport(ctx context.Context, backupID string, dek []byte) (string, error) {
	r, err := ipc.Call[BackupExportReq, *BackupExportResp](ctx, c.C, OpBackupExport, BackupExportReq{BackupID: backupID, DEK: dek})
	if err != nil {
		return "", err
	}
	return r.File, nil
}
