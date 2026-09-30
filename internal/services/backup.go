package services

import "context"

// backupExporters adapts the typed IPC clients to platform.BackupExporters.
type backupExporters struct{ c *Clients }

func (b backupExporters) AuditSnapshot(ctx context.Context, id string) (string, error) {
	return b.c.Audit.Snapshot(ctx, id)
}

func (b backupExporters) SecretsExport(ctx context.Context, id string, dek []byte) (string, error) {
	return b.c.Secrets.BackupExport(ctx, id, dek)
}

func (b backupExporters) ArtifactsExport(ctx context.Context, id string) (string, error) {
	return b.c.Artifact.BackupExport(ctx, id)
}

func (b backupExporters) VolumesExport(ctx context.Context, id string, vols []string) (map[string]string, error) {
	return b.c.Runtime.VolumeExport(ctx, id, vols)
}
