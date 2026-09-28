package platform

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/backup"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/cronexpr"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/daemon"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// BackupExporters are the per-service export calls (least privilege: each
// service exports its own state; secretd seals its bundle itself).
type BackupExporters interface {
	AuditSnapshot(ctx context.Context, id string) (string, error)
	SecretsExport(ctx context.Context, id string, dek []byte) (string, error)
	ArtifactsExport(ctx context.Context, id string) (string, error)
	VolumesExport(ctx context.Context, id string, volumeIDs []string) (map[string]string, error)
}

// BackupStatus is shown in the dashboard.
type BackupStatus struct {
	Enabled         bool        `json:"enabled"`
	Schedule        string      `json:"schedule"`
	Target          string      `json:"target"`
	ObjectLock      bool        `json:"object_lock"`
	RetainDays      int         `json:"retain_days"`
	MasterKeyID     string      `json:"master_key_id,omitempty"`
	SignerPublicKey string      `json:"signer_public_key,omitempty"`
	Last            *LastBackup `json:"last,omitempty"`
	ConfigError     string      `json:"config_error,omitempty"`
}

// LastBackup records the most recent run.
type LastBackup struct {
	ID       string `json:"id"`
	At       string `json:"at"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Size     int64  `json:"size"`
	Duration string `json:"duration"`
}

func (p *Platform) backupKeyPaths() (master, signer string) {
	master = p.Node.Backup.MasterKey
	if master == "" {
		master = filepath.Join(p.Node.ServiceDir(identity.Platform), "backup-master.key")
	}
	return master, filepath.Join(p.Node.ServiceDir(identity.Platform), "backup-signing.key")
}

func (p *Platform) backupKeys() (backup.MasterKey, ed25519.PrivateKey, error) {
	mp, sp := p.backupKeyPaths()
	mk, created, err := backup.LoadOrCreateMasterKey(mp)
	if err != nil {
		return mk, nil, err
	}
	if created {
		p.Log.Warn("generated a new backup master key: export it (Platform → Backups) and store it OFF this node; restores are impossible without it", "path", mp)
	}
	sk, err := daemon.LoadOrCreateEd25519(sp)
	return mk, sk, err
}

// BackupStatus describes configuration and the last run.
func (p *Platform) BackupStatus(ctx context.Context) *BackupStatus {
	c := p.Node.Backup
	st := &BackupStatus{Enabled: c.Enabled, Schedule: c.Schedule, ObjectLock: c.ObjectLock, RetainDays: c.RetainDays}
	if t, _, err := backup.TargetFromConfig(c); err == nil {
		st.Target = t.String()
	} else {
		st.ConfigError = err.Error()
	}
	if mk, sk, err := p.backupKeys(); err == nil {
		st.MasterKeyID = mk.ID()
		st.SignerPublicKey = base64.StdEncoding.EncodeToString(sk.Public().(ed25519.PublicKey))
	}
	var last LastBackup
	if ok, _ := p.Store.GetSetting(ctx, "backup_last", &last); ok {
		st.Last = &last
	}
	return st
}

// ExportMasterKey returns the backup master key (owner, re-authenticated).
func (p *Platform) ExportMasterKey() (string, error) {
	mk, _, err := p.backupKeys()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", mk[:]), nil
}

// BackupSummary is one listed backup.
type BackupSummary struct {
	ID         string             `json:"id"`
	CreatedAt  time.Time          `json:"created_at"`
	Size       int64              `json:"size"`
	Components []backup.Component `json:"components"`
	Version    string             `json:"version"`
	Locked     bool               `json:"object_lock"`
	Error      string             `json:"error,omitempty"`
}

// ListBackups reads manifests (newest first).
func (p *Platform) ListBackups(ctx context.Context, limit int) ([]BackupSummary, error) {
	t, prefix, err := backup.TargetFromConfig(p.Node.Backup)
	if err != nil {
		return nil, err
	}
	ids, err := backup.List(ctx, t, prefix)
	if err != nil {
		return nil, err
	}
	if limit > 0 && len(ids) > limit {
		ids = ids[:limit]
	}
	out := make([]BackupSummary, 0, len(ids))
	for _, id := range ids {
		m, err := backup.ReadManifest(ctx, t, prefix, id, nil)
		if err != nil {
			out = append(out, BackupSummary{ID: id, Error: err.Error()})
			continue
		}
		out = append(out, BackupSummary{ID: id, CreatedAt: m.CreatedAt, Size: m.CipherSize, Components: m.Components, Version: m.Version, Locked: m.ObjectLockActive})
	}
	return out, nil
}

// RunBackup performs a full backup now.
func (p *Platform) RunBackup(ctx context.Context) (*backup.Manifest, error) {
	start := time.Now()
	c := p.Node.Backup
	target, prefix, err := backup.TargetFromConfig(c)
	if err != nil {
		return nil, &PermanentError{err}
	}
	if p.Backups == nil {
		return nil, &PermanentError{errors.New("backup exporters not wired")}
	}
	mk, signer, err := p.backupKeys()
	if err != nil {
		return nil, &PermanentError{err}
	}
	id := backup.NewID(start)
	dek := backup.NewDEK()
	staging := p.Node.BackupStagingDir()
	if err := os.MkdirAll(staging, 0o770); err != nil {
		return nil, err
	}
	defer func() {
		matches, _ := filepath.Glob(filepath.Join(staging, id+"-*"))
		for _, m := range matches {
			os.Remove(m)
		}
	}()
	var srcs []backup.Source
	add := func(name, kind, ref, path string) {
		srcs = append(srcs, backup.Source{Component: backup.Component{Name: name, Kind: kind, Ref: ref}, Path: path})
	}
	// platformd's own DB.
	tmp, err := os.MkdirTemp(staging, ".platform-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	snap, err := p.Store.DB.Snapshot(ctx, tmp, "backup")
	if err != nil {
		return nil, fmt.Errorf("platform snapshot: %w", err)
	}
	add("platform/platform.db", "platform-db", "", snap)
	f, err := p.Backups.AuditSnapshot(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("audit snapshot: %w", err)
	}
	add("audit/audit.db", "audit-db", "", f)
	f, err = p.Backups.SecretsExport(ctx, id, dek)
	if err != nil {
		return nil, fmt.Errorf("secrets export: %w", err)
	}
	add("secrets/bundle.sealed", "secrets", "", f)
	if c.IncludeArtifacts == nil || *c.IncludeArtifacts {
		f, err = p.Backups.ArtifactsExport(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("artifacts export: %w", err)
		}
		add("artifacts/store.tar", "artifacts", "", f)
	}
	vols, err := p.Store.BackupVolumes(ctx)
	if err != nil {
		return nil, err
	}
	if len(vols) > 0 {
		files, err := p.Backups.VolumesExport(ctx, id, vols)
		if err != nil {
			return nil, fmt.Errorf("volume export: %w", err)
		}
		for _, v := range vols {
			if f, ok := files[v]; ok {
				add("volumes/"+v+".tar", "volume", v, f)
			}
		}
	}
	m, err := backup.Create(ctx, backup.Options{ID: id, Node: p.nodeID, Version: daemon.Version, SchemaVersion: store.SchemaVersion, Sources: srcs,
		Target: target, Prefix: prefix, Master: mk, Signer: signer, DEK: dek, StageDir: staging,
		RetainUntil: backup.RetainUntil(c, start), ObjectLock: c.ObjectLock})
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (p *Platform) runBackupJob(ctx context.Context, job *store.Job) error {
	start := time.Now()
	m, err := p.RunBackup(ctx)
	last := LastBackup{At: state.Now(), OK: err == nil, Duration: time.Since(start).Round(time.Second).String()}
	details := map[string]string{}
	result := audit.Success
	if err != nil {
		last.Error = truncate(err.Error(), 500)
		details["reason"] = last.Error
		result = audit.Failure
	} else {
		last.ID, last.Size = m.ID, m.CipherSize
		details["target"] = strings.TrimSpace(m.ID)
	}
	_ = p.Store.SetSetting(ctx, "backup_last", last)
	_, _ = p.Audit.Append(ctx, audit.Event{ActorType: audit.ActorService, ActorID: "platformd", Action: "backup.create", ResourceType: "backup",
		ResourceID: last.ID, Result: result, Details: details})
	if err != nil {
		p.Log.Error("backup failed", "err", err)
	} else {
		p.Log.Info("backup completed", "id", m.ID, "bytes", m.CipherSize)
	}
	return err
}

// EnqueueBackup schedules an immediate backup.
func (p *Platform) EnqueueBackup(ctx context.Context) (string, error) {
	return p.Store.Enqueue(ctx, JobBackup, "backup:manual:"+time.Now().UTC().Format("20060102T1504"), map[string]string{}, 3)
}

// scheduleBackup enqueues the scheduled backup when due (called per minute).
func (p *Platform) scheduleBackup(ctx context.Context, now time.Time) {
	c := p.Node.Backup
	if !c.Enabled {
		return
	}
	sched, err := cronexpr.Parse(c.Schedule)
	if err != nil || !sched.Matches(now.UTC()) {
		return
	}
	_, _ = p.Store.Enqueue(ctx, JobBackup, "backup:scheduled:"+now.UTC().Format("20060102T1504"), map[string]string{}, 3)
}
