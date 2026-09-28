package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
)

// Workloads

type WorkloadRow struct {
	ID            string `json:"id"`
	DeploymentID  string `json:"deployment_id"`
	EnvironmentID string `json:"environment_id"`
	ServiceName   string `json:"service_name"`
	Replica       int    `json:"replica"`
	RuntimeID     string `json:"runtime_id"`
	RuntimeClass  string `json:"runtime_class"`
	Endpoint      string `json:"endpoint"`
	State         string `json:"state"`
	StartedAt     string `json:"started_at"`
	StoppedAt     string `json:"stopped_at"`
	UpdatedAt     string `json:"updated_at"`
}

const wklCols = `id,deployment_id,environment_id,service_name,replica,runtime_id,runtime_class,endpoint,state,started_at,stopped_at,updated_at`

func scanWkl(r interface{ Scan(...any) error }) (*WorkloadRow, error) {
	var w WorkloadRow
	if err := r.Scan(&w.ID, &w.DeploymentID, &w.EnvironmentID, &w.ServiceName, &w.Replica, &w.RuntimeID, &w.RuntimeClass, &w.Endpoint, &w.State, &w.StartedAt, &w.StoppedAt, &w.UpdatedAt); err != nil {
		return nil, notFound(err)
	}
	return &w, nil
}

// EnsureWorkload returns the workload row for (deployment, service, replica),
// creating it with a stable ID if needed (idempotent resume).
func (s *Store) EnsureWorkload(ctx context.Context, depID, envID, service string, replica int, runtimeClass string) (*WorkloadRow, error) {
	var out *WorkloadRow
	err := s.DB.Tx(ctx, func(tx *sql.Tx) error {
		w, err := scanWkl(tx.QueryRowContext(ctx, `SELECT `+wklCols+` FROM workloads WHERE deployment_id=? AND service_name=? AND replica=?`, depID, service, replica))
		if err == nil {
			out = w
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		now := state.Now()
		w = &WorkloadRow{ID: ids.New("wkl"), DeploymentID: depID, EnvironmentID: envID, ServiceName: service, Replica: replica, RuntimeClass: runtimeClass, State: "creating", UpdatedAt: now}
		_, err = tx.ExecContext(ctx, `INSERT INTO workloads(`+wklCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
			w.ID, w.DeploymentID, w.EnvironmentID, w.ServiceName, w.Replica, "", w.RuntimeClass, "", w.State, "", "", now)
		out = w
		return err
	})
	return out, err
}

func (s *Store) UpdateWorkload(ctx context.Context, id, st, runtimeID, endpoint string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		now := state.Now()
		extra := ""
		args := []any{st, now}
		if runtimeID != "" {
			extra += ", runtime_id=?"
			args = append(args, runtimeID)
		}
		if endpoint != "" {
			extra += ", endpoint=?"
			args = append(args, endpoint)
		}
		if st == "running" || st == "healthy" {
			extra += ", started_at=CASE WHEN started_at='' THEN ? ELSE started_at END"
			args = append(args, now)
		}
		if st == "stopped" || st == "failed" {
			extra += ", stopped_at=?"
			args = append(args, now)
		}
		args = append(args, id)
		_, err := tx.ExecContext(ctx, `UPDATE workloads SET state=?, updated_at=?`+extra+` WHERE id=?`, args...)
		return err
	})
}

func (s *Store) WorkloadsForDeployment(ctx context.Context, depID string) ([]*WorkloadRow, error) {
	return s.queryWkl(ctx, `SELECT `+wklCols+` FROM workloads WHERE deployment_id=? ORDER BY service_name, replica`, depID)
}

func (s *Store) WorkloadsForEnvironment(ctx context.Context, envID string) ([]*WorkloadRow, error) {
	return s.queryWkl(ctx, `SELECT `+wklCols+` FROM workloads WHERE environment_id=? ORDER BY updated_at DESC`, envID)
}

func (s *Store) LiveWorkloads(ctx context.Context) ([]*WorkloadRow, error) {
	return s.queryWkl(ctx, `SELECT `+wklCols+` FROM workloads WHERE state NOT IN ('stopped','failed')`)
}

func (s *Store) GetWorkload(ctx context.Context, id string) (*WorkloadRow, error) {
	return scanWkl(s.DB.R().QueryRowContext(ctx, `SELECT `+wklCols+` FROM workloads WHERE id=?`, id))
}

func (s *Store) queryWkl(ctx context.Context, q string, args ...any) ([]*WorkloadRow, error) {
	rows, err := s.DB.R().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WorkloadRow
	for rows.Next() {
		w, err := scanWkl(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// Domains

type Domain struct {
	ID             string          `json:"id"`
	Hostname       string          `json:"hostname"`
	ProjectID      string          `json:"project_id"`
	EnvironmentID  string          `json:"environment_id"`
	Kind           string          `json:"kind"`
	Status         string          `json:"status"`
	ClaimToken     string          `json:"claim_token,omitempty"`
	ClaimExpiresAt string          `json:"claim_expires_at,omitempty"`
	VerifiedAt     string          `json:"verified_at,omitempty"`
	IngressMode    string          `json:"ingress_mode"`
	TLSStatus      string          `json:"tls_status"`
	LastCheck      json.RawMessage `json:"last_check"`
	CreatedAt      string          `json:"created_at"`
	TombstonedAt   string          `json:"tombstoned_at,omitempty"`
}

const domCols = `id,hostname,COALESCE(project_id,''),COALESCE(environment_id,''),kind,status,claim_token,claim_expires_at,verified_at,ingress_mode,tls_status,last_check,created_at,tombstoned_at`

func scanDomain(r interface{ Scan(...any) error }) (*Domain, error) {
	var d Domain
	var lc string
	if err := r.Scan(&d.ID, &d.Hostname, &d.ProjectID, &d.EnvironmentID, &d.Kind, &d.Status, &d.ClaimToken, &d.ClaimExpiresAt, &d.VerifiedAt,
		&d.IngressMode, &d.TLSStatus, &lc, &d.CreatedAt, &d.TombstonedAt); err != nil {
		return nil, notFound(err)
	}
	d.LastCheck = json.RawMessage(lc)
	return &d, nil
}

// CreateDomainClaim inserts a pending claim. A hostname actively owned by
// anyone (verified/active) cannot be claimed.
func (s *Store) CreateDomainClaim(ctx context.Context, d *Domain) error {
	d.Hostname = strings.ToLower(d.Hostname)
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM domains WHERE hostname=? AND status IN ('verified','active')`, d.Hostname).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%w: hostname already attached", ErrConflict)
		}
		// Expire previous pending claims for this hostname by the same project;
		// their tokens must never be accepted again.
		if _, err := tx.ExecContext(ctx, `UPDATE domains SET status='expired', claim_token='', updated_at=? WHERE hostname=? AND status='pending'`, state.Now(), d.Hostname); err != nil {
			return err
		}
		if d.ID == "" {
			d.ID = ids.New("dom")
		}
		now := state.Now()
		d.CreatedAt = now
		if d.Status == "" {
			d.Status = "pending"
		}
		if len(d.LastCheck) == 0 {
			d.LastCheck = json.RawMessage("{}")
		}
		var pid, eid any
		if d.ProjectID != "" {
			pid = d.ProjectID
		}
		if d.EnvironmentID != "" {
			eid = d.EnvironmentID
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO domains(id,hostname,project_id,environment_id,kind,status,claim_token,claim_expires_at,verified_at,ingress_mode,tls_status,last_check,created_at,updated_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, d.ID, d.Hostname, pid, eid, d.Kind, d.Status, d.ClaimToken, d.ClaimExpiresAt, d.VerifiedAt, d.IngressMode,
			firstNonEmpty(d.TLSStatus, "none"), string(d.LastCheck), now, now)
		if isUnique(err) {
			return ErrConflict
		}
		return err
	})
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

func (s *Store) GetDomain(ctx context.Context, id string) (*Domain, error) {
	return scanDomain(s.DB.R().QueryRowContext(ctx, `SELECT `+domCols+` FROM domains WHERE id=?`, id))
}

// DomainsForProject lists non-expired domains of a project.
func (s *Store) DomainsForProject(ctx context.Context, projectID string) ([]*Domain, error) {
	return s.queryDomains(ctx, `SELECT `+domCols+` FROM domains WHERE project_id=? AND status NOT IN ('expired') ORDER BY hostname`, projectID)
}

// ActiveDomains lists domains that must be routed.
func (s *Store) ActiveDomains(ctx context.Context) ([]*Domain, error) {
	return s.queryDomains(ctx, `SELECT `+domCols+` FROM domains WHERE status IN ('verified','active') ORDER BY hostname`)
}

// DomainHistory lists all records (including tombstones) for a hostname.
func (s *Store) DomainHistory(ctx context.Context, host string) ([]*Domain, error) {
	return s.queryDomains(ctx, `SELECT `+domCols+` FROM domains WHERE hostname=? ORDER BY created_at`, strings.ToLower(host))
}

func (s *Store) queryDomains(ctx context.Context, q string, args ...any) ([]*Domain, error) {
	rows, err := s.DB.R().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// MarkDomainVerified moves a pending claim to active ownership. The unique
// index on active hostnames makes concurrent claims race-free.
func (s *Store) MarkDomainVerified(ctx context.Context, id string, check any) error {
	b, _ := json.Marshal(check)
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		now := state.Now()
		res, err := tx.ExecContext(ctx, `UPDATE domains SET status='active', verified_at=?, claim_token='', last_check=?, tls_status='pending', updated_at=? WHERE id=? AND status='pending'`,
			now, string(b), now, id)
		if err != nil {
			if isUnique(err) {
				return fmt.Errorf("%w: hostname already attached", ErrConflict)
			}
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%w: claim is not pending", ErrConflict)
		}
		return nil
	})
}

func (s *Store) RecordDomainCheck(ctx context.Context, id string, check any) error {
	b, _ := json.Marshal(check)
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE domains SET last_check=?, updated_at=? WHERE id=?`, string(b), state.Now(), id)
		return err
	})
}

func (s *Store) SetDomainTLS(ctx context.Context, id, st string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE domains SET tls_status=?, updated_at=? WHERE id=?`, st, state.Now(), id)
		return err
	})
}

// TombstoneDomain detaches a domain. The tombstone row is retained so a
// future claimant must complete a fresh TXT challenge (SC-14).
func (s *Store) TombstoneDomain(ctx context.Context, id string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		now := state.Now()
		res, err := tx.ExecContext(ctx, `UPDATE domains SET status='tombstoned', tombstoned_at=?, claim_token='', updated_at=? WHERE id=? AND status IN ('pending','verified','active')`, now, now, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// TombstoneProjectDomains detaches all domains of a project.
func (s *Store) TombstoneProjectDomains(ctx context.Context, projectID string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		now := state.Now()
		_, err := tx.ExecContext(ctx, `UPDATE domains SET status='tombstoned', tombstoned_at=?, claim_token='', updated_at=? WHERE project_id=? AND status IN ('pending','verified','active')`, now, now, projectID)
		return err
	})
}

// Volumes

type Volume struct {
	ID                 string `json:"id"`
	ProjectID          string `json:"project_id"`
	EnvironmentID      string `json:"environment_id"`
	Name               string `json:"name"`
	MountTarget        string `json:"mount_target"`
	SizeBytes          int64  `json:"size_bytes"`
	DeletionProtection bool   `json:"deletion_protection"`
	BackupPolicy       string `json:"backup_policy"`
	Status             string `json:"status"`
	CreatedAt          string `json:"created_at"`
}

const volCols = `id,project_id,environment_id,name,mount_target,size_bytes,deletion_protection,backup_policy,status,created_at`

func scanVol(r interface{ Scan(...any) error }) (*Volume, error) {
	var v Volume
	if err := r.Scan(&v.ID, &v.ProjectID, &v.EnvironmentID, &v.Name, &v.MountTarget, &v.SizeBytes, &v.DeletionProtection, &v.BackupPolicy, &v.Status, &v.CreatedAt); err != nil {
		return nil, notFound(err)
	}
	return &v, nil
}

// EnsureVolume returns the active volume (env, name), creating it with an
// opaque ID owned by that project/environment.
func (s *Store) EnsureVolume(ctx context.Context, projectID, envID, name, mount, backup string) (*Volume, error) {
	var out *Volume
	err := s.DB.Tx(ctx, func(tx *sql.Tx) error {
		v, err := scanVol(tx.QueryRowContext(ctx, `SELECT `+volCols+` FROM volumes WHERE environment_id=? AND name=? AND status='active'`, envID, name))
		if err == nil {
			if v.ProjectID != projectID {
				return fmt.Errorf("%w: volume owned by another project", ErrConflict)
			}
			if v.MountTarget != mount || v.BackupPolicy != backup {
				if _, err := tx.ExecContext(ctx, `UPDATE volumes SET mount_target=?, backup_policy=?, updated_at=? WHERE id=?`, mount, backup, state.Now(), v.ID); err != nil {
					return err
				}
				v.MountTarget, v.BackupPolicy = mount, backup
			}
			out = v
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		now := state.Now()
		v = &Volume{ID: ids.New("vol"), ProjectID: projectID, EnvironmentID: envID, Name: name, MountTarget: mount, DeletionProtection: true, BackupPolicy: backup, Status: "active", CreatedAt: now}
		_, err = tx.ExecContext(ctx, `INSERT INTO volumes(id,project_id,environment_id,name,mount_target,size_bytes,deletion_protection,backup_policy,status,created_at,updated_at)
			VALUES(?,?,?,?,?,0,1,?,?,?,?)`, v.ID, projectID, envID, name, mount, backup, "active", now, now)
		out = v
		return err
	})
	return out, err
}

func (s *Store) VolumesForProject(ctx context.Context, projectID string) ([]*Volume, error) {
	rows, err := s.DB.R().QueryContext(ctx, `SELECT `+volCols+` FROM volumes WHERE project_id=? AND status='active' ORDER BY name`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Volume
	for rows.Next() {
		v, err := scanVol(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) AllVolumes(ctx context.Context) ([]*Volume, error) {
	rows, err := s.DB.R().QueryContext(ctx, `SELECT `+volCols+` FROM volumes WHERE status='active' ORDER BY project_id, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Volume
	for rows.Next() {
		v, err := scanVol(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) SetVolumeProtection(ctx context.Context, id, projectID string, on bool) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE volumes SET deletion_protection=?, updated_at=? WHERE id=? AND project_id=?`, b2i(on), state.Now(), id, projectID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// TombstoneVolume marks a volume deleted (data removal happens later by the
// runtime after the retention window) unless deletion protection is on.
func (s *Store) TombstoneVolume(ctx context.Context, id, projectID string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		var prot bool
		if err := tx.QueryRowContext(ctx, `SELECT deletion_protection FROM volumes WHERE id=? AND project_id=? AND status='active'`, id, projectID).Scan(&prot); err != nil {
			return notFound(err)
		}
		if prot {
			return fmt.Errorf("%w: volume has deletion protection", ErrConflict)
		}
		now := state.Now()
		_, err := tx.ExecContext(ctx, `UPDATE volumes SET status='tombstoned', tombstoned_at=?, updated_at=? WHERE id=?`, now, now, id)
		return err
	})
}

// Backing services

type ServiceRow struct {
	ID                string `json:"id"`
	ProjectID         string `json:"project_id"`
	EnvironmentID     string `json:"environment_id"`
	Name              string `json:"name"`
	Template          string `json:"template"`
	Version           string `json:"version"`
	RuntimeClass      string `json:"runtime_class"`
	DesiredState      string `json:"desired_state"`
	RuntimeID         string `json:"runtime_id"`
	Endpoint          string `json:"endpoint"`
	VolumeID          string `json:"volume_id"`
	CredentialsSecret string `json:"credentials_secret"`
	CreatedAt         string `json:"created_at"`
}

const svcCols = `id,project_id,environment_id,name,template,version,runtime_class,desired_state,runtime_id,endpoint,volume_id,credentials_secret,created_at`

func scanSvc(r interface{ Scan(...any) error }) (*ServiceRow, error) {
	var x ServiceRow
	if err := r.Scan(&x.ID, &x.ProjectID, &x.EnvironmentID, &x.Name, &x.Template, &x.Version, &x.RuntimeClass, &x.DesiredState, &x.RuntimeID, &x.Endpoint, &x.VolumeID, &x.CredentialsSecret, &x.CreatedAt); err != nil {
		return nil, notFound(err)
	}
	return &x, nil
}

func (s *Store) UpsertService(ctx context.Context, x *ServiceRow) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		cur, err := scanSvc(tx.QueryRowContext(ctx, `SELECT `+svcCols+` FROM services WHERE environment_id=? AND name=?`, x.EnvironmentID, x.Name))
		now := state.Now()
		if err == nil {
			x.ID = cur.ID
			_, err = tx.ExecContext(ctx, `UPDATE services SET template=?, version=?, desired_state=?, volume_id=?, credentials_secret=?, updated_at=? WHERE id=?`,
				x.Template, x.Version, x.DesiredState, x.VolumeID, x.CredentialsSecret, now, cur.ID)
			return err
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		if x.ID == "" {
			x.ID = ids.New("svc")
		}
		x.CreatedAt = now
		_, err = tx.ExecContext(ctx, `INSERT INTO services(`+svcCols+`,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			x.ID, x.ProjectID, x.EnvironmentID, x.Name, x.Template, x.Version, firstNonEmpty(x.RuntimeClass, "runc"), firstNonEmpty(x.DesiredState, "running"),
			"", "", x.VolumeID, x.CredentialsSecret, now, now)
		return err
	})
}

func (s *Store) SetServiceRuntime(ctx context.Context, id, runtimeID, endpoint string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE services SET runtime_id=?, endpoint=?, updated_at=? WHERE id=?`, runtimeID, endpoint, state.Now(), id)
		return err
	})
}

func (s *Store) ServicesForEnvironment(ctx context.Context, envID string) ([]*ServiceRow, error) {
	rows, err := s.DB.R().QueryContext(ctx, `SELECT `+svcCols+` FROM services WHERE environment_id=? AND desired_state!='deleted' ORDER BY name`, envID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ServiceRow
	for rows.Next() {
		x, err := scanSvc(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Store) SetServiceDesired(ctx context.Context, id, projectID, desired string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE services SET desired_state=?, updated_at=? WHERE id=? AND project_id=?`, desired, state.Now(), id, projectID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// Nodes

type Node struct {
	ID           string          `json:"id"`
	Hostname     string          `json:"hostname"`
	Capabilities json.RawMessage `json:"capabilities"`
	Profile      string          `json:"profile"`
	Version      string          `json:"version"`
	UpdateSlot   string          `json:"update_slot"`
	LastSeen     string          `json:"last_seen"`
}

func (s *Store) UpsertNode(ctx context.Context, n *Node) error {
	if len(n.Capabilities) == 0 {
		n.Capabilities = json.RawMessage("{}")
	}
	n.LastSeen = state.Now()
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO nodes(id,hostname,capabilities,profile,version,update_slot,last_seen) VALUES(?,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET hostname=excluded.hostname, capabilities=excluded.capabilities, profile=excluded.profile,
			version=excluded.version, update_slot=excluded.update_slot, last_seen=excluded.last_seen`,
			n.ID, n.Hostname, string(n.Capabilities), n.Profile, n.Version, firstNonEmpty(n.UpdateSlot, "a"), n.LastSeen)
		return err
	})
}

func (s *Store) GetNode(ctx context.Context, id string) (*Node, error) {
	var n Node
	var caps string
	err := s.DB.R().QueryRowContext(ctx, `SELECT id,hostname,capabilities,profile,version,update_slot,last_seen FROM nodes WHERE id=?`, id).
		Scan(&n.ID, &n.Hostname, &caps, &n.Profile, &n.Version, &n.UpdateSlot, &n.LastSeen)
	if err != nil {
		return nil, notFound(err)
	}
	n.Capabilities = json.RawMessage(caps)
	return &n, nil
}

// Backups

type Backup struct {
	ID              string `json:"id"`
	Kind            string `json:"kind"`
	Status          string `json:"status"`
	Target          string `json:"target"`
	ManifestDigest  string `json:"manifest_digest"`
	ObjectKey       string `json:"object_key"`
	SizeBytes       int64  `json:"size_bytes"`
	Error           string `json:"error,omitempty"`
	CreatedAt       string `json:"created_at"`
	CompletedAt     string `json:"completed_at,omitempty"`
	RestoreTestedAt string `json:"restore_tested_at,omitempty"`
}

const bkCols = `id,kind,status,target,manifest_digest,object_key,size_bytes,error,created_at,completed_at,restore_tested_at`

func scanBackup(r interface{ Scan(...any) error }) (*Backup, error) {
	var b Backup
	if err := r.Scan(&b.ID, &b.Kind, &b.Status, &b.Target, &b.ManifestDigest, &b.ObjectKey, &b.SizeBytes, &b.Error, &b.CreatedAt, &b.CompletedAt, &b.RestoreTestedAt); err != nil {
		return nil, notFound(err)
	}
	return &b, nil
}

func (s *Store) CreateBackup(ctx context.Context, b *Backup) error {
	if b.ID == "" {
		b.ID = ids.New("bkp")
	}
	b.CreatedAt = state.Now()
	b.Status = "running"
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO backups(`+bkCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, b.ID, b.Kind, b.Status, b.Target, "", "", 0, "", b.CreatedAt, "", "")
		return err
	})
}

func (s *Store) FinishBackup(ctx context.Context, id, status, manifest, key string, size int64, errMsg string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE backups SET status=?, manifest_digest=?, object_key=?, size_bytes=?, error=?, completed_at=? WHERE id=?`,
			status, manifest, key, size, truncate(errMsg, 2000), state.Now(), id)
		return err
	})
}

func (s *Store) MarkRestoreTested(ctx context.Context, id string) error {
	return s.DB.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE backups SET status='verified', restore_tested_at=? WHERE id=?`, state.Now(), id)
		return err
	})
}

func (s *Store) ListBackups(ctx context.Context, limit int) ([]*Backup, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.DB.R().QueryContext(ctx, `SELECT `+bkCols+` FROM backups ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Backup
	for rows.Next() {
		b, err := scanBackup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) GetBackup(ctx context.Context, id string) (*Backup, error) {
	return scanBackup(s.DB.R().QueryRowContext(ctx, `SELECT `+bkCols+` FROM backups WHERE id=?`, id))
}
