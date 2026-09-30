package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/daemon"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/state"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/update"
)

// HostAgent is the privileged host daemon's update surface. hostd verifies
// the release through TUF itself before installing (it never trusts
// platformd's download).
type HostAgent interface {
	ApplyUpdate(ctx context.Context, channel, version string) error
}

// ErrNoHostAgent is returned when hostd is not available (dev mode).
var ErrNoHostAgent = errors.New("the host agent (hostd) is not running on this node (development or single-process mode)")

// UpdateStatus is shown in the dashboard.
type UpdateStatus struct {
	Current        string          `json:"current"`
	Channel        string          `json:"channel"`
	Configured     bool            `json:"configured"`
	CheckedAt      string          `json:"checked_at,omitempty"`
	Available      *update.Release `json:"available,omitempty"`
	Blocked        string          `json:"blocked,omitempty"` // why the offered release cannot be installed
	CurrentRevoked bool            `json:"current_revoked,omitempty"`
	Error          string          `json:"error,omitempty"`
	Platform       string          `json:"platform"`
}

func (p *Platform) updateClient() (*update.Client, error) {
	u := p.Node.Update
	if u.RepositoryURL == "" || u.TrustedRoot == "" {
		return nil, errors.New("updates are not configured (update.repository_url and update.trusted_root)")
	}
	root, err := os.ReadFile(u.TrustedRoot)
	if err != nil {
		return nil, err
	}
	return &update.Client{MetadataURL: u.RepositoryURL + "/metadata", TargetsURL: u.RepositoryURL + "/targets", TrustedRoot: root,
		CacheDir: filepath.Join(p.Node.ServiceDir(identity.Platform), "tuf")}, nil
}

// CheckUpdates verifies the channel's release through TUF and records it.
func (p *Platform) CheckUpdates(ctx context.Context) *UpdateStatus {
	st := &UpdateStatus{Current: daemon.Version, Channel: p.Node.Update.Channel, Platform: runtime.GOOS + "-" + runtime.GOARCH, CheckedAt: state.Now()}
	c, err := p.updateClient()
	if err != nil {
		st.Error = err.Error()
		return st
	}
	st.Configured = true
	rel, err := c.Check(st.Channel)
	if err != nil {
		st.Error = err.Error()
		_, _ = p.Audit.Append(ctx, audit.Event{ActorType: audit.ActorService, ActorID: "platformd", Action: "update.check", Result: audit.Failure,
			Details: map[string]string{"reason": truncate(err.Error(), 400)}})
	} else {
		st.CurrentRevoked = update.CurrentRevoked(st.Current, rel)
		if rel.Version != st.Current {
			st.Available = rel
			if err := update.Permit(st.Current, rel); err != nil {
				st.Blocked = err.Error()
			} else if _, ok := rel.Artifacts[st.Platform]; !ok {
				st.Blocked = update.ErrNoBuild.Error()
			}
		}
	}
	_ = p.Store.SetSetting(ctx, "update_status", st)
	return st
}

// UpdateStatus returns the last recorded check.
func (p *Platform) UpdateStatus(ctx context.Context) *UpdateStatus {
	var st UpdateStatus
	if ok, _ := p.Store.GetSetting(ctx, "update_status", &st); ok {
		st.Current = daemon.Version
		return &st
	}
	return &UpdateStatus{Current: daemon.Version, Channel: p.Node.Update.Channel, Platform: runtime.GOOS + "-" + runtime.GOARCH,
		Configured: p.Node.Update.RepositoryURL != "" && p.Node.Update.TrustedRoot != ""}
}

// ApplyUpdate asks hostd to stage and activate version.
func (p *Platform) ApplyUpdate(ctx context.Context, version string) error {
	if p.Host == nil {
		return ErrNoHostAgent
	}
	st := p.UpdateStatus(ctx)
	if st.Available == nil || st.Available.Version != version {
		return errors.New("that version is not the verified release offered on this channel; check for updates first")
	}
	if st.Blocked != "" {
		return errors.New(st.Blocked)
	}
	// A release that migrates the schema forward cannot be rolled back
	// automatically: take a backup first and refuse to proceed without one.
	if st.Available.SchemaVersion > store.SchemaVersion {
		if _, err := p.RunBackup(ctx); err != nil {
			return fmt.Errorf("pre-update backup failed (required before a schema migration): %w", err)
		}
	}
	return p.Host.ApplyUpdate(ctx, p.Node.Update.Channel, version)
}

// updateCheckDue runs the periodic check (every 6 hours).
func (p *Platform) updateCheckDue(ctx context.Context) {
	if p.Node.Update.RepositoryURL == "" {
		return
	}
	var st UpdateStatus
	if ok, _ := p.Store.GetSetting(ctx, "update_status", &st); ok && time.Since(state.ParseTime(st.CheckedAt)) < 6*time.Hour {
		return
	}
	p.CheckUpdates(ctx)
}
