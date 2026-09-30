// Package restore rebuilds a node's state from a backup (clean-node
// restore, PRD §19 / ST-11). It runs offline, with all OpenDeploy services
// stopped, as root (so each service's files land in its own directory; the
// packaging's tmpfiles/ownership rules fix owners on next start).
package restore

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/backup"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/secrets"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// Options configure a restore.
type Options struct {
	Node   *config.Node
	Target backup.Target
	Prefix string
	ID     string // backup id or "latest"
	Master backup.MasterKey
	Signer ed25519.PublicKey // pinned manifest signer (recommended)
	Force  bool              // overwrite an existing (non-empty) node
	Out    io.Writer
}

// ErrNotClean refuses to overwrite an initialised node.
var ErrNotClean = errors.New("this node already has platform state; restore onto a clean node or pass --force")

// Run performs the restore and returns the manifest.
func Run(ctx context.Context, o Options) (*backup.Manifest, error) {
	n := o.Node
	out := o.Out
	if out == nil {
		out = io.Discard
	}
	platformDB := filepath.Join(n.ServiceDir(identity.Platform), "platform.db")
	if _, err := os.Stat(platformDB); err == nil && !o.Force {
		return nil, ErrNotClean
	}
	id := o.ID
	if id == "" || id == "latest" {
		ids, err := backup.List(ctx, o.Target, o.Prefix)
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			return nil, fmt.Errorf("no backups found at %s", o.Target)
		}
		id = ids[0]
	}
	stage, err := os.MkdirTemp(n.DataDir, ".restore-")
	if err != nil {
		if err := os.MkdirAll(n.DataDir, 0o755); err != nil {
			return nil, err
		}
		if stage, err = os.MkdirTemp(n.DataDir, ".restore-"); err != nil {
			return nil, err
		}
	}
	defer os.RemoveAll(stage)
	fmt.Fprintf(out, "Restoring %s from %s\n", id, o.Target)
	m, err := backup.Restore(ctx, o.Target, o.Prefix, id, o.Master, o.Signer, func(c backup.Component) (string, error) {
		return filepath.Join(stage, c.Name), nil
	})
	if err != nil {
		return nil, err
	}
	if m.SchemaVersion > store.SchemaVersion {
		return nil, fmt.Errorf("backup schema v%d is newer than this build (v%d): install OpenDeploy %s or later first", m.SchemaVersion, store.SchemaVersion, m.Version)
	}
	dek, err := backup.UnwrapDEK(m, o.Master)
	if err != nil {
		return nil, err
	}
	place := func(src, dst string, mode os.FileMode) error {
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return err
		}
		for _, suffix := range []string{"-wal", "-shm"} {
			_ = os.Remove(dst + suffix)
		}
		if err := os.Rename(src, dst); err != nil {
			return err
		}
		return os.Chmod(dst, mode)
	}
	for _, c := range m.Components {
		src := filepath.Join(stage, c.Name)
		switch c.Kind {
		case "platform-db":
			if err := place(src, platformDB, 0o600); err != nil {
				return nil, err
			}
			fmt.Fprintln(out, "  platform state restored")
		case "audit-db":
			if err := place(src, filepath.Join(n.ServiceDir(identity.Audit), "audit.db"), 0o600); err != nil {
				return nil, err
			}
			fmt.Fprintln(out, "  audit chain restored")
		case "secrets":
			sealed, err := os.ReadFile(src)
			if err != nil {
				return nil, err
			}
			kr, db, err := secrets.OpenBundle(sealed, dek, m.ID)
			if err != nil {
				return nil, fmt.Errorf("secrets bundle: %w", err)
			}
			if err := os.MkdirAll(filepath.Dir(n.Secrets.KEKFile), 0o700); err != nil {
				return nil, err
			}
			if err := os.WriteFile(n.Secrets.KEKFile, kr, 0o600); err != nil {
				return nil, err
			}
			dbPath := filepath.Join(n.ServiceDir(identity.Secret), "secrets.db")
			tmp := dbPath + ".restore"
			if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
				return nil, err
			}
			if err := os.WriteFile(tmp, db, 0o600); err != nil {
				return nil, err
			}
			if err := place(tmp, dbPath, 0o600); err != nil {
				return nil, err
			}
			fmt.Fprintln(out, "  secrets and key ring restored")
		case "artifacts":
			dst := filepath.Join(n.ServiceDir(identity.Artifact), "store")
			if err := untarFile(src, dst); err != nil {
				return nil, fmt.Errorf("artifacts: %w", err)
			}
			fmt.Fprintln(out, "  build artifacts restored")
		case "volume":
			if !strings.HasPrefix(c.Ref, "vol_") {
				return nil, fmt.Errorf("volume component with bad id %q", c.Ref)
			}
			dst := filepath.Join(n.Runtime.VolumesDir, c.Ref)
			if err := os.RemoveAll(dst); err != nil {
				return nil, err
			}
			if err := untarFile(src, dst); err != nil {
				return nil, fmt.Errorf("volume %s: %w", c.Ref, err)
			}
			fmt.Fprintf(out, "  volume %s restored\n", c.Ref)
		default:
			fmt.Fprintf(out, "  skipping unknown component %s (%s)\n", c.Name, c.Kind)
		}
	}
	// A restored node gets a fresh backup signing identity; pin it anew.
	_ = os.Rename(filepath.Join(n.ServiceDir(identity.Platform), "backup-signing.key"), filepath.Join(n.ServiceDir(identity.Platform), "backup-signing.key.pre-restore"))
	fmt.Fprintf(out, "Restore of %s complete (created %s by version %s).\n", m.ID, m.CreatedAt.Format("2006-01-02 15:04 MST"), m.Version)
	return m, nil
}

func untarFile(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	return backup.UntarDir(f, dst)
}
