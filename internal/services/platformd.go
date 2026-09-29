package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/api"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/auth"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/config"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/hostd"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/network"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/platform"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/relay"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
)

// Platformd bundles the orchestrator and its API.
type Platformd struct {
	Store    *store.Store
	Platform *platform.Platform
	API      *api.Server
}

// PlatformOptions configures platformd construction.
type PlatformOptions struct {
	UI                      fs.FS
	Egress                  network.Enforcer
	InsecureNoNetworkPolicy bool
	RequireMFA              *bool
}

// BootstrapTokenPath is where the one-time owner bootstrap token lives.
func BootstrapTokenPath(n *config.Node) string {
	return filepath.Join(n.ServiceDir(identity.Platform), "bootstrap-token")
}

// NewPlatformd opens the platform DB and wires the orchestrator and API.
func NewPlatformd(ctx context.Context, n *config.Node, log *slog.Logger, c *Clients, o PlatformOptions) (*Platformd, error) {
	dir := n.ServiceDir(identity.Platform)
	st, err := store.Open(ctx, filepath.Join(dir, "platform.db"), filepath.Join(dir, "snapshots"), log)
	if err != nil {
		return nil, err
	}
	key, err := loadOrCreateKey(filepath.Join(dir, "sealer.key"))
	if err != nil {
		return nil, err
	}
	sealer, err := auth.NewSealer(key)
	if err != nil {
		return nil, err
	}
	boot := ""
	if cnt, err := st.CountUsers(ctx); err == nil && cnt == 0 {
		boot, err = loadOrCreateToken(BootstrapTokenPath(n))
		if err != nil {
			return nil, err
		}
		log.Warn("no users exist yet: create the owner with `opendeployctl admin bootstrap` or the setup page", "token_file", BootstrapTokenPath(n))
	} else {
		_ = os.Remove(BootstrapTokenPath(n))
	}
	eg := o.Egress
	if eg == nil {
		eg = network.Nop{}
	}
	gh := &platform.GitHubProvider{Node: n, Secrets: c.Secrets}
	p := platform.New(platform.Deps{Store: st, Node: n, Builder: c.Builder, Runtime: c.Runtime, Router: c.Router, Artifacts: c.Artifact,
		Secrets: c.Secrets, Audit: c.Audit, AuditReader: c.Audit, Egress: eg, GitHub: gh, Log: log,
		InsecureNoNetworkPolicy: o.InsecureNoNetworkPolicy})
	p.Backups = backupExporters{c}
	if !n.DevMode {
		p.Host = &hostd.Client{C: n.IPCClient(identity.Host, identity.Platform)}
	}
	if n.Ingress.Mode == "relay" {
		p.Relay = &relay.Client{C: n.IPCClient(identity.RelayAgent, identity.Platform)}
	}
	requireMFA := !n.DevMode
	if o.RequireMFA != nil {
		requireMFA = *o.RequireMFA
	}
	srv := api.New(p, sealer, o.UI, requireMFA, boot)
	srv.Bootstrapped = func() { _ = os.Remove(BootstrapTokenPath(n)) }
	return &Platformd{Store: st, Platform: p, API: srv}, nil
}

func loadOrCreateKey(p string) ([]byte, error) {
	if b, err := os.ReadFile(p); err == nil {
		k, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(k) != 32 {
			return nil, errors.New("invalid key file " + p)
		}
		return k, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	return k, os.WriteFile(p, []byte(hex.EncodeToString(k)+"\n"), 0o600)
}
