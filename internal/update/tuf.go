// Package update implements signed platform updates (PRD §18.2, SC-18/19,
// ST-10): TUF-verified release metadata and artifacts (threshold-signed
// root, expiring timestamp/snapshot, rollback and freeze protection), a
// monotonic-version policy with halt and revocation, and A/B install slots
// with a readiness gate and migration-aware rollback.
package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

// Release is the per-channel release document (itself a TUF target, so it
// is covered by the same threshold signatures and freshness guarantees).
type Release struct {
	Version       string            `json:"version"`
	Channel       string            `json:"channel"`
	PublishedAt   time.Time         `json:"published_at"`
	SchemaVersion int               `json:"schema_version"`
	Artifacts     map[string]string `json:"artifacts"` // "linux-amd64" -> target path
	Notes         string            `json:"notes,omitempty"`
	// Halted stops staged rollout of this version (publisher kill switch).
	Halted bool `json:"halted,omitempty"`
	// Revoked lists versions that must not be installed (and that running
	// nodes should move off).
	Revoked []string `json:"revoked,omitempty"`
}

// Errors returned by policy checks.
var (
	ErrDowngrade = errors.New("refusing to install an older version (rollback protection)")
	ErrHalted    = errors.New("this release was halted by the publisher")
	ErrRevoked   = errors.New("this release has been revoked")
	ErrNoBuild   = errors.New("release has no build for this platform")
)

// Client verifies releases through TUF.
type Client struct {
	MetadataURL string // e.g. https://updates.opendeploy.dev/metadata
	TargetsURL  string // e.g. https://updates.opendeploy.dev/targets
	TrustedRoot []byte // root.json pinned at install time
	CacheDir    string // persistent trusted metadata (rollback/freeze protection) + downloads
	// RefTime overrides "now" for expiry checks (tests only).
	RefTime time.Time
}

func (c *Client) updater() (*updater.Updater, error) {
	if len(c.TrustedRoot) == 0 {
		return nil, errors.New("update: no trusted root configured (update.trusted_root)")
	}
	mdDir := filepath.Join(c.CacheDir, "metadata")
	tgDir := filepath.Join(c.CacheDir, "targets")
	for _, d := range []string{mdDir, tgDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	// The locally trusted root only moves forward: once a newer root has
	// been verified, it is used instead of the install-time one.
	root := c.TrustedRoot
	if b, err := os.ReadFile(filepath.Join(mdDir, "root.json")); err == nil {
		root = b
	}
	cfg, err := config.New(c.MetadataURL, root)
	if err != nil {
		return nil, err
	}
	cfg.LocalMetadataDir, cfg.LocalTargetsDir = mdDir, tgDir
	if c.TargetsURL != "" {
		cfg.RemoteTargetsURL = c.TargetsURL
	}
	cfg.PrefixTargetsWithHash = false
	up, err := updater.New(cfg)
	if err != nil {
		return nil, err
	}
	if !c.RefTime.IsZero() {
		up.UnsafeSetRefTime(c.RefTime)
	}
	return up, nil
}

// ChannelTarget is the TUF target path of a channel's release document.
func ChannelTarget(channel string) string { return "channels/" + channel + ".json" }

// Check refreshes TUF metadata and returns the channel's verified release.
func (c *Client) Check(channel string) (*Release, error) {
	up, err := c.updater()
	if err != nil {
		return nil, err
	}
	if err := up.Refresh(); err != nil {
		return nil, fmt.Errorf("update metadata verification failed: %w", err)
	}
	ti, err := up.GetTargetInfo(ChannelTarget(channel))
	if err != nil {
		return nil, fmt.Errorf("channel %q: %w", channel, err)
	}
	path, data, err := up.DownloadTarget(ti, "", "")
	if err != nil {
		return nil, fmt.Errorf("release document failed verification: %w", err)
	}
	_ = os.Remove(path)
	var r Release
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("release document: %w", err)
	}
	if r.Channel != "" && r.Channel != channel {
		return nil, fmt.Errorf("release document is for channel %q, not %q", r.Channel, channel)
	}
	if _, err := ParseVersion(r.Version); err != nil {
		return nil, err
	}
	return &r, nil
}

// Fetch downloads and verifies (length + hashes from threshold-signed
// targets metadata) the release build for a platform into dir.
func (c *Client) Fetch(r *Release, platform, dir string) (string, error) {
	tp, ok := r.Artifacts[platform]
	if !ok {
		return "", ErrNoBuild
	}
	up, err := c.updater()
	if err != nil {
		return "", err
	}
	if err := up.Refresh(); err != nil {
		return "", fmt.Errorf("update metadata verification failed: %w", err)
	}
	ti, err := up.GetTargetInfo(tp)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, filepath.Base(tp))
	p, _, err := up.DownloadTarget(ti, dst, "")
	if err != nil {
		return "", fmt.Errorf("release artifact failed verification: %w", err)
	}
	return p, nil
}

// Permit applies local policy: no downgrades, no halted or revoked builds.
func Permit(current string, r *Release) error {
	for _, v := range r.Revoked {
		if v == r.Version {
			return ErrRevoked
		}
	}
	if r.Halted {
		return ErrHalted
	}
	if current == "" || current == "dev" {
		return nil
	}
	cv, err := ParseVersion(current)
	if err != nil {
		return nil // unversioned development build
	}
	nv, err := ParseVersion(r.Version)
	if err != nil {
		return err
	}
	if nv.Less(cv) {
		return ErrDowngrade
	}
	return nil
}

// CurrentRevoked reports whether the running version was revoked.
func CurrentRevoked(current string, r *Release) bool {
	for _, v := range r.Revoked {
		if v == strings.TrimPrefix(current, "v") {
			return true
		}
	}
	return false
}

// Version is a parsed semantic version.
type Version struct {
	Major, Minor, Patch int
	Pre                 string
}

// ParseVersion parses MAJOR.MINOR.PATCH[-PRE] (an optional leading v).
func ParseVersion(s string) (Version, error) {
	var v Version
	s = strings.TrimPrefix(s, "v")
	core, pre, _ := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("invalid version %q", s)
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, fmt.Errorf("invalid version %q", s)
		}
		nums[i] = n
	}
	return Version{nums[0], nums[1], nums[2], pre}, nil
}

// Less reports v < o (a pre-release sorts before its release).
func (v Version) Less(o Version) bool {
	if v.Major != o.Major {
		return v.Major < o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor < o.Minor
	}
	if v.Patch != o.Patch {
		return v.Patch < o.Patch
	}
	switch {
	case v.Pre == o.Pre:
		return false
	case v.Pre == "":
		return false
	case o.Pre == "":
		return true
	}
	return v.Pre < o.Pre
}
