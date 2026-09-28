package update

import (
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// Publisher maintains a TUF repository for OpenDeploy releases:
//
//	<dir>/metadata/{N.root.json,root.json,targets.json,snapshot.json,timestamp.json}
//	<dir>/targets/{channels/<channel>.json, <artifacts>}
//
// Root keys are meant to live offline (threshold-signed, rarely used);
// targets/snapshot/timestamp keys sign routine releases.
type Publisher struct {
	Dir       string
	Root      *metadata.Metadata[metadata.RootType]
	Targets   *metadata.Metadata[metadata.TargetsType]
	Snapshot  *metadata.Metadata[metadata.SnapshotType]
	Timestamp *metadata.Metadata[metadata.TimestampType]
	Keys      map[string][]ed25519.PrivateKey // role -> private keys available here
}

// Expiry defaults.
var (
	RootExpiry      = 365 * 24 * time.Hour
	TargetsExpiry   = 90 * 24 * time.Hour
	SnapshotExpiry  = 14 * 24 * time.Hour
	TimestampExpiry = 24 * time.Hour
)

var roles = []string{"root", "targets", "snapshot", "timestamp"}

func (p *Publisher) mdDir() string { return filepath.Join(p.Dir, "metadata") }
func (p *Publisher) tgDir() string { return filepath.Join(p.Dir, "targets") }

// InitRepository creates a repository whose root requires rootThreshold of
// len(keys["root"]) signatures (and 1 for the online roles).
func InitRepository(dir string, keys map[string][]ed25519.PrivateKey, rootThreshold int) (*Publisher, error) {
	now := time.Now().UTC()
	p := &Publisher{Dir: dir, Keys: keys,
		Root: metadata.Root(now.Add(RootExpiry)), Targets: metadata.Targets(now.Add(TargetsExpiry)),
		Snapshot: metadata.Snapshot(now.Add(SnapshotExpiry)), Timestamp: metadata.Timestamp(now.Add(TimestampExpiry))}
	p.Root.Signed.ConsistentSnapshot = false
	for _, role := range roles {
		if len(keys[role]) == 0 {
			return nil, fmt.Errorf("no keys for role %s", role)
		}
		for _, k := range keys[role] {
			pk, err := metadata.KeyFromPublicKey(k.Public())
			if err != nil {
				return nil, err
			}
			if err := p.Root.Signed.AddKey(pk, role); err != nil {
				return nil, err
			}
		}
	}
	if rootThreshold < 1 || rootThreshold > len(keys["root"]) {
		return nil, errors.New("invalid root threshold")
	}
	p.Root.Signed.Roles["root"].Threshold = rootThreshold
	for _, d := range []string{p.mdDir(), p.tgDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	if err := p.signWrite("root"); err != nil {
		return nil, err
	}
	return p, p.Commit()
}

// LoadPublisher reads an existing repository.
func LoadPublisher(dir string, keys map[string][]ed25519.PrivateKey) (*Publisher, error) {
	p := &Publisher{Dir: dir, Keys: keys, Root: metadata.Root(), Targets: metadata.Targets(), Snapshot: metadata.Snapshot(), Timestamp: metadata.Timestamp()}
	var err error
	if p.Root, err = p.Root.FromFile(filepath.Join(p.mdDir(), "root.json")); err != nil {
		return nil, err
	}
	if p.Targets, err = p.Targets.FromFile(filepath.Join(p.mdDir(), "targets.json")); err != nil {
		return nil, err
	}
	if p.Snapshot, err = p.Snapshot.FromFile(filepath.Join(p.mdDir(), "snapshot.json")); err != nil {
		return nil, err
	}
	if p.Timestamp, err = p.Timestamp.FromFile(filepath.Join(p.mdDir(), "timestamp.json")); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Publisher) sign(role string, clear bool) error {
	signers := make([]signature.Signer, 0)
	for _, k := range p.Keys[role] {
		s, err := signature.LoadSigner(k, crypto.Hash(0))
		if err != nil {
			return err
		}
		signers = append(signers, s)
	}
	if len(signers) == 0 {
		return fmt.Errorf("no %s key available", role)
	}
	for _, s := range signers {
		var err error
		switch role {
		case "root":
			if clear {
				p.Root.ClearSignatures()
			}
			_, err = p.Root.Sign(s)
		case "targets":
			if clear {
				p.Targets.ClearSignatures()
			}
			_, err = p.Targets.Sign(s)
		case "snapshot":
			if clear {
				p.Snapshot.ClearSignatures()
			}
			_, err = p.Snapshot.Sign(s)
		case "timestamp":
			if clear {
				p.Timestamp.ClearSignatures()
			}
			_, err = p.Timestamp.Sign(s)
		}
		if err != nil {
			return err
		}
		clear = false
	}
	return nil
}

func (p *Publisher) signWrite(role string) error {
	if err := p.sign(role, true); err != nil {
		return err
	}
	return p.write(role)
}

func (p *Publisher) write(role string) error {
	switch role {
	case "root":
		if err := p.Root.ToFile(filepath.Join(p.mdDir(), fmt.Sprintf("%d.root.json", p.Root.Signed.Version)), true); err != nil {
			return err
		}
		return p.Root.ToFile(filepath.Join(p.mdDir(), "root.json"), true)
	case "targets":
		return p.Targets.ToFile(filepath.Join(p.mdDir(), "targets.json"), true)
	case "snapshot":
		return p.Snapshot.ToFile(filepath.Join(p.mdDir(), "snapshot.json"), true)
	case "timestamp":
		return p.Timestamp.ToFile(filepath.Join(p.mdDir(), "timestamp.json"), true)
	}
	return fmt.Errorf("unknown role %s", role)
}

// AddTarget stores data at targets/<path> and records it in targets
// metadata (committed by Commit).
func (p *Publisher) AddTarget(path string, data []byte) error {
	if strings.Contains(path, "..") || strings.HasPrefix(path, "/") {
		return fmt.Errorf("invalid target path %q", path)
	}
	dst := filepath.Join(p.tgDir(), filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return err
	}
	tf, err := metadata.TargetFile().FromBytes(dst, data, "sha256", "sha512")
	if err != nil {
		return err
	}
	p.Targets.Signed.Targets[path] = tf
	return nil
}

// Commit bumps and re-signs targets, snapshot and timestamp.
func (p *Publisher) Commit() error {
	now := time.Now().UTC()
	p.Targets.Signed.Version++
	p.Targets.Signed.Expires = now.Add(TargetsExpiry)
	if err := p.signWrite("targets"); err != nil {
		return err
	}
	p.Snapshot.Signed.Version++
	p.Snapshot.Signed.Expires = now.Add(SnapshotExpiry)
	p.Snapshot.Signed.Meta["targets.json"] = metadata.MetaFile(p.Targets.Signed.Version)
	if err := p.signWrite("snapshot"); err != nil {
		return err
	}
	return p.BumpTimestamp()
}

// BumpTimestamp re-signs the timestamp (run frequently: freeze protection).
func (p *Publisher) BumpTimestamp() error {
	p.Timestamp.Signed.Version++
	p.Timestamp.Signed.Expires = time.Now().UTC().Add(TimestampExpiry)
	p.Timestamp.Signed.Meta["snapshot.json"] = metadata.MetaFile(p.Snapshot.Signed.Version)
	return p.signWrite("timestamp")
}

// PublishRelease adds release artifacts and the channel document.
func (p *Publisher) PublishRelease(r Release, artifacts map[string][]byte) error {
	if _, err := ParseVersion(r.Version); err != nil {
		return err
	}
	if r.PublishedAt.IsZero() {
		r.PublishedAt = time.Now().UTC().Truncate(time.Second)
	}
	r.Artifacts = map[string]string{}
	plats := make([]string, 0, len(artifacts))
	for plat := range artifacts {
		plats = append(plats, plat)
	}
	sort.Strings(plats)
	for _, plat := range plats {
		tp := fmt.Sprintf("releases/%s/opendeploy_%s_%s.tar.gz", r.Version, r.Version, plat)
		if err := p.AddTarget(tp, artifacts[plat]); err != nil {
			return err
		}
		r.Artifacts[plat] = tp
	}
	return p.SetChannel(r)
}

// SetChannel (re)writes a channel document, e.g. to halt or revoke.
func (p *Publisher) SetChannel(r Release) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := p.AddTarget(ChannelTarget(r.Channel), b); err != nil {
		return err
	}
	return p.Commit()
}

// ReadChannel returns the current channel document.
func (p *Publisher) ReadChannel(channel string) (*Release, error) {
	b, err := os.ReadFile(filepath.Join(p.tgDir(), filepath.FromSlash(ChannelTarget(channel))))
	if err != nil {
		return nil, err
	}
	var r Release
	return &r, json.Unmarshal(b, &r)
}

// Key files: ed25519 seeds, hex encoded.

// GenerateKey writes a new key file (0600) and returns the key.
func GenerateKey(path string) (ed25519.PrivateKey, error) {
	_, k, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return k, os.WriteFile(path, []byte(hex.EncodeToString(k.Seed())+"\n"), 0o600)
}

// LoadKey reads a key file.
func LoadKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: not an ed25519 seed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
