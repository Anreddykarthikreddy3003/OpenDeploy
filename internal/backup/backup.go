package backup

import (
	"archive/tar"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

// Source is a staged file to include as a component.
type Source struct {
	Component Component // Name, Kind, Ref (Size/SHA256 are computed)
	Path      string
}

// Options configure Create.
type Options struct {
	ID            string
	Node          string
	Version       string
	SchemaVersion int
	Sources       []Source
	Target        Target
	Prefix        string
	Master        MasterKey
	Signer        ed25519.PrivateKey
	DEK           []byte // optional; generated when nil
	StageDir      string // scratch space for the ciphertext
	RetainUntil   *time.Time
	ObjectLock    bool
}

// NewID returns a sortable backup id.
func NewID(now time.Time) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "bkp_" + now.UTC().Format("20060102T150405Z") + "_" + hex.EncodeToString(b)
}

// NewDEK returns a fresh data key.
func NewDEK() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}

func objectKeys(prefix, id string) (data, manifest string) {
	return prefix + id + "/data.enc", prefix + id + "/manifest.json"
}

type countingHash struct {
	h hash.Hash
	n int64
}

func (c *countingHash) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return c.h.Write(p)
}

// Create builds, encrypts, signs and uploads a backup. The manifest is
// written last: a backup without a manifest is incomplete and ignored.
func Create(ctx context.Context, o Options) (*Manifest, error) {
	if o.Target == nil || o.Signer == nil {
		return nil, errors.New("backup: target and signer are required")
	}
	if o.ID == "" {
		o.ID = NewID(time.Now())
	}
	dek := o.DEK
	if dek == nil {
		dek = NewDEK()
	}
	prefix := make([]byte, 4)
	if _, err := rand.Read(prefix); err != nil {
		return nil, err
	}
	stage := o.StageDir
	if stage == "" {
		stage = os.TempDir()
	}
	ctf, err := os.CreateTemp(stage, "backup-*.enc")
	if err != nil {
		return nil, err
	}
	defer os.Remove(ctf.Name())
	defer ctf.Close()

	cipherHash := &countingHash{h: sha256.New()}
	enc, err := NewEncryptor(io.MultiWriter(ctf, cipherHash), dek, o.ID, prefix)
	if err != nil {
		return nil, err
	}
	zw, err := zstd.NewWriter(enc, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(zw)
	m := &Manifest{Format: Format, ID: o.ID, CreatedAt: time.Now().UTC().Truncate(time.Second), Node: o.Node, Version: o.Version,
		SchemaVersion: o.SchemaVersion, ChunkSize: ChunkSize, NoncePrefix: base64.StdEncoding.EncodeToString(prefix),
		MasterKeyID: o.Master.ID(), RetainUntil: o.RetainUntil, ObjectLockActive: o.ObjectLock}
	seen := map[string]bool{}
	for _, s := range o.Sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c := s.Component
		if !validName(c.Name) || seen[c.Name] {
			return nil, fmt.Errorf("backup: invalid or duplicate component name %q", c.Name)
		}
		seen[c.Name] = true
		f, err := os.Open(s.Path)
		if err != nil {
			return nil, fmt.Errorf("backup component %s: %w", c.Name, err)
		}
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			f.Close()
			return nil, fmt.Errorf("backup component %s: not a regular file", c.Name)
		}
		if err := tw.WriteHeader(&tar.Header{Name: c.Name, Mode: 0o600, Size: fi.Size(), ModTime: m.CreatedAt, Typeflag: tar.TypeReg}); err != nil {
			f.Close()
			return nil, err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(tw, h), f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("backup component %s: %w", c.Name, err)
		}
		c.Size, c.SHA256 = n, hex.EncodeToString(h.Sum(nil))
		m.Components = append(m.Components, c)
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	m.PlainSize = enc.Plain
	m.CipherSize, m.CipherSHA256 = cipherHash.n, hex.EncodeToString(cipherHash.h.Sum(nil))
	wrapped, err := Wrap(o.Master[:], dek, "dek:"+o.ID)
	if err != nil {
		return nil, err
	}
	m.WrappedDEK = base64.StdEncoding.EncodeToString(wrapped)
	signed, err := Sign(m, o.Signer)
	if err != nil {
		return nil, err
	}
	if _, err := ctf.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	dataKey, manKey := objectKeys(o.Prefix, o.ID)
	if err := o.Target.Put(ctx, dataKey, ctf, m.CipherSize, o.RetainUntil); err != nil {
		return nil, fmt.Errorf("upload data: %w", err)
	}
	if err := o.Target.Put(ctx, manKey, strings.NewReader(string(signed)), int64(len(signed)), o.RetainUntil); err != nil {
		return nil, fmt.Errorf("upload manifest: %w", err)
	}
	return m, nil
}

func validName(n string) bool {
	return n != "" && !strings.HasPrefix(n, "/") && path.Clean(n) == n && !strings.Contains(n, "..") && len(n) < 256
}

// List returns the ids of complete backups (those with a manifest), newest
// first.
func List(ctx context.Context, t Target, prefix string) ([]string, error) {
	keys, err := t.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, k := range keys {
		rest := strings.TrimPrefix(k, prefix)
		if id, ok := strings.CutSuffix(rest, "/manifest.json"); ok && !strings.Contains(id, "/") {
			ids = append(ids, id)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	return ids, nil
}

// ReadManifest fetches and verifies a manifest.
func ReadManifest(ctx context.Context, t Target, prefix, id string, pinned ed25519.PublicKey) (*Manifest, error) {
	_, mk := objectKeys(prefix, id)
	rc, err := t.Get(ctx, mk)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, 4<<20))
	if err != nil {
		return nil, err
	}
	m, err := VerifyManifest(b, pinned)
	if err != nil {
		return nil, err
	}
	if m.ID != id {
		return nil, fmt.Errorf("manifest id %q does not match object %q", m.ID, id)
	}
	return m, nil
}

// Restore downloads, verifies and decrypts a backup, writing each component
// to the path returned by dest (written atomically; hashes verified before
// the final rename).
func Restore(ctx context.Context, t Target, prefix, id string, master MasterKey, pinned ed25519.PublicKey, dest func(Component) (string, error)) (*Manifest, error) {
	m, err := ReadManifest(ctx, t, prefix, id, pinned)
	if err != nil {
		return nil, err
	}
	if m.MasterKeyID != master.ID() {
		return nil, fmt.Errorf("backup %s was encrypted with master key %s, not %s", id, m.MasterKeyID, master.ID())
	}
	wrapped, err := base64.StdEncoding.DecodeString(m.WrappedDEK)
	if err != nil {
		return nil, err
	}
	dek, err := Unwrap(master[:], wrapped, "dek:"+m.ID)
	if err != nil {
		return nil, err
	}
	noncePrefix, err := base64.StdEncoding.DecodeString(m.NoncePrefix)
	if err != nil || len(noncePrefix) != 4 {
		return nil, errors.New("manifest: bad nonce prefix")
	}
	dk, _ := objectKeys(prefix, id)
	rc, err := t.Get(ctx, dk)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	ch := &countingHash{h: sha256.New()}
	dec, err := NewDecryptor(io.TeeReader(io.LimitReader(rc, m.CipherSize+1), ch), dek, m.ID, noncePrefix)
	if err != nil {
		return nil, err
	}
	zr, err := zstd.NewReader(dec, zstd.WithDecoderMaxMemory(1<<30))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	want := map[string]Component{}
	for _, c := range m.Components {
		want[c.Name] = c
	}
	var staged []string
	cleanup := func() {
		for _, p := range staged {
			os.Remove(p)
		}
	}
	done := map[string]string{}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("backup archive: %w", err)
		}
		c, ok := want[h.Name]
		if !ok || h.Typeflag != tar.TypeReg || h.Size != c.Size {
			cleanup()
			return nil, fmt.Errorf("backup archive: unexpected entry %q", h.Name)
		}
		target, err := dest(c)
		if err != nil {
			cleanup()
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			cleanup()
			return nil, err
		}
		tmp := target + ".restore"
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			cleanup()
			return nil, err
		}
		staged = append(staged, tmp)
		hs := sha256.New()
		_, err = io.Copy(io.MultiWriter(f, hs), io.LimitReader(tr, c.Size))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("restore %s: %w", c.Name, err)
		}
		if hex.EncodeToString(hs.Sum(nil)) != c.SHA256 {
			cleanup()
			return nil, fmt.Errorf("restore %s: checksum mismatch", c.Name)
		}
		done[tmp] = target
	}
	// Drain to authenticate the final chunk and check the ciphertext hash.
	if _, err := io.Copy(io.Discard, zr); err != nil {
		cleanup()
		return nil, err
	}
	if _, err := io.Copy(io.Discard, dec); err != nil {
		cleanup()
		return nil, err
	}
	if ch.n != m.CipherSize || hex.EncodeToString(ch.h.Sum(nil)) != m.CipherSHA256 {
		cleanup()
		return nil, ErrTampered
	}
	if len(done) != len(want) {
		cleanup()
		return nil, fmt.Errorf("backup archive incomplete: %d of %d components", len(done), len(want))
	}
	for tmp, target := range done {
		if err := os.Rename(tmp, target); err != nil {
			return nil, err
		}
	}
	return m, nil
}
