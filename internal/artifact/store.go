// Package artifact implements artifactd: the narrow ingest service that
// accepts build outputs, validates them and stores immutable artifacts
// (PRD §4.1, §7.3, ADR-002). The builder never receives the runtime socket;
// it only drops an OCI layout tarball (or static tarball) into a
// per-deployment handoff directory, and artifactd re-hashes every byte.
package artifact

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Limits bound what artifactd will accept.
type Limits struct {
	MaxBlobBytes   int64
	MaxTotalBytes  int64
	MaxStaticFiles int
	MaxLayers      int
}

// DefaultLimits are conservative defaults for single-node hosts.
var DefaultLimits = Limits{MaxBlobBytes: 4 << 30, MaxTotalBytes: 10 << 30, MaxStaticFiles: 100000, MaxLayers: 128}

var (
	digestRE     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	blobPathRE   = regexp.MustCompile(`^blobs/sha256/([a-f0-9]{64})$`)
	ErrInvalid   = errors.New("invalid artifact")
	ErrNotExists = errors.New("artifact not found")
)

// Store is a content-addressed blob store plus extracted static trees.
type Store struct {
	Root   string
	Limits Limits
}

func NewStore(root string, lim Limits) (*Store, error) {
	for _, d := range []string{"blobs/sha256", "static", "tmp", "refs"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			return nil, err
		}
	}
	return &Store{Root: root, Limits: lim}, nil
}

// ValidDigest reports whether d is a sha256 digest string.
func ValidDigest(d string) bool { return digestRE.MatchString(d) }

func (s *Store) blobPath(d string) string {
	return filepath.Join(s.Root, "blobs", "sha256", strings.TrimPrefix(d, "sha256:"))
}

// HasBlob reports whether a blob exists.
func (s *Store) HasBlob(d string) (int64, bool) {
	if !ValidDigest(d) {
		return 0, false
	}
	fi, err := os.Stat(s.blobPath(d))
	if err != nil {
		return 0, false
	}
	return fi.Size(), true
}

// OpenBlob opens a blob for reading.
func (s *Store) OpenBlob(d string) (*os.File, error) {
	if !ValidDigest(d) {
		return nil, ErrInvalid
	}
	f, err := os.Open(s.blobPath(d))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotExists
	}
	return f, err
}

// PutBlob stores r, verifying that its sha256 equals want (when non-empty)
// and that it does not exceed max bytes. It returns the digest and size.
func (s *Store) PutBlob(r io.Reader, want string, max int64) (string, int64, error) {
	if want != "" && !ValidDigest(want) {
		return "", 0, ErrInvalid
	}
	tmp, err := os.CreateTemp(filepath.Join(s.Root, "tmp"), "blob-")
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, max+1))
	if err != nil {
		tmp.Close()
		return "", 0, err
	}
	if n > max {
		tmp.Close()
		return "", 0, fmt.Errorf("%w: blob exceeds %d bytes", ErrInvalid, max)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", 0, err
	}
	tmp.Close()
	got := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if want != "" && got != want {
		return "", 0, fmt.Errorf("%w: digest mismatch (declared %s, actual %s)", ErrInvalid, want, got)
	}
	if err := os.Chmod(tmp.Name(), 0o640); err != nil {
		return "", 0, err
	}
	if err := os.Rename(tmp.Name(), s.blobPath(got)); err != nil {
		return "", 0, err
	}
	return got, n, nil
}

// ReadBlob reads a small blob fully (manifests, configs).
func (s *Store) ReadBlob(d string, max int64) ([]byte, error) {
	f, err := s.OpenBlob(d)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%w: blob too large", ErrInvalid)
	}
	return b, nil
}

// OCI media types accepted.
const (
	MediaOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	MediaOCIIndex       = "application/vnd.oci.image.index.v1+json"
	MediaDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	MediaDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaOCIConfig      = "application/vnd.oci.image.config.v1+json"
	MediaDockerConfig   = "application/vnd.docker.container.image.v1+json"
)

var layerMedia = map[string]bool{
	"application/vnd.oci.image.layer.v1.tar":            true,
	"application/vnd.oci.image.layer.v1.tar+gzip":       true,
	"application/vnd.oci.image.layer.v1.tar+zstd":       true,
	"application/vnd.docker.image.rootfs.diff.tar.gzip": true,
	"application/vnd.docker.image.rootfs.diff.tar":      true,
	"application/vnd.in-toto+json":                      true, // attestation layers
}

// Descriptor is an OCI content descriptor.
type Descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	URLs        []string          `json:"urls,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Platform    *struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
	} `json:"platform,omitempty"`
}

// Manifest is an image manifest.
type Manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        Descriptor   `json:"config"`
	Layers        []Descriptor `json:"layers"`
	Manifests     []Descriptor `json:"manifests"` // for indexes
}

// ImageConfig is the subset of the image config OpenDeploy records.
type ImageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Config       struct {
		User         string              `json:"User"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		Env          []string            `json:"Env"`
		Entrypoint   []string            `json:"Entrypoint"`
		Cmd          []string            `json:"Cmd"`
		WorkingDir   string              `json:"WorkingDir"`
		Labels       map[string]string   `json:"Labels"`
	} `json:"config"`
}

// Info describes an ingested artifact.
type Info struct {
	Kind         string   `json:"kind"` // oci | static
	Digest       string   `json:"digest"`
	MediaType    string   `json:"media_type,omitempty"`
	Size         int64    `json:"size"`
	Layers       int      `json:"layers,omitempty"`
	User         string   `json:"user,omitempty"`
	ExposedPorts []string `json:"exposed_ports,omitempty"`
	Entrypoint   []string `json:"entrypoint,omitempty"`
	Cmd          []string `json:"cmd,omitempty"`
	Architecture string   `json:"architecture,omitempty"`
	Files        int      `json:"files,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

// IngestOCILayout validates and imports an OCI image-layout tarball. Only
// oci-layout, index.json and blobs/sha256/<hex> regular files are accepted;
// every blob is re-hashed; the manifest graph must be complete.
func (s *Store) IngestOCILayout(r io.Reader) (*Info, error) {
	tr := tar.NewReader(r)
	var index []byte
	var total int64
	seen := map[string]int64{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: tar: %v", ErrInvalid, err)
		}
		name := strings.TrimPrefix(path.Clean("/"+h.Name), "/")
		switch h.Typeflag {
		case tar.TypeDir:
			if name != "" && name != "blobs" && name != "blobs/sha256" {
				return nil, fmt.Errorf("%w: unexpected directory %q", ErrInvalid, h.Name)
			}
			continue
		case tar.TypeReg:
		default:
			return nil, fmt.Errorf("%w: entry %q has forbidden type %c", ErrInvalid, h.Name, h.Typeflag)
		}
		total += h.Size
		if total > s.Limits.MaxTotalBytes {
			return nil, fmt.Errorf("%w: artifact exceeds %d bytes", ErrInvalid, s.Limits.MaxTotalBytes)
		}
		switch {
		case name == "oci-layout":
			b, err := io.ReadAll(io.LimitReader(tr, 4096))
			if err != nil || !strings.Contains(string(b), `"imageLayoutVersion"`) {
				return nil, fmt.Errorf("%w: bad oci-layout", ErrInvalid)
			}
		case name == "index.json":
			index, err = io.ReadAll(io.LimitReader(tr, 1<<20))
			if err != nil {
				return nil, err
			}
		case blobPathRE.MatchString(name):
			want := "sha256:" + blobPathRE.FindStringSubmatch(name)[1]
			d, n, err := s.PutBlob(tr, want, s.Limits.MaxBlobBytes)
			if err != nil {
				return nil, err
			}
			seen[d] = n
		case name == "manifest.json" || name == "repositories":
			// docker-archive compatibility files are ignored; index.json is authoritative.
			if _, err := io.Copy(io.Discard, io.LimitReader(tr, 1<<20)); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%w: unexpected entry %q", ErrInvalid, h.Name)
		}
	}
	if index == nil {
		return nil, fmt.Errorf("%w: missing index.json", ErrInvalid)
	}
	var idx Manifest
	if err := json.Unmarshal(index, &idx); err != nil {
		return nil, fmt.Errorf("%w: index.json: %v", ErrInvalid, err)
	}
	desc, err := s.selectManifest(idx.Manifests, seen, 0)
	if err != nil {
		return nil, err
	}
	return s.validateImage(desc, seen)
}

// selectManifest resolves (possibly nested) indexes to a linux/amd64|arm64
// image manifest.
func (s *Store) selectManifest(ds []Descriptor, seen map[string]int64, depth int) (Descriptor, error) {
	if depth > 3 {
		return Descriptor{}, fmt.Errorf("%w: index nesting too deep", ErrInvalid)
	}
	var candidates []Descriptor
	for _, d := range ds {
		if d.Platform != nil && d.Platform.OS != "" && d.Platform.OS != "linux" {
			continue
		}
		if d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
			continue
		}
		candidates = append(candidates, d)
	}
	if len(candidates) == 0 {
		return Descriptor{}, fmt.Errorf("%w: no linux image manifest", ErrInvalid)
	}
	d := candidates[0]
	if err := checkDesc(d, seen); err != nil {
		return Descriptor{}, err
	}
	if d.MediaType == MediaOCIIndex || d.MediaType == MediaDockerList {
		b, err := s.ReadBlob(d.Digest, 4<<20)
		if err != nil {
			return Descriptor{}, err
		}
		var inner Manifest
		if err := json.Unmarshal(b, &inner); err != nil {
			return Descriptor{}, fmt.Errorf("%w: nested index: %v", ErrInvalid, err)
		}
		return s.selectManifest(inner.Manifests, seen, depth+1)
	}
	return d, nil
}

func checkDesc(d Descriptor, seen map[string]int64) error {
	if !ValidDigest(d.Digest) {
		return fmt.Errorf("%w: bad digest %q", ErrInvalid, d.Digest)
	}
	if len(d.URLs) > 0 {
		return fmt.Errorf("%w: foreign (URL) layers are not allowed", ErrInvalid)
	}
	n, ok := seen[d.Digest]
	if !ok {
		return fmt.Errorf("%w: blob %s missing from layout", ErrInvalid, d.Digest)
	}
	if n != d.Size {
		return fmt.Errorf("%w: blob %s size %d != descriptor %d", ErrInvalid, d.Digest, n, d.Size)
	}
	return nil
}

func (s *Store) validateImage(d Descriptor, seen map[string]int64) (*Info, error) {
	if d.MediaType != MediaOCIManifest && d.MediaType != MediaDockerManifest {
		return nil, fmt.Errorf("%w: unsupported manifest media type %q", ErrInvalid, d.MediaType)
	}
	b, err := s.ReadBlob(d.Digest, 4<<20)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%w: manifest: %v", ErrInvalid, err)
	}
	if m.SchemaVersion != 2 {
		return nil, fmt.Errorf("%w: schemaVersion %d", ErrInvalid, m.SchemaVersion)
	}
	if m.Config.MediaType != MediaOCIConfig && m.Config.MediaType != MediaDockerConfig {
		return nil, fmt.Errorf("%w: config media type %q", ErrInvalid, m.Config.MediaType)
	}
	if err := checkDesc(m.Config, seen); err != nil {
		return nil, err
	}
	if len(m.Layers) > s.Limits.MaxLayers {
		return nil, fmt.Errorf("%w: too many layers (%d)", ErrInvalid, len(m.Layers))
	}
	var size int64 = int64(len(b)) + m.Config.Size
	for _, l := range m.Layers {
		if !layerMedia[l.MediaType] {
			return nil, fmt.Errorf("%w: layer media type %q not allowed", ErrInvalid, l.MediaType)
		}
		if err := checkDesc(l, seen); err != nil {
			return nil, err
		}
		size += l.Size
	}
	cb, err := s.ReadBlob(m.Config.Digest, 4<<20)
	if err != nil {
		return nil, err
	}
	var cfg ImageConfig
	if err := json.Unmarshal(cb, &cfg); err != nil {
		return nil, fmt.Errorf("%w: image config: %v", ErrInvalid, err)
	}
	if cfg.OS != "" && cfg.OS != "linux" {
		return nil, fmt.Errorf("%w: image OS %q is not linux", ErrInvalid, cfg.OS)
	}
	info := &Info{Kind: "oci", Digest: d.Digest, MediaType: d.MediaType, Size: size, Layers: len(m.Layers),
		User: cfg.Config.User, Entrypoint: cfg.Config.Entrypoint, Cmd: cfg.Config.Cmd, Architecture: cfg.Architecture}
	for p := range cfg.Config.ExposedPorts {
		info.ExposedPorts = append(info.ExposedPorts, p)
	}
	sort.Strings(info.ExposedPorts)
	if u := cfg.Config.User; u == "" || u == "root" || u == "0" || strings.HasPrefix(u, "0:") || strings.HasPrefix(u, "root:") {
		info.Warnings = append(info.Warnings, "image runs as root; OpenDeploy drops all capabilities and remaps users where supported, but a non-root USER is recommended")
	}
	return info, nil
}

// IngestStatic validates a static-site tarball and extracts it to
// static/<treehash>. Only regular files and directories with clean
// relative paths are accepted; the tree digest is computed over sorted
// (path, sha256) pairs so it is independent of tar ordering and metadata.
func (s *Store) IngestStatic(r io.Reader) (*Info, error) {
	tmpDir, err := os.MkdirTemp(filepath.Join(s.Root, "tmp"), "static-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)
	tr := tar.NewReader(r)
	type entry struct{ path, sum string }
	var entries []entry
	var total int64
	files := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: tar: %v", ErrInvalid, err)
		}
		clean, err := cleanRel(h.Name)
		if err != nil {
			return nil, err
		}
		if clean == "" {
			continue
		}
		dst := filepath.Join(tmpDir, filepath.FromSlash(clean))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return nil, err
			}
		case tar.TypeReg:
			files++
			if files > s.Limits.MaxStaticFiles {
				return nil, fmt.Errorf("%w: more than %d files", ErrInvalid, s.Limits.MaxStaticFiles)
			}
			total += h.Size
			if total > s.Limits.MaxTotalBytes {
				return nil, fmt.Errorf("%w: static artifact too large", ErrInvalid)
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return nil, err
			}
			f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
			}
			hh := sha256.New()
			if _, err := io.Copy(io.MultiWriter(f, hh), io.LimitReader(tr, h.Size)); err != nil {
				f.Close()
				return nil, err
			}
			f.Close()
			entries = append(entries, entry{clean, hex.EncodeToString(hh.Sum(nil))})
		default:
			return nil, fmt.Errorf("%w: %q: only regular files and directories are allowed in static artifacts", ErrInvalid, h.Name)
		}
	}
	if files == 0 {
		return nil, fmt.Errorf("%w: static artifact is empty", ErrInvalid)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	th := sha256.New()
	for _, e := range entries {
		fmt.Fprintf(th, "%s\x00%s\n", e.path, e.sum)
	}
	digest := "sha256:" + hex.EncodeToString(th.Sum(nil))
	final := s.StaticDir(digest)
	if _, err := os.Stat(final); err == nil {
		return &Info{Kind: "static", Digest: digest, Size: total, Files: files}, nil
	}
	if err := os.Rename(tmpDir, final); err != nil {
		return nil, err
	}
	_ = os.Chmod(final, 0o755)
	info := &Info{Kind: "static", Digest: digest, Size: total, Files: files}
	if _, err := os.Stat(filepath.Join(final, "index.html")); err != nil {
		info.Warnings = append(info.Warnings, "static artifact has no index.html at its root")
	}
	return info, nil
}

// StaticDir returns the extracted directory for a static digest.
func (s *Store) StaticDir(digest string) string {
	return filepath.Join(s.Root, "static", strings.TrimPrefix(digest, "sha256:"))
}

func cleanRel(name string) (string, error) {
	n := strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(n, "/") {
		n = strings.TrimLeft(n, "/")
	}
	for _, part := range strings.Split(n, "/") {
		if part == ".." {
			return "", fmt.Errorf("%w: path %q escapes artifact root", ErrInvalid, name)
		}
	}
	c := path.Clean(n)
	if c == "." {
		return "", nil
	}
	if strings.ContainsRune(c, 0) || len(c) > 1024 {
		return "", fmt.Errorf("%w: bad path", ErrInvalid)
	}
	return c, nil
}

// DeleteStatic removes an extracted static tree.
func (s *Store) DeleteStatic(digest string) error {
	if !ValidDigest(digest) {
		return ErrInvalid
	}
	return os.RemoveAll(s.StaticDir(digest))
}

// Tag records name:tag -> manifest digest for registry reads.
func (s *Store) Tag(repo, tag, digest string) error {
	if !repoRE.MatchString(repo) || !tagRE.MatchString(tag) || !ValidDigest(digest) {
		return ErrInvalid
	}
	dir := filepath.Join(s.Root, "refs", filepath.FromSlash(repo))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+tag+".tmp")
	if err := os.WriteFile(tmp, []byte(digest), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, tag))
}

// Resolve returns the digest for repo:tag.
func (s *Store) Resolve(repo, tag string) (string, error) {
	if !repoRE.MatchString(repo) || !tagRE.MatchString(tag) {
		return "", ErrInvalid
	}
	b, err := os.ReadFile(filepath.Join(s.Root, "refs", filepath.FromSlash(repo), tag))
	if err != nil {
		return "", ErrNotExists
	}
	d := strings.TrimSpace(string(b))
	if !ValidDigest(d) {
		return "", ErrInvalid
	}
	return d, nil
}

var (
	repoRE = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*){0,3}$`)
	tagRE  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
)
