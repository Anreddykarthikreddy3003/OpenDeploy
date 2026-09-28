package artifact

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
)

// Registry serves a minimal OCI distribution API over the artifact store.
// Pulls require the node pull credential (held by runtimed / the container
// runtime). Pushes require a short-lived token scoped to one repository,
// issued to builderd for buildpack builds; pushed manifests are fully
// validated before they are accepted.
type Registry struct {
	Store     *Store
	PullUser  string
	PullToken string
	Log       *slog.Logger

	mu      sync.Mutex
	push    map[string]pushGrant // token -> grant
	uploads map[string]*upload
}

type pushGrant struct {
	repo    string
	expires time.Time
}

type upload struct {
	repo    string
	path    string
	size    int64
	expires time.Time
}

// NewRegistry creates a registry handler.
func NewRegistry(s *Store, pullToken string, log *slog.Logger) *Registry {
	if log == nil {
		log = slog.Default()
	}
	return &Registry{Store: s, PullUser: "runtime", PullToken: pullToken, Log: log, push: map[string]pushGrant{}, uploads: map[string]*upload{}}
}

// GrantPush issues a push token for repo valid for ttl.
func (r *Registry) GrantPush(repo string, ttl time.Duration) (string, error) {
	if !repoRE.MatchString(repo) {
		return "", ErrInvalid
	}
	tok := ids.Token(32)
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for k, g := range r.push {
		if now.After(g.expires) {
			delete(r.push, k)
		}
	}
	r.push[tok] = pushGrant{repo: repo, expires: now.Add(ttl)}
	return tok, nil
}

// RevokePush invalidates a push token.
func (r *Registry) RevokePush(tok string) {
	r.mu.Lock()
	delete(r.push, tok)
	r.mu.Unlock()
}

var routeRE = regexp.MustCompile(`^/v2/(.+?)/(manifests|blobs)/(.+)$`)

type access struct {
	pull bool
	repo string // push scope
}

func (r *Registry) auth(req *http.Request) (access, bool) {
	u, p, ok := req.BasicAuth()
	if !ok {
		return access{}, false
	}
	if u == r.PullUser && r.PullToken != "" && subtle.ConstantTimeCompare([]byte(p), []byte(r.PullToken)) == 1 {
		return access{pull: true}, true
	}
	if u == "push" {
		r.mu.Lock()
		g, ok := r.push[p]
		r.mu.Unlock()
		if ok && time.Now().Before(g.expires) {
			return access{pull: true, repo: g.repo}, true
		}
	}
	return access{}, false
}

func (r *Registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	acc, ok := r.auth(req)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="opendeploy-artifactd"`)
		regErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}
	if req.URL.Path == "/v2/" || req.URL.Path == "/v2" {
		w.WriteHeader(http.StatusOK)
		return
	}
	m := routeRE.FindStringSubmatch(req.URL.Path)
	if m == nil {
		regErr(w, http.StatusNotFound, "NAME_UNKNOWN", "not found")
		return
	}
	repo, kind, rest := m[1], m[2], m[3]
	if !repoRE.MatchString(repo) {
		regErr(w, http.StatusBadRequest, "NAME_INVALID", "invalid repository name")
		return
	}
	write := req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch || req.Method == http.MethodDelete
	if write && acc.repo != repo {
		regErr(w, http.StatusForbidden, "DENIED", "push not permitted for this repository")
		return
	}
	switch {
	case kind == "manifests":
		r.manifest(w, req, repo, rest)
	case kind == "blobs" && (rest == "uploads" || rest == "uploads/" || strings.HasPrefix(rest, "uploads/")):
		r.uploadHandler(w, req, repo, strings.TrimPrefix(strings.TrimPrefix(rest, "uploads"), "/"))
	case kind == "blobs":
		r.blob(w, req, rest)
	default:
		regErr(w, http.StatusNotFound, "NAME_UNKNOWN", "not found")
	}
}

func regErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]string{{"code": code, "message": msg}}})
}

func (r *Registry) blob(w http.ResponseWriter, req *http.Request, digest string) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		regErr(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "method not allowed")
		return
	}
	size, ok := r.Store.HasBlob(digest)
	if !ok {
		regErr(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob unknown")
		return
	}
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Content-Type", "application/octet-stream")
	if req.Method == http.MethodHead {
		return
	}
	f, err := r.Store.OpenBlob(digest)
	if err != nil {
		regErr(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob unknown")
		return
	}
	defer f.Close()
	_, _ = io.Copy(w, f)
}

func manifestMediaType(b []byte) string {
	var m struct {
		MediaType string            `json:"mediaType"`
		Manifests []json.RawMessage `json:"manifests"`
	}
	_ = json.Unmarshal(b, &m)
	if m.MediaType != "" {
		return m.MediaType
	}
	if m.Manifests != nil {
		return MediaOCIIndex
	}
	return MediaOCIManifest
}

func (r *Registry) manifest(w http.ResponseWriter, req *http.Request, repo, ref string) {
	switch req.Method {
	case http.MethodGet, http.MethodHead:
		digest := ref
		if !ValidDigest(ref) {
			d, err := r.Store.Resolve(repo, ref)
			if err != nil {
				regErr(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest unknown")
				return
			}
			digest = d
		}
		b, err := r.Store.ReadBlob(digest, 4<<20)
		if err != nil {
			regErr(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest unknown")
			return
		}
		w.Header().Set("Content-Type", manifestMediaType(b))
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		if req.Method == http.MethodGet {
			_, _ = w.Write(b)
		}
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(req.Body, 4<<20+1))
		if err != nil || len(body) > 4<<20 {
			regErr(w, http.StatusBadRequest, "MANIFEST_INVALID", "manifest too large")
			return
		}
		if _, err := r.validatePushedManifest(body, 0); err != nil {
			regErr(w, http.StatusBadRequest, "MANIFEST_INVALID", err.Error())
			return
		}
		sum := sha256.Sum256(body)
		digest := "sha256:" + hex.EncodeToString(sum[:])
		if ValidDigest(ref) && ref != digest {
			regErr(w, http.StatusBadRequest, "DIGEST_INVALID", "digest mismatch")
			return
		}
		if _, _, err := r.Store.PutBlob(strings.NewReader(string(body)), digest, 4<<20); err != nil {
			regErr(w, http.StatusInternalServerError, "UNKNOWN", err.Error())
			return
		}
		if !ValidDigest(ref) {
			if err := r.Store.Tag(repo, ref, digest); err != nil {
				regErr(w, http.StatusBadRequest, "TAG_INVALID", "invalid tag")
				return
			}
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", repo, digest))
		w.WriteHeader(http.StatusCreated)
	default:
		regErr(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "method not allowed")
	}
}

// validatePushedManifest checks that all referenced content exists with the
// declared sizes and media types.
func (r *Registry) validatePushedManifest(body []byte, depth int) (string, error) {
	if depth > 2 {
		return "", errors.New("index nesting too deep")
	}
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return "", err
	}
	mt := manifestMediaType(body)
	seen := func(d Descriptor) error {
		if len(d.URLs) > 0 {
			return errors.New("foreign layers not allowed")
		}
		n, ok := r.Store.HasBlob(d.Digest)
		if !ok {
			return fmt.Errorf("blob %s not uploaded", d.Digest)
		}
		if n != d.Size {
			return fmt.Errorf("blob %s size mismatch", d.Digest)
		}
		return nil
	}
	switch mt {
	case MediaOCIIndex, MediaDockerList:
		for _, d := range m.Manifests {
			if err := seen(d); err != nil {
				return "", err
			}
		}
	case MediaOCIManifest, MediaDockerManifest:
		if m.Config.MediaType != MediaOCIConfig && m.Config.MediaType != MediaDockerConfig {
			return "", fmt.Errorf("config media type %q", m.Config.MediaType)
		}
		if err := seen(m.Config); err != nil {
			return "", err
		}
		if len(m.Layers) > r.Store.Limits.MaxLayers {
			return "", errors.New("too many layers")
		}
		for _, l := range m.Layers {
			if !layerMedia[l.MediaType] {
				return "", fmt.Errorf("layer media type %q", l.MediaType)
			}
			if err := seen(l); err != nil {
				return "", err
			}
		}
	default:
		return "", fmt.Errorf("unsupported manifest media type %q", mt)
	}
	return mt, nil
}

func (r *Registry) uploadHandler(w http.ResponseWriter, req *http.Request, repo, id string) {
	r.gcUploads()
	switch {
	case req.Method == http.MethodPost && id == "":
		f, err := os.CreateTemp(filepath.Join(r.Store.Root, "tmp"), "upload-")
		if err != nil {
			regErr(w, http.StatusInternalServerError, "UNKNOWN", "cannot create upload")
			return
		}
		f.Close()
		uid := ids.Token(16)
		r.mu.Lock()
		r.uploads[uid] = &upload{repo: repo, path: f.Name(), expires: time.Now().Add(time.Hour)}
		r.mu.Unlock()
		// Monolithic POST with ?digest= is also allowed.
		if d := req.URL.Query().Get("digest"); d != "" {
			r.finish(w, req, repo, uid, d)
			return
		}
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, uid))
		w.Header().Set("Range", "0-0")
		w.Header().Set("Docker-Upload-UUID", uid)
		w.WriteHeader(http.StatusAccepted)
	case req.Method == http.MethodPatch && id != "":
		up := r.getUpload(repo, id)
		if up == nil {
			regErr(w, http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "upload unknown")
			return
		}
		n, err := appendUpload(up, req.Body, r.Store.Limits.MaxBlobBytes)
		if err != nil {
			regErr(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", err.Error())
			return
		}
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, id))
		w.Header().Set("Range", fmt.Sprintf("0-%d", n-1))
		w.Header().Set("Docker-Upload-UUID", id)
		w.WriteHeader(http.StatusAccepted)
	case req.Method == http.MethodPut && id != "":
		r.finish(w, req, repo, id, req.URL.Query().Get("digest"))
	case req.Method == http.MethodDelete && id != "":
		if up := r.getUpload(repo, id); up != nil {
			r.dropUpload(id)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		regErr(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "method not allowed")
	}
}

func (r *Registry) finish(w http.ResponseWriter, req *http.Request, repo, id, digest string) {
	up := r.getUpload(repo, id)
	if up == nil {
		regErr(w, http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "upload unknown")
		return
	}
	defer r.dropUpload(id)
	if !ValidDigest(digest) {
		regErr(w, http.StatusBadRequest, "DIGEST_INVALID", "digest required")
		return
	}
	if _, err := appendUpload(up, req.Body, r.Store.Limits.MaxBlobBytes); err != nil {
		regErr(w, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", err.Error())
		return
	}
	f, err := os.Open(up.path)
	if err != nil {
		regErr(w, http.StatusInternalServerError, "UNKNOWN", "upload lost")
		return
	}
	defer f.Close()
	if _, _, err := r.Store.PutBlob(f, digest, r.Store.Limits.MaxBlobBytes); err != nil {
		regErr(w, http.StatusBadRequest, "DIGEST_INVALID", err.Error())
		return
	}
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo, digest))
	w.WriteHeader(http.StatusCreated)
}

func appendUpload(up *upload, body io.Reader, max int64) (int64, error) {
	f, err := os.OpenFile(up.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(body, max-up.size+1))
	if err != nil {
		return 0, err
	}
	up.size += n
	if up.size > max {
		return 0, errors.New("blob too large")
	}
	return up.size, nil
}

func (r *Registry) getUpload(repo, id string) *upload {
	r.mu.Lock()
	defer r.mu.Unlock()
	up, ok := r.uploads[id]
	if !ok || up.repo != repo || time.Now().After(up.expires) {
		return nil
	}
	return up
}

func (r *Registry) dropUpload(id string) {
	r.mu.Lock()
	up, ok := r.uploads[id]
	delete(r.uploads, id)
	r.mu.Unlock()
	if ok {
		os.Remove(up.path)
	}
}

func (r *Registry) gcUploads() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for id, up := range r.uploads {
		if now.After(up.expires) {
			os.Remove(up.path)
			delete(r.uploads, id)
		}
	}
}

// ValidateTagged validates the image manifest referenced by repo:tag and
// returns its Info (used after buildpack pushes).
func (s *Store) ValidateTagged(repo, tag string) (*Info, error) {
	d, err := s.Resolve(repo, tag)
	if err != nil {
		return nil, err
	}
	b, err := s.ReadBlob(d, 4<<20)
	if err != nil {
		return nil, err
	}
	seen := map[string]int64{}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	all := append([]Descriptor{m.Config}, m.Layers...)
	all = append(all, m.Manifests...)
	for _, x := range all {
		if n, ok := s.HasBlob(x.Digest); ok {
			seen[x.Digest] = n
		}
	}
	seen[d] = int64(len(b))
	mt := manifestMediaType(b)
	desc := Descriptor{MediaType: mt, Digest: d, Size: int64(len(b))}
	if mt == MediaOCIIndex || mt == MediaDockerList {
		// Record child manifests' sizes as well.
		for _, c := range m.Manifests {
			if cb, err := s.ReadBlob(c.Digest, 4<<20); err == nil {
				var cm Manifest
				_ = json.Unmarshal(cb, &cm)
				for _, x := range append([]Descriptor{cm.Config}, cm.Layers...) {
					if n, ok := s.HasBlob(x.Digest); ok {
						seen[x.Digest] = n
					}
				}
			}
		}
		desc, err = s.selectManifest(m.Manifests, seen, 0)
		if err != nil {
			return nil, err
		}
	}
	return s.validateImage(desc, seen)
}
