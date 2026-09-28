package artifact

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

// IPC operations.
const (
	OpIngest    = "artifact.ingest"
	OpPushGrant = "artifact.push_grant"
	OpInfo      = "artifact.info"
	OpStaticDir = "artifact.static_dir"
	OpGC        = "artifact.gc"
	OpPullCreds = "artifact.pull_credentials"
)

// Handoff file names inside handoff/<deployment-id>/.
const (
	HandoffImage  = "image.oci.tar"
	HandoffStatic = "static.tar"
)

type IngestReq struct {
	ProjectID    string `json:"project_id"`
	DeploymentID string `json:"deployment_id"`
	Kind         string `json:"kind"` // oci | static | pushed
}

type IngestResp struct {
	Info
	ImageRef string `json:"image_ref,omitempty"`
}

type PushGrantReq struct {
	ProjectID    string `json:"project_id"`
	DeploymentID string `json:"deployment_id"`
}

type PushGrantResp struct {
	Registry string `json:"registry"`
	Repo     string `json:"repo"`
	Tag      string `json:"tag"`
	User     string `json:"user"`
	Token    string `json:"token"`
}

type DigestReq struct {
	Digest string `json:"digest"`
	Kind   string `json:"kind"`
}

type StaticDirResp struct {
	Path string `json:"path"`
}

type GCReq struct {
	KeepImages []string `json:"keep_images"`
	KeepStatic []string `json:"keep_static"`
}

type GCResp struct {
	RemovedBlobs  int   `json:"removed_blobs"`
	RemovedStatic int   `json:"removed_static"`
	FreedBytes    int64 `json:"freed_bytes"`
}

type PullCreds struct {
	Registry string `json:"registry"`
	User     string `json:"user"`
	Token    string `json:"token"`
}

type Empty struct{}

// Service wires the store, registry and audit sink to IPC.
type Service struct {
	Store       *Store
	Registry    *Registry
	RegistryURL string // host:port
	HandoffDir  string
	Audit       audit.Sink
}

// Repo is the registry repository for a project.
func Repo(projectID string) string {
	return "od/" + strings.ReplaceAll(strings.ToLower(projectID), "_", "-")
}

func (s *Service) handoff(depID, name string) (string, error) {
	if !ids.HasPrefix(depID, "dep") {
		return "", ipc.Errorf(ipc.CodeBadRequest, "invalid deployment id")
	}
	p := filepath.Join(s.HandoffDir, depID, name)
	fi, err := os.Lstat(p)
	if err != nil {
		return "", ipc.Errorf(ipc.CodeNotFound, "no build output for deployment")
	}
	if !fi.Mode().IsRegular() {
		return "", ipc.Errorf(ipc.CodeBadRequest, "build output is not a regular file")
	}
	return p, nil
}

// Ingest validates and imports a build output.
func (s *Service) Ingest(ctx context.Context, r IngestReq) (*IngestResp, error) {
	if !ids.HasPrefix(r.ProjectID, "prj") {
		return nil, ipc.Errorf(ipc.CodeBadRequest, "invalid project id")
	}
	var info *Info
	var err error
	repo := Repo(r.ProjectID)
	switch r.Kind {
	case "oci":
		p, herr := s.handoff(r.DeploymentID, HandoffImage)
		if herr != nil {
			return nil, herr
		}
		f, ferr := os.Open(p)
		if ferr != nil {
			return nil, ferr
		}
		info, err = s.Store.IngestOCILayout(f)
		f.Close()
		if err == nil {
			err = s.Store.Tag(repo, r.DeploymentID, info.Digest)
		}
		_ = os.Remove(p)
	case "static":
		p, herr := s.handoff(r.DeploymentID, HandoffStatic)
		if herr != nil {
			return nil, herr
		}
		f, ferr := os.Open(p)
		if ferr != nil {
			return nil, ferr
		}
		info, err = s.Store.IngestStatic(f)
		f.Close()
		_ = os.Remove(p)
	case "pushed":
		info, err = s.Store.ValidateTagged(repo, r.DeploymentID)
	default:
		return nil, ipc.Errorf(ipc.CodeBadRequest, "unknown kind %q", r.Kind)
	}
	res := audit.Success
	details := map[string]string{"deployment_id": r.DeploymentID}
	if err != nil {
		res = audit.Denied
		details["reason"] = trunc(err.Error(), 500)
	} else {
		details["artifact_digest"] = info.Digest
	}
	if s.Audit != nil {
		_, _ = s.Audit.Append(ctx, audit.Event{ActorType: audit.ActorService, ActorID: identity.Artifact, Action: "artifact.ingest",
			ResourceType: "artifact", ResourceID: r.DeploymentID, ProjectID: r.ProjectID, Result: res, Details: details})
	}
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			return nil, ipc.Errorf(ipc.CodeBadRequest, "%v", err)
		}
		return nil, err
	}
	out := &IngestResp{Info: *info}
	if info.Kind == "oci" {
		out.ImageRef = fmt.Sprintf("%s/%s@%s", s.RegistryURL, repo, info.Digest)
	}
	return out, nil
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// GC removes blobs unreachable from the kept manifests and static trees
// not in the keep set.
func (s *Service) GC(_ context.Context, r GCReq) (*GCResp, error) {
	keep := map[string]bool{}
	var mark func(d string, depth int)
	mark = func(d string, depth int) {
		if depth > 3 || !ValidDigest(d) || keep[d] {
			return
		}
		keep[d] = true
		b, err := s.Store.ReadBlob(d, 4<<20)
		if err != nil {
			return
		}
		var m Manifest
		if json.Unmarshal(b, &m) != nil {
			return
		}
		if m.Config.Digest != "" {
			keep[m.Config.Digest] = true
		}
		for _, l := range m.Layers {
			keep[l.Digest] = true
		}
		for _, c := range m.Manifests {
			mark(c.Digest, depth+1)
		}
	}
	for _, d := range r.KeepImages {
		mark(d, 0)
	}
	out := &GCResp{}
	blobDir := filepath.Join(s.Store.Root, "blobs", "sha256")
	entries, err := os.ReadDir(blobDir)
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().Add(-1 * time.Hour) // never collect blobs from in-flight pushes
	for _, e := range entries {
		d := "sha256:" + e.Name()
		if keep[d] {
			continue
		}
		fi, err := e.Info()
		if err != nil || fi.ModTime().After(cutoff) {
			continue
		}
		if os.Remove(filepath.Join(blobDir, e.Name())) == nil {
			out.RemovedBlobs++
			out.FreedBytes += fi.Size()
		}
	}
	keepStatic := map[string]bool{}
	for _, d := range r.KeepStatic {
		keepStatic[strings.TrimPrefix(d, "sha256:")] = true
	}
	sdirs, _ := os.ReadDir(filepath.Join(s.Store.Root, "static"))
	for _, e := range sdirs {
		if keepStatic[e.Name()] {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.ModTime().After(cutoff) {
			continue
		}
		if os.RemoveAll(filepath.Join(s.Store.Root, "static", e.Name())) == nil {
			out.RemovedStatic++
		}
	}
	return out, nil
}

// Register exposes the service over IPC.
func Register(srv *ipc.Server, s *Service) {
	ipc.Handle(srv, OpIngest, []string{identity.Builder}, func(ctx context.Context, _ ipc.Caller, r IngestReq) (*IngestResp, error) {
		return s.Ingest(ctx, r)
	})
	ipc.Handle(srv, OpPushGrant, []string{identity.Builder}, func(ctx context.Context, _ ipc.Caller, r PushGrantReq) (*PushGrantResp, error) {
		if !ids.HasPrefix(r.ProjectID, "prj") || !ids.HasPrefix(r.DeploymentID, "dep") {
			return nil, ipc.Errorf(ipc.CodeBadRequest, "invalid ids")
		}
		repo := Repo(r.ProjectID)
		tok, err := s.Registry.GrantPush(repo, time.Hour)
		if err != nil {
			return nil, err
		}
		return &PushGrantResp{Registry: s.RegistryURL, Repo: repo, Tag: r.DeploymentID, User: "push", Token: tok}, nil
	})
	ipc.Handle(srv, OpInfo, []string{identity.Platform, identity.Runtime}, func(_ context.Context, _ ipc.Caller, r DigestReq) (*Info, error) {
		if r.Kind == "static" {
			if _, err := os.Stat(s.Store.StaticDir(r.Digest)); err != nil || !ValidDigest(r.Digest) {
				return nil, ipc.Errorf(ipc.CodeNotFound, "static artifact not found")
			}
			return &Info{Kind: "static", Digest: r.Digest}, nil
		}
		n, ok := s.Store.HasBlob(r.Digest)
		if !ok {
			return nil, ipc.Errorf(ipc.CodeNotFound, "artifact not found")
		}
		return &Info{Kind: "oci", Digest: r.Digest, Size: n}, nil
	})
	ipc.Handle(srv, OpStaticDir, []string{identity.Router, identity.Platform}, func(_ context.Context, _ ipc.Caller, r DigestReq) (*StaticDirResp, error) {
		if !ValidDigest(r.Digest) {
			return nil, ipc.Errorf(ipc.CodeBadRequest, "invalid digest")
		}
		p := s.Store.StaticDir(r.Digest)
		if _, err := os.Stat(p); err != nil {
			return nil, ipc.Errorf(ipc.CodeNotFound, "static artifact not found")
		}
		return &StaticDirResp{Path: p}, nil
	})
	ipc.Handle(srv, OpGC, []string{identity.Platform}, func(ctx context.Context, _ ipc.Caller, r GCReq) (*GCResp, error) {
		return s.GC(ctx, r)
	})
	ipc.Handle(srv, OpPullCreds, []string{identity.Runtime}, func(_ context.Context, _ ipc.Caller, _ Empty) (*PullCreds, error) {
		return &PullCreds{Registry: s.RegistryURL, User: s.Registry.PullUser, Token: s.Registry.PullToken}, nil
	})
}

// Client is a typed artifactd client.
type Client struct{ C *ipc.Client }

func (c *Client) Ingest(ctx context.Context, r IngestReq) (*IngestResp, error) {
	return ipc.Call[IngestReq, *IngestResp](ctx, c.C, OpIngest, r)
}
func (c *Client) PushGrant(ctx context.Context, r PushGrantReq) (*PushGrantResp, error) {
	return ipc.Call[PushGrantReq, *PushGrantResp](ctx, c.C, OpPushGrant, r)
}
func (c *Client) StaticDir(ctx context.Context, digest string) (string, error) {
	r, err := ipc.Call[DigestReq, *StaticDirResp](ctx, c.C, OpStaticDir, DigestReq{Digest: digest})
	if err != nil {
		return "", err
	}
	return r.Path, nil
}
func (c *Client) GC(ctx context.Context, r GCReq) (*GCResp, error) {
	return ipc.Call[GCReq, *GCResp](ctx, c.C, OpGC, r)
}
func (c *Client) PullCredentials(ctx context.Context) (*PullCreds, error) {
	return ipc.Call[Empty, *PullCreds](ctx, c.C, OpPullCreds, Empty{})
}
