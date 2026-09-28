// Package runtime implements runtimed: the dedicated runtime identity that
// creates OCI workloads through a typed API (PRD §4.1, §8, SC-02, SC-04,
// SC-12, SC-22, SC-23). It exposes no generic exec, never publishes host
// ports, never mounts runtime sockets or arbitrary host paths, and only
// runs images that artifactd validated (plus pinned backing-service
// templates).
package runtime

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/policy"
)

// Runtime handler names (mirror trust.Runtime).
const (
	RuntimeRunc  = "runc"
	RuntimeRunsc = "runsc"
	RuntimeVM    = "vm"
)

// Spec describes a workload to run.
type Spec struct {
	ID            string            `json:"id"` // workload id (wkl_...)
	ProjectID     string            `json:"project_id"`
	EnvironmentID string            `json:"environment_id"`
	DeploymentID  string            `json:"deployment_id"`
	Service       string            `json:"service"`
	Kind          string            `json:"kind"` // app | backing
	Image         string            `json:"image"`
	Runtime       string            `json:"runtime"`
	Command       []string          `json:"command,omitempty"`
	Env           map[string]string `json:"env,omitempty"`
	SecretFiles   map[string]string `json:"secret_files,omitempty"` // name -> value, mounted read-only at /run/secrets/<name>
	Port          int               `json:"port"`
	MemoryBytes   int64             `json:"memory_bytes"`
	CPU           float64           `json:"cpu"`
	PIDs          int               `json:"pids"`
	ReadOnlyRoot  bool              `json:"read_only_root"`
	Tmpfs         []string          `json:"tmpfs,omitempty"`
	Volumes       []VolumeMount     `json:"volumes,omitempty"`
	Network       string            `json:"network"` // environment network id
	Aliases       []string          `json:"aliases,omitempty"`
	Capabilities  []string          `json:"capabilities,omitempty"`
	User          string            `json:"user,omitempty"`
	Replica       int               `json:"replica"`
}

// VolumeMount references an opaque, runtimed-owned volume (never a host path).
type VolumeMount struct {
	VolumeID string `json:"volume_id"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
	OwnerUID int    `json:"owner_uid"`
}

// Workload is the observed state of a workload.
type Workload struct {
	ID        string            `json:"id"`
	RuntimeID string            `json:"runtime_id"`
	State     string            `json:"state"` // created | running | exited | missing
	Endpoint  string            `json:"endpoint,omitempty"`
	IP        string            `json:"ip,omitempty"`
	ExitCode  int               `json:"exit_code"`
	StartedAt string            `json:"started_at,omitempty"`
	Restarts  int               `json:"restarts"`
	OOMKilled bool              `json:"oom_killed"`
	Labels    map[string]string `json:"labels,omitempty"`
}

var (
	envNameRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	serviceRE   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	secretRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
	reservedEnv = map[string]bool{"LD_PRELOAD": true, "LD_LIBRARY_PATH": true, "LD_AUDIT": true, "DOCKER_HOST": true, "CONTAINERD_ADDRESS": true}
)

// TemplateImages are the only non-artifactd images runtimed will run
// (backing-service templates, pinned by the release; SC-19).
var TemplateImages = map[string]string{
	"postgres": "postgres:16-bookworm",
	"mysql":    "mysql:8.4",
	"redis":    "redis:7-bookworm",
}

// Validate enforces the runtime default restrictions (PRD §8.1).
func (s *Spec) Validate(registry string, allowedRuntimes map[string]bool) error {
	var p []string
	add := func(f string, a ...any) { p = append(p, fmt.Sprintf(f, a...)) }
	if !ids.HasPrefix(s.ID, "wkl") {
		add("invalid workload id")
	}
	if !ids.HasPrefix(s.ProjectID, "prj") || !ids.HasPrefix(s.EnvironmentID, "env") {
		add("invalid project/environment id")
	}
	if !serviceRE.MatchString(s.Service) {
		add("invalid service name")
	}
	switch s.Kind {
	case "app":
		if !strings.HasPrefix(s.Image, registry+"/od/") || !strings.Contains(s.Image, "@sha256:") {
			add("app image must be an artifactd digest reference")
		}
	case "backing":
		ok := false
		for _, img := range TemplateImages {
			if s.Image == img {
				ok = true
			}
		}
		if !ok {
			add("backing image %q is not a pinned template", s.Image)
		}
	default:
		add("invalid kind")
	}
	if !allowedRuntimes[s.Runtime] {
		add("runtime %q unavailable on this node (fail closed)", s.Runtime)
	}
	for k := range s.Env {
		if !envNameRE.MatchString(k) || reservedEnv[strings.ToUpper(k)] {
			add("env %q not allowed", k)
		}
	}
	for k := range s.SecretFiles {
		if !secretRE.MatchString(k) {
			add("secret file name %q invalid", k)
		}
	}
	if s.Port < 0 || s.Port > 65535 {
		add("invalid port")
	}
	if s.MemoryBytes < 16<<20 {
		add("memory limit required (>=16Mi)")
	}
	if s.CPU <= 0 || s.CPU > 64 {
		add("cpu limit required")
	}
	if s.PIDs < 16 || s.PIDs > 32768 {
		add("pids limit required")
	}
	for _, t := range s.Tmpfs {
		if !validTarget(t) {
			add("tmpfs %q not allowed", t)
		}
	}
	seen := map[string]bool{}
	for _, v := range s.Volumes {
		if !ids.HasPrefix(v.VolumeID, "vol") {
			add("volume id %q invalid", v.VolumeID)
		}
		if !validTarget(v.Target) {
			add("volume target %q not allowed", v.Target)
		}
		if seen[v.Target] {
			add("duplicate mount target %q", v.Target)
		}
		seen[v.Target] = true
	}
	if !ids.HasPrefix(s.Network, "env") && s.Network != "" {
		add("invalid network")
	}
	for _, a := range s.Aliases {
		if !serviceRE.MatchString(a) {
			add("invalid alias %q", a)
		}
	}
	for _, c := range s.Capabilities {
		if !policy.KnownCapabilities[c] {
			add("unknown capability %q", c)
		}
	}
	if s.User != "" && !regexp.MustCompile(`^[0-9]{1,10}(:[0-9]{1,10})?$`).MatchString(s.User) {
		add("user must be numeric uid[:gid]")
	}
	for _, c := range s.Command {
		if len(c) > 8192 {
			add("command too long")
		}
	}
	if len(p) > 0 {
		sort.Strings(p)
		return fmt.Errorf("invalid workload spec: %s", strings.Join(p, "; "))
	}
	return nil
}

func validTarget(t string) bool {
	if !strings.HasPrefix(t, "/") || strings.Contains(t, "..") || len(t) > 256 {
		return false
	}
	c := path.Clean(t)
	if c == "/" {
		return false
	}
	for _, bad := range []string{"/proc", "/sys", "/dev", "/run/secrets", "/var/run/docker.sock", "/run/containerd", "/etc/hosts", "/etc/resolv.conf", "/etc/hostname"} {
		if c == bad || strings.HasPrefix(c, bad+"/") {
			return false
		}
	}
	return true
}

// Labels applied to every workload for ownership tracking.
func (s *Spec) Labels() map[string]string {
	return map[string]string{
		"org.opendeploy.managed":     "true",
		"org.opendeploy.workload":    s.ID,
		"org.opendeploy.project":     s.ProjectID,
		"org.opendeploy.environment": s.EnvironmentID,
		"org.opendeploy.deployment":  s.DeploymentID,
		"org.opendeploy.service":     s.Service,
		"org.opendeploy.kind":        s.Kind,
	}
}

// NetworkSpec describes an environment network.
type NetworkSpec struct {
	EnvironmentID string `json:"environment_id"`
	ProjectID     string `json:"project_id"`
	Kind          string `json:"kind"` // production | staging | preview
}

// NetworkInfo reports an environment network.
type NetworkInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Subnet  string `json:"subnet"`
	Gateway string `json:"gateway"`
	Bridge  string `json:"bridge"`
}

// NetworkName is the backend network name for an environment.
func NetworkName(envID string) string { return "od-" + strings.ReplaceAll(envID, "_", "-") }

// Capabilities reports what the runtime backend can enforce.
type Capabilities struct {
	Backend  string          `json:"backend"`
	Runtimes map[string]bool `json:"runtimes"`
	Devices  map[string]bool `json:"devices"`
	Version  string          `json:"version"`
}
