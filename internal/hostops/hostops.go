// Package hostops defines the complete, closed set of privileged host
// operations exposed by opendeploy-hostd (PRD §4.1, §15.2, SC-10, Q25).
//
// There is deliberately no operation that accepts a command, script, path or
// free-form argument list. Every parameter is an enum or a strictly
// validated identifier, so a compromised platformd can only ask hostd to do
// the specific things listed here.
package hostops

import (
	"fmt"
	"regexp"
)

// Operation names.
const (
	OpInfo            = "host.info"
	OpServiceRestart  = "host.service.restart"
	OpServiceStatus   = "host.service.status"
	OpFirewallApply   = "host.firewall.apply"
	OpUpdateStage     = "host.update.stage"
	OpUpdateCommit    = "host.update.commit"
	OpUpdateRollback  = "host.update.rollback"
	OpSupportBundle   = "host.support_bundle"
	OpDataPlaneStart  = "host.dataplane.start"
	OpDataPlaneStop   = "host.dataplane.stop"
	OpDataPlaneStatus = "host.dataplane.status"
)

// AllOps is the closed operation inventory; tests assert the hostd server
// registers exactly this set.
var AllOps = []string{OpInfo, OpServiceRestart, OpServiceStatus, OpFirewallApply, OpUpdateStage, OpUpdateCommit,
	OpUpdateRollback, OpSupportBundle, OpDataPlaneStart, OpDataPlaneStop, OpDataPlaneStatus}

// Units are the only systemd units hostd will act on.
var Units = map[string]string{
	"platformd": "opendeploy-platformd.service",
	"builderd":  "opendeploy-builderd.service",
	"artifactd": "opendeploy-artifactd.service",
	"runtimed":  "opendeploy-runtimed.service",
	"secretd":   "opendeploy-secretd.service",
	"routemgr":  "opendeploy-routemgr.service",
	"egressd":   "opendeploy-egressd.service",
	"auditd":    "opendeploy-auditd.service",
	"relay":     "opendeploy-relay-agent.service",
	"caddy":     "opendeploy-caddy.service",
	"buildkit":  "opendeploy-buildkitd.service",
}

type ServiceReq struct {
	Service string `json:"service"`
}

func (r ServiceReq) Validate() error {
	if _, ok := Units[r.Service]; !ok {
		return fmt.Errorf("service %q is not managed by hostd", r.Service)
	}
	return nil
}

type ServiceStatus struct {
	Service string `json:"service"`
	Active  string `json:"active"`
	Sub     string `json:"sub"`
}

// FirewallReq asks hostd to (re)apply the host edge policy: only the
// listed public ports are opened to the edge (Caddy/relay), everything else
// inbound is dropped (SC-12).
type FirewallReq struct {
	HTTPPort  int  `json:"http_port"`
	HTTPSPort int  `json:"https_port"`
	AdminPort int  `json:"admin_port"` // 0 unless remote admin enabled
	LANOnly   bool `json:"lan_only"`
}

func (r FirewallReq) Validate() error {
	for _, p := range []int{r.HTTPPort, r.HTTPSPort} {
		if p < 1 || p > 65535 {
			return fmt.Errorf("invalid port %d", p)
		}
	}
	if r.AdminPort < 0 || r.AdminPort > 65535 {
		return fmt.Errorf("invalid admin port %d", r.AdminPort)
	}
	return nil
}

var versionRE = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)
var digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// UpdateStageReq installs a verified release into the inactive slot. The
// release must already have been verified by the TUF client in platformd and
// is re-verified by hostd from its own trusted root before staging.
type UpdateStageReq struct {
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

func (r UpdateStageReq) Validate() error {
	if !versionRE.MatchString(r.Version) {
		return fmt.Errorf("invalid version %q", r.Version)
	}
	if !digestRE.MatchString(r.Digest) {
		return fmt.Errorf("invalid digest")
	}
	return nil
}

type UpdateCommitReq struct {
	Version string `json:"version"`
}

func (r UpdateCommitReq) Validate() error {
	if !versionRE.MatchString(r.Version) {
		return fmt.Errorf("invalid version %q", r.Version)
	}
	return nil
}

type Empty struct{}

// Info reports host capabilities measured by hostd probes.
type Info struct {
	OS             string            `json:"os"`
	Arch           string            `json:"arch"`
	Kernel         string            `json:"kernel"`
	Hostname       string            `json:"hostname"`
	CgroupV2       bool              `json:"cgroup_v2"`
	UserNamespaces bool              `json:"user_namespaces"`
	Nftables       bool              `json:"nftables"`
	GVisor         bool              `json:"gvisor"`
	KVM            bool              `json:"kvm"`
	Devices        map[string]bool   `json:"devices"`
	CPUs           int               `json:"cpus"`
	MemoryBytes    uint64            `json:"memory_bytes"`
	DiskFreeBytes  uint64            `json:"disk_free_bytes"`
	ActiveSlot     string            `json:"active_slot"`
	Version        string            `json:"version"`
	DataPlane      string            `json:"data_plane"` // native | wsl2 | vz
	Warnings       []string          `json:"warnings"`
	Extra          map[string]string `json:"extra,omitempty"`
}

type SupportBundle struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type DataPlaneStatus struct {
	State   string `json:"state"` // running | stopped | starting | error
	Message string `json:"message"`
}
