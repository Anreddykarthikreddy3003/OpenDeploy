// Package identity names the Tier-0 service identities (PRD §4.1, SC-10).
// Each identity runs as its own Unix user in production; IPC servers map the
// kernel-reported peer UID to one of these names.
package identity

const (
	Host       = "hostd"
	Platform   = "platformd"
	Builder    = "builderd"
	Artifact   = "artifactd"
	Runtime    = "runtimed"
	Secret     = "secretd"
	Router     = "routemgr"
	Egress     = "egressd"
	Audit      = "auditd"
	RelayAgent = "relay-agent"
)

// All lists every service identity.
var All = []string{Host, Platform, Builder, Artifact, Runtime, Secret, Router, Egress, Audit, RelayAgent}

// ControlPlane are identities permitted to emit security audit events.
var ControlPlane = []string{Host, Platform, Builder, Artifact, Runtime, Secret, Router, Egress, RelayAgent}

// UnixUser returns the system account name for an identity.
func UnixUser(id string) string { return "od-" + id }
