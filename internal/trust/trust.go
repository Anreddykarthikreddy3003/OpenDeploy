// Package trust implements the workload trust-class decision (PRD §3.2,
// SC-01, SC-02, SC-23, ADR-014).
//
// Every build and every workload start passes through Decide. The function is
// pure: given the administrator policy, the event that triggered the work,
// what the repository asked for, and what the host can actually enforce, it
// returns the isolation that MUST be applied or an error. It never silently
// downgrades isolation; if the required sandbox is missing it fails closed.
package trust

import (
	"errors"
	"fmt"
	"sort"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/policy"
)

type Class = policy.TrustClass

const (
	Trusted    = policy.TrustTrusted
	Untrusted  = policy.TrustUntrusted
	Privileged = policy.TrustPrivileged
)

// Runtime is the OCI runtime handler a workload is started with.
type Runtime string

const (
	RuntimeRunc  Runtime = "runc"
	RuntimeRunsc Runtime = "runsc" // gVisor
	RuntimeVM    Runtime = "vm"    // disposable VM/microVM (Kata/Firecracker)
)

// EnvKind is the environment a workload belongs to.
type EnvKind string

const (
	EnvProduction EnvKind = "production"
	EnvStaging    EnvKind = "staging"
	EnvPreview    EnvKind = "preview"
)

// HostCapabilities describes isolation actually enforceable on this node.
// It is measured by hostd/runtimed probes, never taken from configuration.
type HostCapabilities struct {
	GVisor                 bool
	VM                     bool
	RootlessBuild          bool
	NetworkPolicy          bool // netns + nftables enforcement available
	Devices                map[string]bool
	ProfileAllowsUntrusted bool // resource profile permits untrusted execution
}

// AdminPolicy is the administrator-controlled project policy. It is stored
// in the control-plane database and can only be changed through the
// authenticated admin API (privileged grants are MFA-gated).
type AdminPolicy struct {
	Class               Class
	GrantedCapabilities []string
	PreferGVisor        bool
	AllowPublicForks    bool
}

// Source describes what triggered the work.
type Source struct {
	Env           EnvKind
	FromFork      bool // PR head repository differs from base repository
	AuthorIsOwner bool // push by an installation-authorised repository owner
}

// Request is what the repository configuration asked for (untrusted input).
type Request struct {
	DeclaredClass Class
	Sandbox       policy.Sandbox
	Capabilities  []string
}

// Decision is the enforceable outcome.
type Decision struct {
	Class              Class
	BuildRuntime       Runtime
	Runtime            Runtime
	RootlessBuild      bool
	ProductionSecrets  bool
	SecretScope        EnvKind
	AllowPrivateEgress bool
	Capabilities       []string
	Reasons            []string
}

var (
	ErrSandboxUnavailable = errors.New("required untrusted-workload sandbox is unavailable on this host (fail closed)")
	ErrCapabilityDenied   = errors.New("capability not granted by administrator policy")
	ErrForksDisabled      = errors.New("public fork previews are disabled")
	ErrRejectedCombo      = errors.New("rejected capability/trust combination")
	ErrNoNetworkPolicy    = errors.New("network policy enforcement unavailable (fail closed)")
	ErrNoRootlessBuild    = errors.New("rootless build boundary unavailable (fail closed)")
)

func rank(c Class) int {
	switch c {
	case Trusted:
		return 0
	case Untrusted:
		return 1
	case Privileged:
		return 2
	}
	return 1
}

// Decide computes the isolation for a build or workload.
func Decide(admin AdminPolicy, src Source, req Request, host HostCapabilities) (*Decision, error) {
	d := &Decision{Class: admin.Class, SecretScope: src.Env}
	if d.Class == "" {
		d.Class = Trusted
	}
	note := func(f string, a ...any) { d.Reasons = append(d.Reasons, fmt.Sprintf(f, a...)) }

	// The repository may only make itself MORE restricted, never less.
	if req.DeclaredClass == Untrusted && d.Class == Trusted {
		d.Class = Untrusted
		note("repository declared itself untrusted")
	}
	if req.DeclaredClass == Privileged && d.Class != Privileged {
		return nil, fmt.Errorf("%w: repository requested privileged class", ErrCapabilityDenied)
	}

	// Fork code is always untrusted regardless of project policy.
	if src.FromFork {
		if !admin.AllowPublicForks {
			return nil, ErrForksDisabled
		}
		if d.Class == Privileged {
			return nil, fmt.Errorf("%w: fork code cannot run in a privileged project", ErrRejectedCombo)
		}
		d.Class = Untrusted
		note("fork pull request forces untrusted class")
	}

	if !host.NetworkPolicy {
		return nil, ErrNoNetworkPolicy
	}

	// Capability requests (SC-23): only admin grants count.
	granted := map[string]bool{}
	for _, c := range admin.GrantedCapabilities {
		granted[c] = true
	}
	for _, c := range req.Capabilities {
		if !policy.KnownCapabilities[c] {
			return nil, fmt.Errorf("%w: unknown capability %q", ErrCapabilityDenied, c)
		}
		if d.Class != Privileged || !granted[c] {
			return nil, fmt.Errorf("%w: %q", ErrCapabilityDenied, c)
		}
		if c != "host-network" && host.Devices != nil && !host.Devices[c] {
			return nil, fmt.Errorf("%w: host lacks %q", ErrCapabilityDenied, c)
		}
		d.Capabilities = append(d.Capabilities, c)
	}
	sort.Strings(d.Capabilities)
	if d.Class == Privileged && src.Env == EnvPreview {
		return nil, fmt.Errorf("%w: privileged workloads cannot run as previews", ErrRejectedCombo)
	}

	switch d.Class {
	case Untrusted:
		if !host.ProfileAllowsUntrusted {
			return nil, fmt.Errorf("%w: resource profile disables untrusted execution", ErrSandboxUnavailable)
		}
		switch {
		case req.Sandbox == policy.SandboxVM:
			if !host.VM {
				return nil, ErrSandboxUnavailable
			}
			d.Runtime = RuntimeVM
		case host.GVisor:
			d.Runtime = RuntimeRunsc
		case host.VM:
			d.Runtime = RuntimeVM
		default:
			return nil, ErrSandboxUnavailable
		}
		if req.Sandbox == policy.SandboxRunc {
			note("runc request ignored for untrusted class")
		}
		d.BuildRuntime = d.Runtime
		d.ProductionSecrets = false
		if src.Env == EnvProduction {
			// Untrusted production still never gets secrets broader than its own env,
			// but untrusted *builds* never receive secrets at all (§7.5).
			d.SecretScope = EnvProduction
		}
		d.AllowPrivateEgress = false
	case Trusted:
		switch req.Sandbox {
		case policy.SandboxGVisor:
			if !host.GVisor {
				return nil, fmt.Errorf("%w: gvisor explicitly requested", ErrSandboxUnavailable)
			}
			d.Runtime = RuntimeRunsc
		case policy.SandboxVM:
			if !host.VM {
				return nil, fmt.Errorf("%w: vm explicitly requested", ErrSandboxUnavailable)
			}
			d.Runtime = RuntimeVM
		default:
			d.Runtime = RuntimeRunc
			if admin.PreferGVisor && host.GVisor {
				d.Runtime = RuntimeRunsc
			}
		}
		if !host.RootlessBuild {
			return nil, ErrNoRootlessBuild
		}
		d.RootlessBuild = true
		d.BuildRuntime = RuntimeRunc
		d.ProductionSecrets = src.Env == EnvProduction
	case Privileged:
		d.Runtime = RuntimeRunc
		d.BuildRuntime = RuntimeRunc
		if !host.RootlessBuild {
			return nil, ErrNoRootlessBuild
		}
		d.RootlessBuild = true
		d.ProductionSecrets = src.Env == EnvProduction
		note("privileged class: expanded blast radius")
	default:
		return nil, fmt.Errorf("unknown trust class %q", d.Class)
	}

	if src.Env == EnvPreview {
		d.ProductionSecrets = false
		d.SecretScope = EnvPreview
	}
	return d, nil
}

// MoreRestrictive returns the more restrictive of two trust classes for the
// purposes of secrets and sandboxing (untrusted is the most restrictive for
// sandboxing; privileged is the broadest for capabilities).
func MoreRestrictive(a, b Class) Class {
	if a == Untrusted || b == Untrusted {
		return Untrusted
	}
	if rank(a) > rank(b) {
		return b
	}
	return a
}
