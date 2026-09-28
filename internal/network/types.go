// Package network implements egressd: per-environment network segmentation
// and outbound policy (PRD §9, SC-05, SC-12). This file holds the shared
// request types; enforcement lives in nft.go / service.go.
package network

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
)

// EnvPolicy is the outbound/inbound policy for one environment network.
type EnvPolicy struct {
	EnvironmentID string   `json:"environment_id"`
	ProjectID     string   `json:"project_id"`
	Kind          string   `json:"kind"` // production | staging | preview
	Bridge        string   `json:"bridge"`
	Subnet        string   `json:"subnet"`
	Internet      bool     `json:"internet"`
	AllowPrivate  bool     `json:"allow_private"` // explicit administrator opt-in (never for previews)
	AllowHosts    []string `json:"allow_hosts,omitempty"`
}

var bridgeRE = regexp.MustCompile(`^[a-z0-9]{1,15}$`)

// Validate checks the policy.
func (p *EnvPolicy) Validate() error {
	if !ids.HasPrefix(p.EnvironmentID, "env") || !ids.HasPrefix(p.ProjectID, "prj") {
		return fmt.Errorf("invalid ids")
	}
	if !bridgeRE.MatchString(p.Bridge) {
		return fmt.Errorf("invalid bridge name %q", p.Bridge)
	}
	if _, err := netip.ParsePrefix(p.Subnet); err != nil {
		return fmt.Errorf("invalid subnet %q", p.Subnet)
	}
	if p.Kind == "preview" && p.AllowPrivate {
		return fmt.Errorf("previews may not reach private networks")
	}
	return nil
}

// Status reports whether enforcement is active.
type Status struct {
	Enforcing bool   `json:"enforcing"`
	Backend   string `json:"backend"`
	Message   string `json:"message,omitempty"`
	Envs      int    `json:"environments"`
}

// Enforcer is implemented by egressd (and fakes in tests).
type Enforcer interface {
	Apply(ctx context.Context, p EnvPolicy) error
	Remove(ctx context.Context, envID string) error
	Status(ctx context.Context) (*Status, error)
}

// Nop is an Enforcer that enforces nothing and says so; it exists only for
// insecure development mode (trust decisions fail closed against it).
type Nop struct{}

func (Nop) Apply(context.Context, EnvPolicy) error { return nil }
func (Nop) Remove(context.Context, string) error   { return nil }
func (Nop) Status(context.Context) (*Status, error) {
	return &Status{Enforcing: false, Backend: "none", Message: "network policy enforcement disabled"}, nil
}
