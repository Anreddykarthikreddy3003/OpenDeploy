package platform

import (
	"context"
	"fmt"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/policy"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/store"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/trust"
)

// HostCaps is the measured isolation capability of this node.
type HostCaps struct {
	Runtime       string          `json:"runtime_backend"`
	Runtimes      map[string]bool `json:"runtimes"`
	Devices       map[string]bool `json:"devices"`
	NetworkPolicy bool            `json:"network_policy"`
	NetworkNote   string          `json:"network_note,omitempty"`
	RootlessBuild bool            `json:"rootless_build"`
	Profile       string          `json:"profile"`
	Measured      time.Time       `json:"measured"`
}

// HostCapabilities measures (and caches for 30s) what this node enforces.
func (p *Platform) HostCapabilities(ctx context.Context) (*HostCaps, error) {
	p.capMu.Lock()
	defer p.capMu.Unlock()
	if p.caps != nil && time.Since(p.capsAt) < 30*time.Second {
		return p.caps, nil
	}
	rc, err := p.Runtime.Capabilities(ctx)
	if err != nil {
		return nil, fmt.Errorf("runtime capabilities: %w", err)
	}
	c := &HostCaps{Runtime: rc.Backend, Runtimes: rc.Runtimes, Devices: rc.Devices, Profile: p.Node.Profile, Measured: time.Now(),
		// The builder boundary is rootless BuildKit in production packaging;
		// the Docker backend's embedded BuildKit is the documented dev/CI
		// adapter and is treated as the trusted build path.
		RootlessBuild: true}
	st, err := p.Egress.Status(ctx)
	if err == nil && st.Enforcing {
		c.NetworkPolicy = true
	} else if p.InsecureNoNetworkPolicy && p.Node.DevMode {
		c.NetworkPolicy = true
		c.NetworkNote = "INSECURE: network policy not enforced (dev mode)"
	} else if err != nil {
		c.NetworkNote = err.Error()
	} else {
		c.NetworkNote = st.Message
	}
	p.caps, p.capsAt = c, time.Now()
	return c, nil
}

// decide runs the trust decision for a deployment.
func (p *Platform) decide(ctx context.Context, proj *store.Project, env *store.Environment, cfg *policy.Config) (*trust.Decision, error) {
	hc, err := p.HostCapabilities(ctx)
	if err != nil {
		return nil, err
	}
	host := trust.HostCapabilities{
		GVisor:                 hc.Runtimes["runsc"],
		VM:                     hc.Runtimes["vm"],
		RootlessBuild:          hc.RootlessBuild,
		NetworkPolicy:          hc.NetworkPolicy,
		Devices:                hc.Devices,
		ProfileAllowsUntrusted: p.Node.Profile != "tiny" || hc.Runtimes["runsc"],
	}
	admin := trust.AdminPolicy{Class: policy.TrustClass(proj.TrustClass), GrantedCapabilities: proj.GrantedCapabilities,
		PreferGVisor: proj.PreferGVisor, AllowPublicForks: proj.AllowPublicForks}
	src := trust.Source{Env: trust.EnvKind(env.Kind), FromFork: env.PRFromFork}
	req := trust.Request{}
	if cfg != nil {
		req.DeclaredClass = cfg.Source.Trust
		req.Sandbox = cfg.Runtime.Sandbox
		req.Capabilities = cfg.Runtime.Capabilities
	}
	d, err := trust.Decide(admin, src, req, host)
	if err != nil {
		if !hc.NetworkPolicy && hc.NetworkNote != "" {
			return nil, fmt.Errorf("%w (%s)", err, hc.NetworkNote)
		}
		return nil, err
	}
	return d, nil
}
