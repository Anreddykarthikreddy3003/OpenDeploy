package network

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/audit"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/identity"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/ipc"
)

// Service is egressd: it owns the nftables table and the egress proxy
// policy for every environment network.
type Service struct {
	NftBin       string
	StateFile    string
	BuildBridges []string
	BuildUIDs    []int
	ProxyPort    int
	DNS          []string
	BuildAllow   []string // node-level allowlist for restricted builds (empty = any public host)
	Audit        audit.Sink
	Log          *slog.Logger
	// ApplyFn replaces nft application in tests.
	ApplyFn func(ctx context.Context, script string) error

	mu        sync.Mutex
	envs      map[string]EnvPolicy
	enforcing bool
	lastErr   string
}

// Init loads persisted policies, probes nftables and applies the ruleset.
func (s *Service) Init(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.envs = map[string]EnvPolicy{}
	if b, err := os.ReadFile(s.StateFile); err == nil {
		var saved []EnvPolicy
		if json.Unmarshal(b, &saved) == nil {
			for _, p := range saved {
				s.envs[p.EnvironmentID] = p
			}
		}
	}
	if len(s.DNS) == 0 {
		s.DNS = ResolvConfServers("/etc/resolv.conf")
	}
	if s.ApplyFn == nil {
		if err := Probe(ctx, s.NftBin); err != nil {
			s.lastErr = "nftables unavailable: " + err.Error()
			return err
		}
	}
	return s.applyLocked(ctx)
}

// ResolvConfServers lists non-loopback nameservers from resolv.conf.
func ResolvConfServers(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) >= 2 && fs[0] == "nameserver" {
			if a, err := netip.ParseAddr(fs[1]); err == nil && !a.IsLoopback() {
				out = append(out, a.String())
			}
		}
	}
	return out
}

func (s *Service) ruleset() Ruleset {
	r := Ruleset{BuildBridges: s.BuildBridges, ProxyPort: s.ProxyPort, DNS: s.DNS, Gateways: map[string]string{}}
	for _, p := range s.envs {
		r.Envs = append(r.Envs, p)
		if p.Gateway != "" {
			r.Gateways[p.EnvironmentID] = p.Gateway
		}
	}
	return r
}

func (s *Service) applyLocked(ctx context.Context) error {
	script, err := s.ruleset().Render()
	if err == nil {
		script += renderOutput(s.BuildUIDs)
		if s.ApplyFn != nil {
			err = s.ApplyFn(ctx, script)
		} else {
			err = Apply(ctx, s.NftBin, script)
		}
	}
	if err != nil {
		s.enforcing, s.lastErr = false, err.Error()
		return err
	}
	s.enforcing, s.lastErr = true, ""
	if s.StateFile != "" {
		var saved []EnvPolicy
		for _, p := range s.envs {
			saved = append(saved, p)
		}
		b, _ := json.Marshal(saved)
		_ = os.MkdirAll(filepath.Dir(s.StateFile), 0o700)
		tmp := s.StateFile + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			_ = os.Rename(tmp, s.StateFile)
		}
	}
	return nil
}

// renderOutput adds an OUTPUT chain so rootless BuildKit (whose egress
// leaves from the host network stack as the build user) cannot reach
// private, loopback or metadata addresses.
func renderOutput(uids []int) string {
	if len(uids) == 0 {
		return ""
	}
	var ids []string
	for _, u := range uids {
		ids = append(ids, fmt.Sprint(u))
	}
	return fmt.Sprintf(`table inet %s {
  chain output {
    type filter hook output priority filter - 10; policy accept;
    meta skuid { %s } oifname "lo" drop comment "build->loopback"
    meta skuid { %s } ip daddr @blocked4 drop comment "build->private"
    meta skuid { %s } ip6 daddr @blocked6 drop
  }
}
`, TableName, strings.Join(ids, ", "), strings.Join(ids, ", "), strings.Join(ids, ", "))
}

// Apply installs or updates one environment's policy.
func (s *Service) Apply(ctx context.Context, p EnvPolicy) error {
	if err := p.Validate(); err != nil {
		return ipc.Errorf(ipc.CodeBadRequest, "%v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.envs[p.EnvironmentID]
	s.envs[p.EnvironmentID] = p
	if err := s.applyLocked(ctx); err != nil {
		if had {
			s.envs[p.EnvironmentID] = prev
		} else {
			delete(s.envs, p.EnvironmentID)
		}
		return ipc.Errorf(ipc.CodeUnavailable, "apply network policy: %v", err)
	}
	if s.Audit != nil {
		_, _ = s.Audit.Append(ctx, audit.Event{ActorType: audit.ActorService, ActorID: identity.Egress, Action: "network.policy_apply",
			ResourceType: "environment", ResourceID: p.EnvironmentID, ProjectID: p.ProjectID, Result: audit.Success,
			Details: map[string]string{"policy": fmt.Sprintf("internet=%v private=%v hosts=%d", p.Internet, p.AllowPrivate, len(p.AllowHosts))}})
	}
	return nil
}

// Remove drops an environment's policy.
func (s *Service) Remove(ctx context.Context, envID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.envs[envID]; !ok {
		return nil
	}
	delete(s.envs, envID)
	return s.applyLocked(ctx)
}

// Status reports enforcement state.
func (s *Service) Status(context.Context) (*Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &Status{Enforcing: s.enforcing, Backend: "nftables", Message: s.lastErr, Envs: len(s.envs)}, nil
}

// ProxyPolicy maps a source address to its environment's allowlist.
func (s *Service) ProxyPolicy(src netip.Addr) ([]string, bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.envs {
		pr, err := netip.ParsePrefix(p.Subnet)
		if err == nil && pr.Contains(src) {
			if p.Internet {
				return nil, true, true
			}
			return p.AllowHosts, false, len(p.AllowHosts) > 0
		}
	}
	// Builds and other local clients: node allowlist or any public host.
	if src.IsLoopback() || src.IsPrivate() {
		return s.BuildAllow, len(s.BuildAllow) == 0, true
	}
	return nil, false, false
}

// Register exposes egressd over IPC (platformd only).
func Register(srv *ipc.Server, s *Service) {
	p := []string{identity.Platform}
	ipc.Handle(srv, OpApply, p, func(ctx context.Context, _ ipc.Caller, e EnvPolicy) (Empty, error) { return Empty{}, s.Apply(ctx, e) })
	ipc.Handle(srv, OpRemove, p, func(ctx context.Context, _ ipc.Caller, r RemoveReq) (Empty, error) {
		return Empty{}, s.Remove(ctx, r.EnvironmentID)
	})
	ipc.Handle(srv, OpStatus, []string{identity.Platform, identity.Host}, func(ctx context.Context, _ ipc.Caller, _ Empty) (*Status, error) {
		return s.Status(ctx)
	})
}
