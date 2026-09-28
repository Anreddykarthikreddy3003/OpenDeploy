package hostd

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/hostops"
)

// firewallRules renders a dedicated nftables table that protects
// OpenDeploy's internal listeners from the network without touching the
// host's own firewall policy (SSH and other services are unaffected):
// the admin API (unless remote admin is enabled), the artifact registry and
// the edge verification listener only accept loopback; in LAN-only mode the
// public edge ports accept private source addresses only.
func (h *Host) firewallRules(r hostops.FirewallReq) string {
	var internal []int
	for _, a := range []string{h.Node.API.Listen, h.Node.Artifact.RegistryListen, "127.0.0.1:18080"} {
		if _, p, err := net.SplitHostPort(a); err == nil {
			if n, _ := strconv.Atoi(p); n > 0 && n != r.AdminPort {
				internal = append(internal, n)
			}
		}
	}
	ports := make([]string, len(internal))
	for i, p := range internal {
		ports[i] = strconv.Itoa(p)
	}
	var b strings.Builder
	b.WriteString("table inet opendeploy_host\ndelete table inet opendeploy_host\n")
	b.WriteString("table inet opendeploy_host {\n")
	b.WriteString("  chain input {\n    type filter hook input priority -5; policy accept;\n")
	b.WriteString("    iifname \"lo\" accept\n")
	if len(ports) > 0 {
		fmt.Fprintf(&b, "    tcp dport { %s } drop comment \"opendeploy internal listeners are loopback-only\"\n", strings.Join(ports, ", "))
	}
	if r.LANOnly {
		fmt.Fprintf(&b, "    tcp dport { %d, %d } ip saddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 } drop comment \"LAN-only edge\"\n", r.HTTPPort, r.HTTPSPort)
		fmt.Fprintf(&b, "    tcp dport { %d, %d } ip6 saddr != { fc00::/7, fe80::/10 } drop comment \"LAN-only edge\"\n", r.HTTPPort, r.HTTPSPort)
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

// ApplyFirewall loads the rules atomically.
func (h *Host) ApplyFirewall(ctx context.Context, r hostops.FirewallReq) error {
	rules := h.firewallRules(r)
	c, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, "nft", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
