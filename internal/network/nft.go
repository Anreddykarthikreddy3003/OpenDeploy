package network

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
)

// Blocked destination ranges for workloads and builds by default (PRD §7.5,
// §9.1): loopback, RFC1918, CGNAT, link-local (incl. cloud metadata),
// multicast, reserved and documentation ranges.
var BlockedV4 = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4",
}

var BlockedV6 = []string{"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32"}

// TableName is the dedicated nftables table. It only ever drops traffic, so
// it composes with the container engine's own rules.
const TableName = "opendeploy"

// Ruleset is the full desired state rendered to nft syntax.
type Ruleset struct {
	Envs         []EnvPolicy
	BuildBridges []string // bridges used by build containers (e.g. docker0)
	ProxyPort    int      // egress proxy port on each bridge gateway (0 = none)
	Gateways     map[string]string
	// DNS lists resolver addresses workloads/builds may query on port 53 even
	// when they are private (home routers, VPC resolvers).
	DNS []string
}

// Render produces an atomic nft script that replaces the opendeploy table.
func (r Ruleset) Render() (string, error) {
	envs := append([]EnvPolicy(nil), r.Envs...)
	sort.Slice(envs, func(i, j int) bool { return envs[i].Bridge < envs[j].Bridge })
	var b strings.Builder
	// Declaring then deleting guarantees an atomic replace even if absent.
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\n", TableName, TableName)
	fmt.Fprintf(&b, "table inet %s {\n", TableName)
	bridges := []string{}
	for _, e := range envs {
		if err := e.Validate(); err != nil {
			return "", fmt.Errorf("env %s: %w", e.EnvironmentID, err)
		}
		bridges = append(bridges, quote(e.Bridge))
	}
	for _, br := range r.BuildBridges {
		if !bridgeRE.MatchString(br) {
			return "", fmt.Errorf("invalid build bridge %q", br)
		}
	}
	fmt.Fprintf(&b, "  set workload_bridges { type ifname; %s}\n", elems(bridges))
	builds := []string{}
	for _, br := range r.BuildBridges {
		builds = append(builds, quote(br))
	}
	fmt.Fprintf(&b, "  set build_bridges { type ifname; %s}\n", elems(builds))
	fmt.Fprintf(&b, "  set blocked4 { type ipv4_addr; flags interval; auto-merge; elements = { %s } }\n", strings.Join(BlockedV4, ", "))
	fmt.Fprintf(&b, "  set blocked6 { type ipv6_addr; flags interval; auto-merge; elements = { %s } }\n", strings.Join(BlockedV6, ", "))

	// FORWARD: traffic routed through the host between interfaces.
	b.WriteString("  chain forward {\n    type filter hook forward priority filter - 10; policy accept;\n")
	b.WriteString("    ct state established,related accept\n")
	b.WriteString("    ct state invalid drop\n")
	var dns4, dns6 []string
	for _, d := range r.DNS {
		a, err := netip.ParseAddr(d)
		if err != nil {
			return "", fmt.Errorf("invalid dns server %q", d)
		}
		if a.Is4() {
			dns4 = append(dns4, a.String())
		} else {
			dns6 = append(dns6, a.String())
		}
	}
	allowDNS := func(br string) {
		if len(dns4) > 0 {
			fmt.Fprintf(&b, "    iifname %s ip daddr { %s } meta l4proto { tcp, udp } th dport 53 accept\n", br, strings.Join(dns4, ", "))
		}
		if len(dns6) > 0 {
			fmt.Fprintf(&b, "    iifname %s ip6 daddr { %s } meta l4proto { tcp, udp } th dport 53 accept\n", br, strings.Join(dns6, ", "))
		}
	}
	for _, e := range envs {
		br := quote(e.Bridge)
		// Intra-environment traffic (br_netfilter makes bridged frames visible
		// here) is permitted before any private-range drop.
		fmt.Fprintf(&b, "    iifname %s oifname %s accept comment \"intra-env %s\"\n", br, br, e.EnvironmentID)
		// Cross-environment / cross-project traffic is always denied (SC-05).
		fmt.Fprintf(&b, "    iifname %s oifname @workload_bridges oifname != %s drop comment \"cross-env %s\"\n", br, br, e.EnvironmentID)
		fmt.Fprintf(&b, "    iifname %s oifname @build_bridges drop\n", br)
		if e.Internet {
			allowDNS(br)
		}
		if !e.AllowPrivate {
			fmt.Fprintf(&b, "    iifname %s ip daddr @blocked4 drop comment \"private/metadata egress %s\"\n", br, e.EnvironmentID)
			fmt.Fprintf(&b, "    iifname %s ip6 daddr @blocked6 drop\n", br)
		} else {
			// Even with private access, cloud metadata and loopback stay blocked.
			fmt.Fprintf(&b, "    iifname %s ip daddr { 169.254.0.0/16, 127.0.0.0/8, 0.0.0.0/8 } drop\n", br)
		}
		if !e.Internet {
			fmt.Fprintf(&b, "    iifname %s oifname != %s drop comment \"no internet %s\"\n", br, br, e.EnvironmentID)
		}
	}
	for _, br := range builds {
		allowDNS(br)
		fmt.Fprintf(&b, "    iifname %s ip daddr @blocked4 drop comment \"build egress\"\n", br)
		fmt.Fprintf(&b, "    iifname %s ip6 daddr @blocked6 drop\n", br)
		fmt.Fprintf(&b, "    iifname %s oifname @workload_bridges drop\n", br)
	}
	b.WriteString("  }\n")

	// INPUT: traffic addressed to the host itself. Workloads and builds may
	// not open connections to host services (platform API, registry, Caddy
	// admin, SSH, databases on the host...). Replies to host-initiated
	// connections (Caddy proxying, health checks) are allowed.
	b.WriteString("  chain input {\n    type filter hook input priority filter - 10; policy accept;\n")
	b.WriteString("    ct state established,related accept\n")
	if r.ProxyPort > 0 {
		for _, e := range envs {
			if gw, ok := r.Gateways[e.EnvironmentID]; ok && !e.Internet && len(e.AllowHosts) > 0 {
				if _, err := netip.ParseAddr(gw); err == nil {
					fmt.Fprintf(&b, "    iifname %s ip daddr %s tcp dport %d accept comment \"egress proxy %s\"\n", quote(e.Bridge), gw, r.ProxyPort, e.EnvironmentID)
				}
			}
		}
	}
	if r.ProxyPort > 0 {
		fmt.Fprintf(&b, "    iifname @build_bridges tcp dport %d accept comment \"build egress proxy\"\n", r.ProxyPort)
		fmt.Fprintf(&b, "    tcp dport %d iifname != \"lo\" iifname != @workload_bridges iifname != @build_bridges drop comment \"proxy not exposed\"\n", r.ProxyPort)
	}
	b.WriteString("    iifname @workload_bridges drop comment \"workload->host\"\n")
	b.WriteString("    iifname @build_bridges drop comment \"build->host\"\n")
	b.WriteString("  }\n}\n")
	return b.String(), nil
}

func quote(s string) string { return "\"" + s + "\"" }

func elems(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return "elements = { " + strings.Join(xs, ", ") + " }; "
}

// Apply loads the ruleset atomically with `nft -f -`.
func Apply(ctx context.Context, nftBin, script string) error {
	if nftBin == "" {
		nftBin = "nft"
	}
	cmd := exec.CommandContext(ctx, nftBin, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}

// Flush removes the opendeploy table (uninstall).
func Flush(ctx context.Context, nftBin string) error {
	return Apply(ctx, nftBin, fmt.Sprintf("table inet %s\ndelete table inet %s\n", TableName, TableName))
}

// Probe reports whether nftables can be programmed on this host.
func Probe(ctx context.Context, nftBin string) error {
	script := "table inet odprobe\ndelete table inet odprobe\ntable inet odprobe {\n  chain c {\n    type filter hook forward priority 0; policy accept;\n  }\n}\ndelete table inet odprobe\n"
	return Apply(ctx, nftBin, script)
}
