package github

import (
	"net/netip"
	"net/url"
	"strings"
)

// cgnat is the shared address space of RFC 6598 (carrier-grade NAT).
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// PubliclyReachable reports whether GitHub could plausibly deliver webhooks
// to publicURL, judged from the URL alone (no DNS lookup, no probe).
//
// It is false when the host is an IP literal that is loopback, private
// (RFC 1918, fc00::/7), link-local, unspecified, multicast or in CGNAT
// 100.64.0.0/10; when the host is "localhost" or ends in ".localhost",
// ".local" or ".internal"; when the host is a single label ("myhost"); and
// when the URL does not parse or has no host. Anything else (a public IP or
// a multi-label DNS name, such as a relay hostname) counts as reachable.
//
// GitHub refuses an App manifest whose hook URL it cannot reach, so the
// manifest leaves the webhook out when this is false (F-8).
func PubliclyReachable(publicURL string) bool {
	u, err := url.Parse(strings.TrimSpace(publicURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || cgnat.Contains(ip))
	}
	if host == "localhost" || !strings.Contains(host, ".") {
		return false
	}
	for _, suffix := range []string{".localhost", ".local", ".internal"} {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	return true
}
