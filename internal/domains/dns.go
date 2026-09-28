package domains

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Verifier is the DNS surface the platform needs (fakeable in tests).
type Verifier interface {
	// TXT queries every authoritative server of name's zone directly.
	TXT(ctx context.Context, name string) (*TXTResult, error)
	// Resolve follows CNAMEs and returns A/AAAA addresses of host.
	Resolve(ctx context.Context, host string) (*Resolution, error)
}

// ServerAnswer is one authoritative server's response.
type ServerAnswer struct {
	Server        string   `json:"server"`
	Authoritative bool     `json:"authoritative"`
	Rcode         string   `json:"rcode,omitempty"`
	Records       []string `json:"records,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// TXTResult collects authoritative answers for one TXT name.
type TXTResult struct {
	Name    string         `json:"name"`
	Zone    string         `json:"zone"`
	Servers []ServerAnswer `json:"servers"`
}

// Proves reports whether the exact value is published by every responding
// authoritative server (at least one must respond authoritatively). A
// value served by a cache, a lame server or only some of the zone's
// servers is not proof.
func (r *TXTResult) Proves(value string) (bool, string) {
	return r.ProvesFunc(func(rec string) bool { return rec == value })
}

// ProvesFunc is Proves with a record matcher.
func (r *TXTResult) ProvesFunc(match func(string) bool) (bool, string) {
	auth, have := 0, 0
	for _, s := range r.Servers {
		if s.Error != "" || !s.Authoritative {
			continue
		}
		auth++
		for _, rec := range s.Records {
			if match(rec) {
				have++
				break
			}
		}
	}
	switch {
	case auth == 0:
		return false, "no authoritative name server answered for " + r.Zone
	case have == 0:
		return false, "the claim TXT record was not found on the authoritative name servers"
	case have < auth:
		return false, fmt.Sprintf("the claim TXT record is on %d of %d authoritative name servers (wait for propagation)", have, auth)
	}
	return true, fmt.Sprintf("claim TXT record found on %d authoritative name server(s) for %s", auth, r.Zone)
}

// Resolution is the address view of a hostname.
type Resolution struct {
	Host   string   `json:"host"`
	CNAMEs []string `json:"cnames,omitempty"`
	Addrs  []string `json:"addrs,omitempty"`
}

// Resolver implements Verifier with miekg/dns. Recursive resolvers are used
// only to locate the zone cut and its name server addresses; the proof
// itself is read from the authoritative servers with recursion disabled.
type Resolver struct {
	Recursive []string      // host:port
	Port      string        // authoritative server port (default 53)
	Timeout   time.Duration // per query (default 4s)
	// AllowPrivateNS permits authoritative servers on private addresses
	// (LAN deployments and tests); otherwise such NS records are ignored so
	// a hostile zone cannot aim queries at internal hosts.
	AllowPrivateNS bool
}

// NewResolver parses a comma-separated list of recursive resolvers.
func NewResolver(recursive string) *Resolver {
	var rs []string
	for _, s := range strings.Split(recursive, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		rs = append(rs, s)
	}
	return &Resolver{Recursive: rs}
}

func (r *Resolver) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return 4 * time.Second
}

func (r *Resolver) exchange(ctx context.Context, m *dns.Msg, server string) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp", Timeout: r.timeout(), UDPSize: 4096}
	m.SetEdns0(4096, false)
	in, _, err := c.ExchangeContext(ctx, m, server)
	if err == nil && in.Truncated {
		c.Net = "tcp"
		in, _, err = c.ExchangeContext(ctx, m, server)
	}
	if err == nil && in.Id != m.Id {
		return nil, errors.New("dns: id mismatch")
	}
	return in, err
}

func (r *Resolver) recursive(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	if len(r.Recursive) == 0 {
		return nil, errors.New("no DNS resolver configured")
	}
	var last error
	for _, srv := range r.Recursive {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qtype)
		m.RecursionDesired = true
		in, err := r.exchange(ctx, m, srv)
		if err != nil {
			last = err
			continue
		}
		if in.Rcode == dns.RcodeSuccess || in.Rcode == dns.RcodeNameError {
			return in, nil
		}
		last = fmt.Errorf("%s: %s", srv, dns.RcodeToString[in.Rcode])
	}
	return nil, last
}

// FindZone returns the closest enclosing zone apex of name (the deepest
// ancestor that has its own NS set). Top-level domains are never accepted.
func (r *Resolver) FindZone(ctx context.Context, name string) (string, error) {
	labels := dns.SplitDomainName(name)
	for i := 0; i < len(labels)-1; i++ {
		cand := dns.Fqdn(strings.Join(labels[i:], "."))
		in, err := r.recursive(ctx, cand, dns.TypeNS)
		if err != nil {
			return "", err
		}
		for _, rr := range in.Answer {
			if ns, ok := rr.(*dns.NS); ok && strings.EqualFold(ns.Hdr.Name, cand) {
				return cand, nil
			}
		}
	}
	return "", fmt.Errorf("no DNS zone found for %s", name)
}

func (r *Resolver) addrs(ctx context.Context, host string) ([]string, []string, error) {
	var out, cnames []string
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		in, err := r.recursive(ctx, host, qt)
		if err != nil {
			return nil, nil, err
		}
		for _, rr := range in.Answer {
			switch v := rr.(type) {
			case *dns.A:
				out = append(out, v.A.String())
			case *dns.AAAA:
				out = append(out, v.AAAA.String())
			case *dns.CNAME:
				if qt == dns.TypeA {
					cnames = append(cnames, strings.TrimSuffix(strings.ToLower(v.Target), "."))
				}
			}
		}
	}
	return dedupe(out), cnames, nil
}

func (r *Resolver) nameServers(ctx context.Context, zone string) ([]string, error) {
	in, err := r.recursive(ctx, zone, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	port := r.Port
	if port == "" {
		port = "53"
	}
	var servers []string
	for _, rr := range in.Answer {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		ips, _, err := r.addrs(ctx, ns.Ns)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if !r.AllowPrivateNS && !publicIP(net.ParseIP(ip)) {
				continue
			}
			servers = append(servers, net.JoinHostPort(ip, port))
		}
	}
	servers = dedupe(servers)
	if len(servers) > 12 {
		servers = servers[:12]
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no usable authoritative name servers for %s", zone)
	}
	return servers, nil
}

// TXT implements Verifier.
func (r *Resolver) TXT(ctx context.Context, name string) (*TXTResult, error) {
	zone, err := r.FindZone(ctx, name)
	if err != nil {
		return nil, err
	}
	servers, err := r.nameServers(ctx, zone)
	if err != nil {
		return nil, err
	}
	res := &TXTResult{Name: strings.TrimSuffix(dns.Fqdn(name), "."), Zone: strings.TrimSuffix(zone, ".")}
	for _, srv := range servers {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
		m.RecursionDesired = false
		sa := ServerAnswer{Server: srv}
		in, err := r.exchange(ctx, m, srv)
		if err != nil {
			sa.Error = err.Error()
			res.Servers = append(res.Servers, sa)
			continue
		}
		sa.Authoritative, sa.Rcode = in.Authoritative, dns.RcodeToString[in.Rcode]
		if in.Rcode != dns.RcodeSuccess && in.Rcode != dns.RcodeNameError {
			sa.Authoritative = false
		}
		for _, rr := range in.Answer {
			// CNAMEs at the challenge name are not followed: the proof must
			// live in the zone that serves the hostname.
			if t, ok := rr.(*dns.TXT); ok && strings.EqualFold(t.Hdr.Name, dns.Fqdn(name)) {
				sa.Records = append(sa.Records, strings.Join(t.Txt, ""))
			}
		}
		res.Servers = append(res.Servers, sa)
	}
	return res, nil
}

// Resolve implements Verifier.
func (r *Resolver) Resolve(ctx context.Context, host string) (*Resolution, error) {
	a, c, err := r.addrs(ctx, host)
	if err != nil {
		return nil, err
	}
	return &Resolution{Host: host, CNAMEs: c, Addrs: a}, nil
}

// Targets are where a hostname must point for the chosen ingress mode.
type Targets struct {
	IPs   []string `json:"ips,omitempty"`
	Hosts []string `json:"hosts,omitempty"` // e.g. the relay edge name (CNAME target)
}

// Empty reports whether nothing is known about the expected path.
func (t Targets) Empty() bool { return len(t.IPs) == 0 && len(t.Hosts) == 0 }

// RoutingCheck is the A/AAAA/CNAME path validation result.
type RoutingCheck struct {
	OK       bool     `json:"ok"`
	Detail   string   `json:"detail"`
	Found    []string `json:"found,omitempty"`
	CNAMEs   []string `json:"cnames,omitempty"`
	Expected []string `json:"expected,omitempty"`
}

// CheckRouting validates that every address of host belongs to the
// expected ingress (direct public IPs or the relay edge).
func CheckRouting(ctx context.Context, v Verifier, host string, t Targets) RoutingCheck {
	if t.Empty() {
		return RoutingCheck{Detail: "expected ingress address unknown (set ingress.public_ipv4/ipv6 or relay); routing not validated"}
	}
	expected := append([]string{}, t.IPs...)
	for _, h := range t.Hosts {
		if rs, err := v.Resolve(ctx, h); err == nil {
			expected = append(expected, rs.Addrs...)
		}
	}
	expected = dedupe(normIPs(expected))
	rc := RoutingCheck{Expected: expected}
	res, err := v.Resolve(ctx, host)
	if err != nil {
		rc.Detail = "resolving " + host + ": " + err.Error()
		return rc
	}
	rc.Found, rc.CNAMEs = normIPs(res.Addrs), res.CNAMEs
	if len(rc.Found) == 0 {
		rc.Detail = host + " has no A/AAAA records yet"
		return rc
	}
	var stray []string
	for _, a := range rc.Found {
		if !contains(expected, a) {
			stray = append(stray, a)
		}
	}
	if len(stray) > 0 {
		rc.Detail = fmt.Sprintf("%s resolves to %s, which is not this node's ingress (%s)", host, strings.Join(stray, ", "), strings.Join(expected, ", "))
		return rc
	}
	rc.OK, rc.Detail = true, host+" points at this node's ingress"
	return rc
}

func publicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil && (v4[0] == 100 && v4[1]&0xc0 == 64 || v4[0] == 0 || v4[0] >= 240) {
		return false // CGNAT, "this network", reserved
	}
	return true
}

func normIPs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, ip.String())
		}
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
