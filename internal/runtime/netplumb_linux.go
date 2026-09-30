//go:build linux

package runtime

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// netPlumber implements per-environment bridges and per-workload network
// namespaces for the containerd backend: veth pairs, a file-backed IPAM
// (stable addresses per workload), NAT for egress, and generated
// resolv.conf/hosts files. egressd applies the security policy on top.
type netPlumber struct {
	mu    sync.Mutex
	dir   string
	pool  netip.Prefix // e.g. 10.210.0.0/16, one /24 per environment
	state ipamState
}

type ipamState struct {
	Envs map[string]*envNet `json:"envs"`
}

type envNet struct {
	Subnet  string            `json:"subnet"`
	Gateway string            `json:"gateway"`
	Bridge  string            `json:"bridge"`
	IPs     map[string]string `json:"ips"`   // workload id -> ip
	Names   map[string]string `json:"names"` // workload id -> service alias
}

func newNetPlumber(dir string) (*netPlumber, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := &netPlumber{dir: dir, pool: netip.MustParsePrefix("10.210.0.0/16"), state: ipamState{Envs: map[string]*envNet{}}}
	if b, err := os.ReadFile(filepath.Join(dir, "ipam.json")); err == nil {
		_ = json.Unmarshal(b, &p.state)
		if p.state.Envs == nil {
			p.state.Envs = map[string]*envNet{}
		}
	}
	return p, nil
}

func (p *netPlumber) save() error {
	b, _ := json.MarshalIndent(p.state, "", " ")
	tmp := filepath.Join(p.dir, "ipam.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(p.dir, "ipam.json"))
}

func (p *netPlumber) allocSubnet() (netip.Prefix, error) {
	used := map[string]bool{}
	for _, e := range p.state.Envs {
		used[e.Subnet] = true
	}
	base := p.pool.Addr().As4()
	for i := 1; i < 255; i++ {
		pr := netip.PrefixFrom(netip.AddrFrom4([4]byte{base[0], base[1], byte(i), 0}), 24)
		if !used[pr.String()] {
			return pr, nil
		}
	}
	return netip.Prefix{}, errors.New("ipam: environment subnet pool exhausted")
}

// ensureEnv creates the environment bridge (idempotent).
func (p *netPlumber) ensureEnv(envID string) (*envNet, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.state.Envs[envID]
	if !ok {
		pr, err := p.allocSubnet()
		if err != nil {
			return nil, err
		}
		gw := pr.Addr().Next()
		e = &envNet{Subnet: pr.String(), Gateway: gw.String(), Bridge: bridgeName(envID), IPs: map[string]string{}, Names: map[string]string{}}
		p.state.Envs[envID] = e
		if err := p.save(); err != nil {
			return nil, err
		}
	}
	if err := ensureBridge(e.Bridge, e.Gateway, e.Subnet); err != nil {
		return nil, err
	}
	if err := ensureNAT(p.pool.String()); err != nil {
		return nil, err
	}
	return e, nil
}

func ensureBridge(name, gw, subnet string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		la := netlink.NewLinkAttrs()
		la.Name = name
		br := &netlink.Bridge{LinkAttrs: la}
		if err := netlink.LinkAdd(br); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create bridge %s: %w", name, err)
		}
		if link, err = netlink.LinkByName(name); err != nil {
			return err
		}
	}
	pr := netip.MustParsePrefix(subnet)
	addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/%d", gw, pr.Bits()))
	addrs, _ := netlink.AddrList(link, netlink.FAMILY_V4)
	have := false
	for _, a := range addrs {
		if a.IP.Equal(addr.IP) {
			have = true
		}
	}
	if !have {
		if err := netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("address bridge: %w", err)
		}
	}
	return netlink.LinkSetUp(link)
}

var natOnce sync.Once
var natErr error

// ensureNAT enables forwarding and masquerades the workload pool.
func ensureNAT(pool string) error {
	natOnce.Do(func() {
		_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644)
		script := fmt.Sprintf(`table ip opendeploy_nat
delete table ip opendeploy_nat
table ip opendeploy_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr %s oifname != "od*" masquerade
  }
}
`, pool)
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			natErr = fmt.Errorf("nat: %v: %s", err, out)
			return
		}
		// Hosts that also run Docker set the FORWARD policy to DROP; let
		// OpenDeploy bridges through (egressd's own table still filters).
		if exec.Command("iptables", "-L", "DOCKER-USER", "-n").Run() == nil {
			for _, args := range [][]string{{"-i", "od+"}, {"-o", "od+"}} {
				check := append([]string{"-C", "DOCKER-USER"}, append(args, "-j", "ACCEPT")...)
				if exec.Command("iptables", check...).Run() != nil {
					ins := append([]string{"-I", "DOCKER-USER"}, append(args, "-j", "ACCEPT")...)
					_ = exec.Command("iptables", ins...).Run()
				}
			}
		}
	})
	return natErr
}

func (p *netPlumber) removeEnv(envID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.state.Envs[envID]
	if !ok {
		return nil
	}
	if len(e.IPs) > 0 {
		return fmt.Errorf("environment network still has %d workloads", len(e.IPs))
	}
	if link, err := netlink.LinkByName(e.Bridge); err == nil {
		_ = netlink.LinkDel(link)
	}
	delete(p.state.Envs, envID)
	return p.save()
}

func (p *netPlumber) allocIP(envID, wid, alias string) (net.IP, *envNet, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.state.Envs[envID]
	if !ok {
		return nil, nil, fmt.Errorf("environment network %s missing", envID)
	}
	if ip, ok := e.IPs[wid]; ok {
		return net.ParseIP(ip), e, nil
	}
	used := map[string]bool{e.Gateway: true}
	for _, ip := range e.IPs {
		used[ip] = true
	}
	pr := netip.MustParsePrefix(e.Subnet)
	for a := pr.Addr().Next().Next(); pr.Contains(a); a = a.Next() {
		if a.As4()[3] == 255 {
			break
		}
		if !used[a.String()] {
			e.IPs[wid] = a.String()
			e.Names[wid] = alias
			return net.ParseIP(a.String()), e, p.save()
		}
	}
	return nil, nil, errors.New("ipam: environment subnet exhausted")
}

func (p *netPlumber) releaseIP(envID, wid string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.state.Envs[envID]; ok {
		delete(e.IPs, wid)
		delete(e.Names, wid)
		_ = p.save()
	}
}

func (p *netPlumber) lookup(envID, wid string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.state.Envs[envID]; ok {
		return e.IPs[wid]
	}
	return ""
}

func nsName(wid string) string { return "od-" + strings.TrimPrefix(wid, "wkl_") }

func vethName(wid string) string {
	s := strings.TrimPrefix(wid, "wkl_")
	if len(s) > 11 {
		s = s[:11]
	}
	return "odv" + s
}

// setupWorkload creates the netns and wires a veth into the env bridge.
func (p *netPlumber) setupWorkload(envID, wid, alias string) (nsPath string, ip net.IP, err error) {
	ip, e, err := p.allocIP(envID, wid, alias)
	if err != nil {
		return "", nil, err
	}
	name := nsName(wid)
	nsPath = filepath.Join("/run/netns", name)
	if _, err := os.Stat(nsPath); err == nil {
		return nsPath, ip, nil // already wired (idempotent restart)
	}
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		return "", nil, err
	}
	defer orig.Close()
	ns, err := netns.NewNamed(name)
	if err != nil {
		return "", nil, fmt.Errorf("create netns: %w", err)
	}
	defer ns.Close()
	if err := netns.Set(orig); err != nil {
		return "", nil, err
	}
	br, err := netlink.LinkByName(e.Bridge)
	if err != nil {
		return "", nil, fmt.Errorf("bridge %s: %w", e.Bridge, err)
	}
	host := vethName(wid)
	peer := host + "p"
	if l, err := netlink.LinkByName(host); err == nil {
		_ = netlink.LinkDel(l)
	}
	la := netlink.NewLinkAttrs()
	la.Name = host
	la.MasterIndex = br.Attrs().Index
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: la, PeerName: peer}); err != nil {
		return "", nil, fmt.Errorf("veth: %w", err)
	}
	pl, err := netlink.LinkByName(peer)
	if err != nil {
		return "", nil, err
	}
	if err := netlink.LinkSetNsFd(pl, int(ns)); err != nil {
		return "", nil, err
	}
	hl, _ := netlink.LinkByName(host)
	if err := netlink.LinkSetUp(hl); err != nil {
		return "", nil, err
	}
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		return "", nil, err
	}
	defer h.Close()
	in, err := h.LinkByName(peer)
	if err != nil {
		return "", nil, err
	}
	if err := h.LinkSetName(in, "eth0"); err != nil {
		return "", nil, err
	}
	in, _ = h.LinkByName("eth0")
	pr := netip.MustParsePrefix(e.Subnet)
	addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/%d", ip, pr.Bits()))
	if err := h.AddrAdd(in, addr); err != nil {
		return "", nil, err
	}
	if err := h.LinkSetUp(in); err != nil {
		return "", nil, err
	}
	if lo, err := h.LinkByName("lo"); err == nil {
		_ = h.LinkSetUp(lo)
	}
	if err := h.RouteAdd(&netlink.Route{LinkIndex: in.Attrs().Index, Gw: net.ParseIP(e.Gateway)}); err != nil {
		return "", nil, fmt.Errorf("default route: %w", err)
	}
	return nsPath, ip, nil
}

func (p *netPlumber) teardownWorkload(envID, wid string) {
	if l, err := netlink.LinkByName(vethName(wid)); err == nil {
		_ = netlink.LinkDel(l)
	}
	_ = netns.DeleteNamed(nsName(wid))
	p.releaseIP(envID, wid)
}

// hostsFile renders /etc/hosts with service aliases in the environment.
func (p *netPlumber) hostsFile(envID, self string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var b strings.Builder
	b.WriteString("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n")
	if e, ok := p.state.Envs[envID]; ok {
		seen := map[string]bool{}
		for wid, name := range e.Names {
			if name == "" || seen[name] || wid == "" {
				continue
			}
			seen[name] = true
			fmt.Fprintf(&b, "%s\t%s\n", e.IPs[wid], name)
		}
		_ = self
	}
	return b.String()
}

// resolvConf returns nameservers usable from workloads (never loopback).
func resolvConf() string {
	var servers []string
	for _, f := range []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"} {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) >= 2 && fs[0] == "nameserver" {
				if a, err := netip.ParseAddr(fs[1]); err == nil && !a.IsLoopback() {
					servers = append(servers, a.String())
				}
			}
		}
		fh.Close()
		if len(servers) > 0 {
			break
		}
	}
	if len(servers) == 0 {
		servers = []string{"1.1.1.1", "8.8.8.8"}
	}
	var b strings.Builder
	for _, s := range servers {
		fmt.Fprintf(&b, "nameserver %s\n", s)
	}
	b.WriteString("options ndots:0\n")
	return b.String()
}
