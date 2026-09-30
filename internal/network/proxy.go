package network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/git"
)

// Proxy is the egress policy gateway for builds and restricted workloads
// (PRD §7.5, SC-05). It resolves destinations itself and dials only the
// resolved public address, so DNS rebinding cannot reach private ranges.
type Proxy struct {
	Log *slog.Logger
	// Policy returns the allowlist for a client address; ok=false denies.
	Policy func(src netip.Addr) (allowHosts []string, any bool, ok bool)
	// Resolver may be replaced in tests.
	Resolver *net.Resolver
	Dialer   *net.Dialer

	mu    sync.Mutex
	stats map[string]int
}

func hostAllowed(host string, allow []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, a := range allow {
		a = strings.ToLower(a)
		if h, _, err := net.SplitHostPort(a); err == nil {
			a = h
		}
		if strings.HasPrefix(a, "*.") {
			if strings.HasSuffix(host, a[1:]) && host != a[2:] {
				return true
			}
		} else if host == a {
			return true
		}
	}
	return false
}

// resolvePublic returns a public address for host or an error.
func (p *Proxy) resolvePublic(ctx context.Context, host string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		if !git.PublicAddr(a) {
			return netip.Addr{}, fmt.Errorf("destination %s is not a public address", a)
		}
		return a, nil
	}
	r := p.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if git.PublicAddr(a) {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%s resolves only to non-public addresses", host)
}

func (p *Proxy) authorize(r *http.Request, host string) (netip.Addr, error) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, errors.New("bad source")
	}
	allow, anyHost, ok := p.Policy(ap.Addr().Unmap())
	if !ok {
		return netip.Addr{}, errors.New("source not permitted to use the egress proxy")
	}
	if !anyHost && !hostAllowed(host, allow) {
		return netip.Addr{}, fmt.Errorf("%s is not in the egress allowlist", host)
	}
	return p.resolvePublic(r.Context(), host)
}

func (p *Proxy) log() *slog.Logger {
	if p.Log == nil {
		return slog.Default()
	}
	return p.Log
}

func (p *Proxy) dialer() *net.Dialer {
	if p.Dialer != nil {
		return p.Dialer
	}
	return &net.Dialer{Timeout: 15 * time.Second}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	if r.URL.Scheme != "http" || r.URL.Host == "" {
		http.Error(w, "only absolute http:// URLs or CONNECT are supported", http.StatusBadRequest)
		return
	}
	host, port := r.URL.Hostname(), r.URL.Port()
	if port == "" {
		port = "80"
	}
	ip, err := p.authorize(r, host)
	if err != nil {
		p.deny(w, r, host, err)
		return
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return p.dialer().DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
	}, Proxy: nil, ResponseHeaderTimeout: 60 * time.Second}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Header.Del("Proxy-Authorization")
	out.Header.Del("Proxy-Connection")
	resp, err := tr.RoundTrip(out)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *Proxy) deny(w http.ResponseWriter, r *http.Request, host string, err error) {
	p.mu.Lock()
	if p.stats == nil {
		p.stats = map[string]int{}
	}
	p.stats["denied"]++
	p.mu.Unlock()
	p.log().Warn("egress denied", "src", r.RemoteAddr, "host", host, "reason", err.Error())
	http.Error(w, "egress denied by OpenDeploy policy: "+err.Error(), http.StatusForbidden)
}

func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "bad CONNECT target", http.StatusBadRequest)
		return
	}
	if port != "443" && port != "80" && port != "22" && port != "9418" {
		p.deny(w, r, host, fmt.Errorf("port %s not permitted", port))
		return
	}
	ip, err := p.authorize(r, host)
	if err != nil {
		p.deny(w, r, host, err)
		return
	}
	up, err := p.dialer().DialContext(r.Context(), "tcp", net.JoinHostPort(ip.String(), port))
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go func() {
		defer up.Close()
		defer client.Close()
		if buf.Reader.Buffered() > 0 {
			b, _ := buf.Reader.Peek(buf.Reader.Buffered())
			_, _ = up.Write(b)
		}
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(up, client); done <- struct{}{} }()
		go func() { _, _ = io.Copy(client, up); done <- struct{}{} }()
		<-done
	}()
}
