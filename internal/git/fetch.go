// Package git fetches repository source at an exact commit (FR-005).
package git

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var shaRE = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
var refRE = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,250}$`)

// Source identifies what to fetch.
type Source struct {
	CloneURL string // https only
	SHA      string // exact commit; required unless Ref is set
	Ref      string // branch name, resolved to a SHA when SHA is empty
	Token    string // short-lived GitHub installation token (never logged)
	// AllowedHosts restricts clone hosts (e.g. github.com). Empty = any
	// public host.
	AllowedHosts []string
}

// Result reports what was fetched.
type Result struct {
	SHA     string
	Message string
	Author  string
}

// ErrUnsafeURL is returned for non-https or private-address clone URLs.
var ErrUnsafeURL = errors.New("clone URL must be https to a public host")

// ValidateCloneURL enforces https and a public destination (SSRF defence).
func ValidateCloneURL(ctx context.Context, raw string, allowed []string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrUnsafeURL
	}
	host := u.Hostname()
	if len(allowed) > 0 {
		ok := false
		for _, a := range allowed {
			if strings.EqualFold(host, a) {
				ok = true
			}
		}
		if !ok {
			return nil, fmt.Errorf("%w: host %s not allowed", ErrUnsafeURL, host)
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !PublicAddr(ip) {
			return nil, ErrUnsafeURL
		}
		return u, nil
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(rctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	for _, a := range addrs {
		if !PublicAddr(a) {
			return nil, fmt.Errorf("%w: %s resolves to non-public %s", ErrUnsafeURL, host, a)
		}
	}
	return u, nil
}

// PublicAddr reports whether ip is a globally routable unicast address
// (not loopback, private, link-local, CGNAT, metadata or unspecified).
func PublicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("64:ff9b::/96"), // NAT64 can reach IPv4 internals
	netip.MustParsePrefix("2001:db8::/32"),
}

// Fetch clones exactly src.SHA (or the head of src.Ref) into dir, verifies
// the checked-out commit, and removes .git. The token is supplied via
// GIT_CONFIG_* environment (never argv or disk). Hooks, submodules,
// non-https protocols and system/global config are disabled.
func Fetch(ctx context.Context, dir string, src Source) (*Result, error) {
	if src.SHA != "" && !shaRE.MatchString(src.SHA) {
		return nil, fmt.Errorf("invalid commit sha %q", src.SHA)
	}
	if src.SHA == "" && !refRE.MatchString(src.Ref) {
		return nil, fmt.Errorf("invalid ref %q", src.Ref)
	}
	if strings.Contains(src.Ref, "..") {
		return nil, fmt.Errorf("invalid ref %q", src.Ref)
	}
	if _, err := ValidateCloneURL(ctx, src.CloneURL, src.AllowedHosts); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	home, err := os.MkdirTemp("", "od-git-home-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(home)

	cfg := [][2]string{
		{"protocol.allow", "never"},
		{"protocol.https.allow", "always"},
		{"core.hooksPath", "/dev/null"},
		{"core.symlinks", "true"},
		{"core.fsmonitor", "false"},
		{"submodule.recurse", "false"},
		{"fetch.recurseSubmodules", "false"},
		{"credential.helper", ""},
		{"http.followRedirects", "false"},
		{"safe.directory", dir},
	}
	if src.Token != "" {
		basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + src.Token))
		cfg = append(cfg, [2]string{"http.extraHeader", "Authorization: Basic " + basic})
	}
	env := []string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_ASKPASS=/bin/false",
		"GIT_LFS_SKIP_SMUDGE=1",
		fmt.Sprintf("GIT_CONFIG_COUNT=%d", len(cfg)),
	}
	if p := os.Getenv("HTTPS_PROXY"); p != "" {
		env = append(env, "HTTPS_PROXY="+p)
	}
	for _, v := range []string{"SSL_CERT_FILE", "GIT_SSL_CAINFO"} {
		if p := os.Getenv(v); p != "" {
			env = append(env, v+"="+p)
		}
	}
	for i, kv := range cfg {
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, kv[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, kv[1]))
	}
	run := func(args ...string) (string, error) {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(cctx, "git", args...)
		cmd.Dir = dir
		cmd.Env = env
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		if err := cmd.Run(); err != nil {
			msg := redact(stderr.String(), src.Token)
			return "", fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(lastLines(msg, 5)))
		}
		return strings.TrimSpace(out.String()), nil
	}
	if _, err := run("init", "-q", "."); err != nil {
		return nil, err
	}
	if _, err := run("remote", "add", "origin", src.CloneURL); err != nil {
		return nil, err
	}
	target := src.SHA
	if target == "" {
		target = "refs/heads/" + src.Ref
	}
	if _, err := run("fetch", "-q", "--no-tags", "--depth=1", "origin", target); err != nil {
		return nil, err
	}
	if _, err := run("checkout", "-q", "--detach", "FETCH_HEAD"); err != nil {
		return nil, err
	}
	head, err := run("rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	if src.SHA != "" && head != src.SHA {
		return nil, fmt.Errorf("fetched commit %s does not match requested %s", head, src.SHA)
	}
	res := &Result{SHA: head}
	if msg, err := run("log", "-1", "--format=%s"); err == nil {
		res.Message = msg
	}
	if a, err := run("log", "-1", "--format=%an"); err == nil {
		res.Author = a
	}
	if err := os.RemoveAll(filepath.Join(dir, ".git")); err != nil {
		return nil, err
	}
	return res, nil
}

func redact(s, secret string) string {
	if secret == "" {
		return s
	}
	s = strings.ReplaceAll(s, secret, "[REDACTED]")
	return strings.ReplaceAll(s, base64.StdEncoding.EncodeToString([]byte("x-access-token:"+secret)), "[REDACTED]")
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
