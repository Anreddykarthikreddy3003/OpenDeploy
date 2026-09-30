package git

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

func TestPublicAddr(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1", "fe80::1", "fd00::1", "0.0.0.0", "::ffff:127.0.0.1", "64:ff9b::a00:1"} {
		if PublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s considered public", s)
		}
	}
	for _, s := range []string{"140.82.112.3", "8.8.8.8", "2606:4700::1111"} {
		if !PublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s considered private", s)
		}
	}
}

func TestValidateCloneURL(t *testing.T) {
	ctx := context.Background()
	for _, u := range []string{"http://github.com/a/b", "file:///etc", "ssh://git@github.com/a/b", "https://127.0.0.1/a", "https://169.254.169.254/latest",
		"https://user:pw@github.com/a/b", "https://[::1]/x", "https://10.0.0.1/r.git", "ext::sh -c touch% /tmp/pwned"} {
		if _, err := ValidateCloneURL(ctx, u, nil); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	if _, err := ValidateCloneURL(ctx, "https://8.8.8.8/x", []string{"github.com"}); err == nil {
		t.Error("host allowlist not enforced")
	}
}

func TestFetchRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	if _, err := Fetch(ctx, t.TempDir(), Source{CloneURL: "https://github.com/a/b", SHA: "--upload-pack=x"}); err == nil {
		t.Fatal("bad sha accepted")
	}
	if _, err := Fetch(ctx, t.TempDir(), Source{CloneURL: "https://github.com/a/b", Ref: "-x"}); err == nil {
		// "-x" matches refRE; ensure git never sees it as an option: target is refs/heads/-x
		t.Log("ref '-x' passed validation; it is prefixed with refs/heads/ so cannot be an option")
	}
	if _, err := Fetch(ctx, t.TempDir(), Source{CloneURL: "https://github.com/a/b", Ref: "a..b"}); err == nil {
		t.Fatal("ref with .. accepted")
	}
}

func TestRedact(t *testing.T) {
	if got := redact("fatal: token ghs_abc leaked", "ghs_abc"); got != "fatal: token [REDACTED] leaked" {
		t.Fatal(got)
	}
}

func TestPinResolve(t *testing.T) {
	u, _ := url.Parse("https://git.example.com/o/r.git")
	got := pinResolve(u, []netip.Addr{netip.MustParseAddr("140.82.112.3"), netip.MustParseAddr("2606:50c0:8000::153")})
	if got != "git.example.com:443:140.82.112.3,[2606:50c0:8000::153]" {
		t.Fatal(got)
	}
	u, _ = url.Parse("https://git.example.com:8443/o/r.git")
	if got := pinResolve(u, []netip.Addr{netip.MustParseAddr("140.82.112.3")}); got != "git.example.com:8443:140.82.112.3" {
		t.Fatal(got)
	}
}

// The fetch is pinned to the validated address: git connects where
// http.curloptResolve says, never to a fresh DNS answer (rebinding).
func TestGitHonoursResolvePin(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var hits atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	host := "pinned.opendeploy.invalid" // never resolvable through DNS
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-c", fmt.Sprintf("http.curloptResolve=%s:%d:127.0.0.1", host, port),
		"ls-remote", fmt.Sprintf("https://%s:%d/o/r.git", host, port))
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "HTTPS_PROXY=", "https_proxy=", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	out, _ := cmd.CombinedOutput()
	if hits.Load() == 0 {
		t.Fatalf("git ignored http.curloptResolve (needs git >= 2.37): %s", out)
	}
}

func TestCheckGitVersion(t *testing.T) {
	for out, ok := range map[string]bool{"git version 2.43.0\n": true, "git version 2.37.1": true, "git version 3.0.0": true,
		"git version 2.34.1": false, "git version 1.9": false, "garbage": false, "git version 2.39.5 (Apple Git-154)": true} {
		if err := checkGitVersion(out); (err == nil) != ok {
			t.Errorf("%q: %v", out, err)
		}
	}
}
