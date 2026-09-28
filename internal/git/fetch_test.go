package git

import (
	"context"
	"net/netip"
	"testing"
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
