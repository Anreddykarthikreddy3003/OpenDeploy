package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, y string) (*Node, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "node.yaml")
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestDefaultsLoopback(t *testing.T) {
	n, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if n.API.Listen != "127.0.0.1:7070" || n.Ingress.Mode != "lan" {
		t.Fatalf("%+v", n.API)
	}
}

// Q24 / ST-06: wildcard bind without acknowledged remote admin refuses to start.
func TestWildcardBindRefused(t *testing.T) {
	for _, l := range []string{"0.0.0.0:7070", "[::]:7070", ":7070", "192.168.1.5:7070"} {
		if _, err := load(t, "api:\n  listen: \""+l+"\"\n"); err == nil {
			t.Errorf("%s accepted", l)
		}
	}
	_, err := load(t, "api:\n  listen: \"0.0.0.0:7070\"\n  remote_admin:\n    enabled: true\n    acknowledged_risk: true\n")
	if err == nil || !strings.Contains(err.Error(), "tls_cert") {
		t.Fatalf("remote admin without TLS must fail: %v", err)
	}
	_, err = load(t, "api:\n  listen: \"0.0.0.0:7070\"\n  remote_admin:\n    enabled: true\n    acknowledged_risk: true\n    tls_cert: c\n    tls_key: k\n    allowed_cidrs: [\"10.0.0.0/8\"]\n")
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	if _, err := load(t, "bogus: 1\n"); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestDevModeRequiresEnv(t *testing.T) {
	os.Unsetenv("OPENDEPLOY_INSECURE_DEV")
	if _, err := load(t, "dev_mode: true\n"); err == nil {
		t.Fatal("dev mode accepted without env")
	}
}

func TestSecretFilePerms(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s")
	os.WriteFile(p, []byte("x\n"), 0o644)
	if _, err := ReadSecretFile(p); err == nil {
		t.Fatal("world-readable secret accepted")
	}
	os.Chmod(p, 0o600)
	if b, err := ReadSecretFile(p); err != nil || string(b) != "x" {
		t.Fatal(err)
	}
}

// The node.yaml shipped in packages must parse and validate.
func TestPackagedExampleConfig(t *testing.T) {
	n, err := Load("../../packaging/linux/etc/node.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if n.Ingress.CaddyAdmin != "/run/opendeploy/caddy/admin.sock" || n.Runtime.Backend != "containerd" || !n.Egress.Enforce {
		t.Fatalf("unexpected defaults: %+v", n.Ingress)
	}
}
