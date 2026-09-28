package trust

import (
	"errors"
	"testing"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/policy"
)

var fullHost = HostCapabilities{GVisor: true, VM: true, RootlessBuild: true, NetworkPolicy: true, ProfileAllowsUntrusted: true, Devices: map[string]bool{"gpu": true}}
var noSandboxHost = HostCapabilities{RootlessBuild: true, NetworkPolicy: true, ProfileAllowsUntrusted: true}

func TestTrustedProductionDefaultsToRunc(t *testing.T) {
	d, err := Decide(AdminPolicy{Class: Trusted}, Source{Env: EnvProduction, AuthorIsOwner: true}, Request{}, fullHost)
	if err != nil {
		t.Fatal(err)
	}
	if d.Runtime != RuntimeRunc || !d.ProductionSecrets || !d.RootlessBuild {
		t.Fatalf("%+v", d)
	}
}

func TestPreferGVisor(t *testing.T) {
	d, err := Decide(AdminPolicy{Class: Trusted, PreferGVisor: true}, Source{Env: EnvProduction}, Request{}, fullHost)
	if err != nil || d.Runtime != RuntimeRunsc {
		t.Fatalf("%+v %v", d, err)
	}
}

// ADR-014 / ST: untrusted must fail closed without a sandbox.
func TestUntrustedFailsClosedWithoutSandbox(t *testing.T) {
	_, err := Decide(AdminPolicy{Class: Untrusted}, Source{Env: EnvProduction}, Request{}, noSandboxHost)
	if !errors.Is(err, ErrSandboxUnavailable) {
		t.Fatalf("want ErrSandboxUnavailable, got %v", err)
	}
}

func TestUntrustedRuncRequestIgnored(t *testing.T) {
	d, err := Decide(AdminPolicy{Class: Untrusted}, Source{Env: EnvProduction}, Request{Sandbox: policy.SandboxRunc}, fullHost)
	if err != nil || d.Runtime != RuntimeRunsc || d.BuildRuntime != RuntimeRunsc {
		t.Fatalf("%+v %v", d, err)
	}
	if d.ProductionSecrets {
		t.Fatal("untrusted must not receive production secrets")
	}
}

func TestRepoCannotRaiseTrust(t *testing.T) {
	_, err := Decide(AdminPolicy{Class: Trusted}, Source{Env: EnvProduction}, Request{DeclaredClass: Privileged}, fullHost)
	if !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("got %v", err)
	}
	d, err := Decide(AdminPolicy{Class: Trusted}, Source{Env: EnvProduction}, Request{DeclaredClass: Untrusted}, fullHost)
	if err != nil || d.Class != Untrusted {
		t.Fatalf("repo lowering trust must be honoured: %+v %v", d, err)
	}
}

func TestForkPR(t *testing.T) {
	_, err := Decide(AdminPolicy{Class: Trusted}, Source{Env: EnvPreview, FromFork: true}, Request{}, fullHost)
	if !errors.Is(err, ErrForksDisabled) {
		t.Fatalf("got %v", err)
	}
	d, err := Decide(AdminPolicy{Class: Trusted, AllowPublicForks: true}, Source{Env: EnvPreview, FromFork: true}, Request{}, fullHost)
	if err != nil || d.Class != Untrusted || d.Runtime != RuntimeRunsc || d.ProductionSecrets || d.SecretScope != EnvPreview {
		t.Fatalf("%+v %v", d, err)
	}
	_, err = Decide(AdminPolicy{Class: Trusted, AllowPublicForks: true}, Source{Env: EnvPreview, FromFork: true}, Request{}, noSandboxHost)
	if !errors.Is(err, ErrSandboxUnavailable) {
		t.Fatalf("fork without sandbox must fail closed, got %v", err)
	}
}

func TestPreviewNeverGetsProdSecrets(t *testing.T) {
	d, err := Decide(AdminPolicy{Class: Trusted}, Source{Env: EnvPreview}, Request{}, fullHost)
	if err != nil || d.ProductionSecrets || d.SecretScope != EnvPreview {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestCapabilities(t *testing.T) {
	_, err := Decide(AdminPolicy{Class: Trusted, GrantedCapabilities: []string{"gpu"}}, Source{Env: EnvProduction}, Request{Capabilities: []string{"gpu"}}, fullHost)
	if !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("trusted class must not get capabilities: %v", err)
	}
	_, err = Decide(AdminPolicy{Class: Privileged}, Source{Env: EnvProduction}, Request{Capabilities: []string{"gpu"}}, fullHost)
	if !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("ungranted capability must be denied: %v", err)
	}
	d, err := Decide(AdminPolicy{Class: Privileged, GrantedCapabilities: []string{"gpu"}}, Source{Env: EnvProduction}, Request{Capabilities: []string{"gpu"}}, fullHost)
	if err != nil || len(d.Capabilities) != 1 {
		t.Fatalf("%+v %v", d, err)
	}
	_, err = Decide(AdminPolicy{Class: Privileged, GrantedCapabilities: []string{"fuse"}}, Source{Env: EnvProduction}, Request{Capabilities: []string{"fuse"}}, fullHost)
	if !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("host lacking device must deny: %v", err)
	}
	_, err = Decide(AdminPolicy{Class: Privileged, GrantedCapabilities: []string{"gpu"}}, Source{Env: EnvPreview}, Request{}, fullHost)
	if !errors.Is(err, ErrRejectedCombo) {
		t.Fatalf("privileged preview must be rejected: %v", err)
	}
}

func TestFailsClosedWithoutNetworkPolicy(t *testing.T) {
	h := fullHost
	h.NetworkPolicy = false
	if _, err := Decide(AdminPolicy{Class: Trusted}, Source{Env: EnvProduction}, Request{}, h); !errors.Is(err, ErrNoNetworkPolicy) {
		t.Fatalf("got %v", err)
	}
}

func TestExplicitSandboxRequestNeverDowngrades(t *testing.T) {
	if _, err := Decide(AdminPolicy{Class: Trusted}, Source{Env: EnvProduction}, Request{Sandbox: policy.SandboxGVisor}, noSandboxHost); !errors.Is(err, ErrSandboxUnavailable) {
		t.Fatalf("got %v", err)
	}
	if _, err := Decide(AdminPolicy{Class: Untrusted}, Source{Env: EnvProduction}, Request{Sandbox: policy.SandboxVM}, HostCapabilities{GVisor: true, NetworkPolicy: true, ProfileAllowsUntrusted: true}); !errors.Is(err, ErrSandboxUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestTinyProfileDisablesUntrusted(t *testing.T) {
	h := fullHost
	h.ProfileAllowsUntrusted = false
	if _, err := Decide(AdminPolicy{Class: Untrusted}, Source{Env: EnvProduction}, Request{}, h); !errors.Is(err, ErrSandboxUnavailable) {
		t.Fatalf("got %v", err)
	}
}
