//go:build adversarial

// Package adversarial holds release-gate negative tests (PRD §30). They
// need a Linux host with Docker and nftables and run as root. A control the
// host cannot enforce is reported via t.Skip("CAPABILITY-BLOCKED: ...")
// rather than passing silently.
package adversarial

import (
	"context"
	"fmt"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/testcap"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/ids"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/network"
	"github.com/anreddykarthikreddy3003/opendeploy/internal/runtime"
)

func need(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		testcap.Blocked(t, "requires root")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		testcap.Blocked(t, "docker unavailable")
	}
	if err := network.Probe(context.Background(), ""); err != nil {
		testcap.Blocked(t, "nftables unavailable: %v", err)
	}
}

func dockerOut(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// probe runs a TCP connect from inside the attacker container.
func probe(t *testing.T, container, addr string) bool {
	host, port, _ := net.SplitHostPort(addr)
	_, err := dockerOut(t, "exec", container, "nc", "-z", "-w", "3", host, port)
	return err == nil
}

func hostIPs(t *testing.T) []string {
	var out []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
			out = append(out, ipn.IP.String())
		}
	}
	return out
}

// ST-02 / ST-04 / Q38 / Q67 / Q68 / Q69: cross-project isolation, workload
// to host/LAN/metadata denial, and that intra-environment traffic still works.
func TestNetworkSegmentation(t *testing.T) {
	need(t)
	ctx := context.Background()
	d, err := runtime.NewDocker("unix:///var/run/docker.sock", t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prjA, prjB := ids.New("prj"), ids.New("prj")
	envA, envB := ids.New("env"), ids.New("env")
	na, err := d.EnsureNetwork(ctx, runtime.NetworkSpec{EnvironmentID: envA, ProjectID: prjA, Kind: "production"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.RemoveNetwork(ctx, envA)
	nb, err := d.EnsureNetwork(ctx, runtime.NetworkSpec{EnvironmentID: envB, ProjectID: prjB, Kind: "production"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.RemoveNetwork(ctx, envB)

	// A host service (stands in for the platform API / registry / SSH).
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	run := func(name, netName string, cmd ...string) string {
		args := append([]string{"run", "-d", "--rm", "--name", name, "--network", netName, "alpine:3.20"}, cmd...)
		if _, err := dockerOut(t, args...); err != nil {
			t.Fatalf("docker run %s: %v", name, err)
		}
		t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })
		ip, _ := dockerOut(t, "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)
		return ip
	}
	suffix := strings.TrimPrefix(envA, "env_")[:8]
	attacker := "od-adv-attacker-" + suffix
	peer := "od-adv-peer-" + suffix
	victim := "od-adv-victim-" + suffix
	run(attacker, runtime.NetworkName(envA), "sleep", "600")
	peerIP := run(peer, runtime.NetworkName(envA), "nc", "-lk", "-p", "7000", "-e", "true")
	victimIP := run(victim, runtime.NetworkName(envB), "nc", "-lk", "-p", "7000", "-e", "true")
	time.Sleep(time.Second)

	gwA := na.Gateway
	hostTargets := []string{net.JoinHostPort(gwA, fmt.Sprint(port))}
	for _, ip := range hostIPs(t) {
		hostTargets = append(hostTargets, net.JoinHostPort(ip, fmt.Sprint(port)))
	}
	// Precondition: without OpenDeploy policy the container CAN reach the
	// host service, proving the test exercises our enforcement.
	if !probe(t, attacker, hostTargets[0]) {
		t.Log("host service unreachable even without policy (engine already blocks it)")
	}

	svc := &network.Service{StateFile: t.TempDir() + "/p.json"}
	if err := svc.Init(ctx); err != nil {
		t.Fatal(err)
	}
	defer network.Flush(ctx, "")
	for _, p := range []network.EnvPolicy{
		{EnvironmentID: envA, ProjectID: prjA, Kind: "production", Bridge: na.Bridge, Subnet: na.Subnet, Gateway: na.Gateway, Internet: true},
		{EnvironmentID: envB, ProjectID: prjB, Kind: "production", Bridge: nb.Bridge, Subnet: nb.Subnet, Gateway: nb.Gateway, Internet: true},
	} {
		if err := svc.Apply(ctx, p); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("same-environment traffic allowed", func(t *testing.T) {
		if !probe(t, attacker, net.JoinHostPort(peerIP, "7000")) {
			t.Fatal("intra-environment connectivity broken by policy")
		}
	})
	t.Run("cross-project denied", func(t *testing.T) {
		if probe(t, attacker, net.JoinHostPort(victimIP, "7000")) {
			t.Fatal("project A reached project B")
		}
	})
	t.Run("workload to host denied", func(t *testing.T) {
		for _, tgt := range hostTargets {
			if probe(t, attacker, tgt) {
				t.Fatalf("workload reached host service at %s", tgt)
			}
		}
	})
	t.Run("metadata and private ranges denied", func(t *testing.T) {
		for _, tgt := range []string{"169.254.169.254:80", "10.255.255.1:80", "192.168.255.1:80", "172.31.255.1:80"} {
			if probe(t, attacker, tgt) {
				t.Fatalf("reached %s", tgt)
			}
		}
		// Verify the drop is ours (rule counters / listing mention the env).
		out, _ := exec.Command("nft", "list", "table", "inet", network.TableName).CombinedOutput()
		if !strings.Contains(string(out), "private/metadata egress "+envA) {
			t.Fatal("expected OpenDeploy rule missing")
		}
	})
	t.Run("internet egress allowed (positive control)", func(t *testing.T) {
		if !probe(t, attacker, "1.1.1.1:443") && !probe(t, attacker, "140.82.112.3:443") {
			testcap.Blocked(t, "this host has no direct internet egress to verify the positive control")
		}
	})
	t.Run("no-internet environment isolated", func(t *testing.T) {
		if err := svc.Apply(ctx, network.EnvPolicy{EnvironmentID: envA, ProjectID: prjA, Kind: "production", Bridge: na.Bridge, Subnet: na.Subnet, Gateway: na.Gateway, Internet: false}); err != nil {
			t.Fatal(err)
		}
		if probe(t, attacker, "1.1.1.1:443") || probe(t, attacker, "140.82.112.3:443") {
			t.Fatal("offline environment reached the internet")
		}
		if !probe(t, attacker, net.JoinHostPort(peerIP, "7000")) {
			t.Fatal("offline environment lost intra-environment connectivity")
		}
	})
}
