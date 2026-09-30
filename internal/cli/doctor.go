package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type check struct {
	name, status, detail string
}

func cmdDoctor(ctx context.Context, _ []string) error {
	var cs []check
	add := func(name string, ok bool, warnOnly bool, detail string) {
		st := "ok"
		if !ok {
			st = "FAIL"
			if warnOnly {
				st = "warn"
			}
		}
		cs = append(cs, check{name, st, detail})
	}
	run := func(name string, args ...string) (string, error) {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(c, name, args...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	add("platform", runtime.GOOS == "linux", false, runtime.GOOS+"/"+runtime.GOARCH+" (Linux hosts run workloads natively; Windows/macOS use the bundled Linux VM)")
	if runtime.GOOS != "linux" {
		return printChecks(cs)
	}
	add("running as root", os.Geteuid() == 0, true, "hostd/egressd need root; other services drop to their own users")
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	add("cgroup v2", err == nil, false, "required for per-workload CPU/memory/PID limits")
	if b, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
		add("user namespaces", strings.TrimSpace(string(b)) != "0", false, "rootless BuildKit needs user namespaces")
	}
	_, err = os.Stat("/run/containerd/containerd.sock")
	add("containerd", err == nil, true, "primary runtime backend (/run/containerd/containerd.sock)")
	if out, err := run("docker", "info", "--format", "{{.ServerVersion}} {{json .Runtimes}}"); err == nil {
		add("docker engine", true, true, "optional backend: "+strings.SplitN(out, " ", 2)[0])
		add("gVisor registered with docker", strings.Contains(out, "runsc"), true, "Untrusted projects and fork previews fail closed without it (`runsc install`)")
	} else {
		add("docker engine", false, true, "optional backend not reachable")
	}
	_, err = exec.LookPath("runsc")
	add("gVisor (runsc)", err == nil, true, "sandbox for the Untrusted trust class")
	_, err1 := exec.LookPath("buildctl")
	_, err2 := exec.LookPath("docker")
	add("build executor", err1 == nil || err2 == nil, false, "buildctl (rootless buildkitd) or docker buildx")
	if out, err := run("nft", "--version"); err == nil {
		add("nftables", true, false, out)
	} else {
		add("nftables", false, false, "egressd enforces network isolation with nftables")
	}
	if out, err := run("caddy", "version"); err == nil {
		add("caddy", true, false, strings.Fields(out)[0])
	} else {
		add("caddy", false, false, "edge proxy and automatic HTTPS")
	}
	for _, p := range []string{"80", "443"} {
		ln, err := net.Listen("tcp", ":"+p)
		if err == nil {
			ln.Close()
			add("port "+p, true, true, "free (Caddy will bind it)")
		} else {
			add("port "+p, false, true, "in use — fine if it is OpenDeploy's Caddy")
		}
	}
	return printChecks(cs)
}

func printChecks(cs []check) error {
	rows := [][]string{{"CHECK", "STATUS", "DETAIL"}}
	fail := 0
	for _, c := range cs {
		rows = append(rows, []string{c.name, c.status, c.detail})
		if c.status == "FAIL" {
			fail++
		}
	}
	table(rows)
	if fail > 0 {
		return fmt.Errorf("%d required capabilities missing", fail)
	}
	return nil
}
