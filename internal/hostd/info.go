package hostd

import (
	"bufio"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/hostops"
)

// Info probes host capabilities.
func (h *Host) Info() *hostops.Info {
	in := &hostops.Info{OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU(), Version: h.Version, DataPlane: "native",
		Devices: map[string]bool{}, Warnings: []string{}}
	in.Hostname, _ = os.Hostname()
	in.Kernel = kernelRelease()
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	in.CgroupV2 = err == nil
	if b, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
		in.UserNamespaces = strings.TrimSpace(string(b)) != "0"
	}
	_, err = exec.LookPath("nft")
	in.Nftables = err == nil
	_, err = exec.LookPath("runsc")
	in.GVisor = err == nil
	_, err = os.Stat("/dev/kvm")
	in.KVM = err == nil
	for _, d := range []string{"/dev/nvidia0", "/dev/dri/renderD128"} {
		if _, err := os.Stat(d); err == nil {
			in.Devices[d] = true
		}
	}
	in.MemoryBytes = memTotal()
	in.DiskFreeBytes = diskFree(h.Node.DataDir)
	if ss, err := h.Slots.State(); err == nil {
		in.ActiveSlot = ss.Active
	}
	if !in.CgroupV2 {
		in.Warnings = append(in.Warnings, "cgroup v2 is required for workload resource limits")
	}
	if !in.GVisor {
		in.Warnings = append(in.Warnings, "gVisor (runsc) not installed: Untrusted projects fail closed")
	}
	if in.DiskFreeBytes > 0 && in.DiskFreeBytes < 5<<30 {
		in.Warnings = append(in.Warnings, "less than 5 GiB free in the data directory")
	}
	return in
}

func memTotal() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kb, _ := strconv.ParseUint(fields[1], 10, 64)
			return kb * 1024
		}
	}
	return 0
}
