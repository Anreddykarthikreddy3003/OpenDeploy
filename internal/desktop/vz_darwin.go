package desktop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Code-Hex/vz/v3"
)

// VZ runs the data plane in a Linux VM on Apple Virtualization.framework.
//
// Image layout (ImageDir, shipped read-only with the package):
//
//	vmlinuz       uncompressed kernel
//	initrd.img    initramfs (virtio block + ext4)
//	modules.img   ext4 image of /usr/lib/modules for that kernel (attached read-only)
//	disk.img.gz   root filesystem, expanded once into DataDir/disk.img
//
// Kernel and modules always come from the package so they cannot drift
// apart; the root disk is the node's persistent state and is updated from
// inside by the verified updater. The VM has NAT networking for outbound
// traffic only: the dashboard and edge ports reach it over virtio-vsock,
// where opendeploy-guest-agent splices them to the guest's loopback.
type VZ struct {
	Config Config
	Log    *slog.Logger

	mu     sync.Mutex
	vm     *vz.VirtualMachine
	cancel context.CancelFunc
}

func (v *VZ) Kind() string { return "vz" }

func (v *VZ) disk() string { return filepath.Join(v.Config.DataDir, "disk.img") }

func (v *VZ) Ensure(ctx context.Context) error {
	for _, f := range []string{"vmlinuz", "initrd.img", "modules.img"} {
		if _, err := os.Stat(filepath.Join(v.Config.ImageDir, f)); err != nil {
			return fmt.Errorf("guest image incomplete: %w", err)
		}
	}
	if _, err := os.Stat(v.disk()); err == nil {
		return nil
	}
	if err := os.MkdirAll(v.Config.DataDir, 0o700); err != nil {
		return err
	}
	v.Log.Info("creating the OpenDeploy VM disk (first start)", "path", v.disk(), "size_gib", v.Config.DiskGiB)
	return ExpandImage(filepath.Join(v.Config.ImageDir, "disk.img.gz"), v.disk(), int64(v.Config.DiskGiB)<<30)
}

func (v *VZ) configuration() (*vz.VirtualMachineConfiguration, error) {
	boot, err := vz.NewLinuxBootLoader(filepath.Join(v.Config.ImageDir, "vmlinuz"),
		vz.WithInitrd(filepath.Join(v.Config.ImageDir, "initrd.img")),
		vz.WithCommandLine("console=hvc0 root=LABEL=odroot rw rootwait systemd.unified_cgroup_hierarchy=1 quiet"))
	if err != nil {
		return nil, err
	}
	cfg, err := vz.NewVirtualMachineConfiguration(boot, uint(v.Config.CPUs), uint64(v.Config.MemoryMiB)<<20)
	if err != nil {
		return nil, err
	}
	serial, err := vz.NewFileSerialPortAttachment(filepath.Join(v.Config.DataDir, "console.log"), false)
	if err != nil {
		return nil, err
	}
	console, err := vz.NewVirtioConsoleDeviceSerialPortConfiguration(serial)
	if err != nil {
		return nil, err
	}
	cfg.SetSerialPortsVirtualMachineConfiguration([]*vz.VirtioConsoleDeviceSerialPortConfiguration{console})

	nat, err := vz.NewNATNetworkDeviceAttachment()
	if err != nil {
		return nil, err
	}
	nic, err := vz.NewVirtioNetworkDeviceConfiguration(nat)
	if err != nil {
		return nil, err
	}
	mac, err := v.macAddress()
	if err != nil {
		return nil, err
	}
	nic.SetMACAddress(mac)
	cfg.SetNetworkDevicesVirtualMachineConfiguration([]*vz.VirtioNetworkDeviceConfiguration{nic})

	entropy, err := vz.NewVirtioEntropyDeviceConfiguration()
	if err != nil {
		return nil, err
	}
	cfg.SetEntropyDevicesVirtualMachineConfiguration([]*vz.VirtioEntropyDeviceConfiguration{entropy})

	var disks []vz.StorageDeviceConfiguration
	for _, d := range []struct {
		path string
		ro   bool
	}{{v.disk(), false}, {filepath.Join(v.Config.ImageDir, "modules.img"), true}} {
		att, err := vz.NewDiskImageStorageDeviceAttachment(d.path, d.ro)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", d.path, err)
		}
		blk, err := vz.NewVirtioBlockDeviceConfiguration(att)
		if err != nil {
			return nil, err
		}
		disks = append(disks, blk)
	}
	cfg.SetStorageDevicesVirtualMachineConfiguration(disks)

	balloon, err := vz.NewVirtioTraditionalMemoryBalloonDeviceConfiguration()
	if err != nil {
		return nil, err
	}
	cfg.SetMemoryBalloonDevicesVirtualMachineConfiguration([]vz.MemoryBalloonDeviceConfiguration{balloon})

	sock, err := vz.NewVirtioSocketDeviceConfiguration()
	if err != nil {
		return nil, err
	}
	cfg.SetSocketDevicesVirtualMachineConfiguration([]vz.SocketDeviceConfiguration{sock})

	if ok, err := cfg.Validate(); !ok || err != nil {
		return nil, fmt.Errorf("invalid VM configuration: %v", err)
	}
	return cfg, nil
}

// macAddress keeps a stable MAC per install so the guest's DHCP lease and
// machine identity do not change on every boot.
func (v *VZ) macAddress() (*vz.MACAddress, error) {
	p := filepath.Join(v.Config.DataDir, "mac")
	if b, err := os.ReadFile(p); err == nil {
		if hw, err := net.ParseMAC(string(b)); err == nil {
			return vz.NewMACAddress(hw)
		}
	}
	m, err := vz.NewRandomLocallyAdministeredMACAddress()
	if err != nil {
		return nil, err
	}
	_ = os.WriteFile(p, []byte(m.String()), 0o600)
	return m, nil
}

func (v *VZ) Start(ctx context.Context) (<-chan error, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.vm != nil {
		return nil, errors.New("guest already started")
	}
	cfg, err := v.configuration()
	if err != nil {
		return nil, err
	}
	vm, err := vz.NewVirtualMachine(cfg)
	if err != nil {
		return nil, err
	}
	if err := vm.Start(); err != nil {
		return nil, fmt.Errorf("start VM: %w", err)
	}
	deadline := time.After(time.Minute)
	for vm.State() != vz.VirtualMachineStateRunning {
		select {
		case st := <-vm.StateChangedNotify():
			if st == vz.VirtualMachineStateError || st == vz.VirtualMachineStateStopped {
				return nil, fmt.Errorf("VM entered state %v while starting", st)
			}
		case <-deadline:
			_ = vm.Stop()
			return nil, errors.New("VM did not start within a minute")
		case <-ctx.Done():
			_ = vm.Stop()
			return nil, ctx.Err()
		}
	}
	socks := vm.SocketDevices()
	if len(socks) == 0 {
		_ = vm.Stop()
		return nil, errors.New("VM has no vsock device")
	}
	fctx, cancel := context.WithCancel(context.Background())
	for _, port := range []int{v.Config.APIPort, v.Config.HTTPPort, v.Config.HTTPSPort} {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			cancel()
			_ = vm.Stop()
			return nil, fmt.Errorf("host port %d: %w", port, err)
		}
		dev, vport := socks[0], uint32(port)
		go func() {
			_ = Forward(fctx, ln, func(context.Context) (net.Conn, error) { return dev.Connect(vport) }, v.Log)
		}()
	}
	// Vsock ports served by opendeploy-guest-agent use the TCP port numbers.
	v.vm, v.cancel = vm, cancel
	done := make(chan error, 1)
	go func() {
		for st := range vm.StateChangedNotify() {
			if st == vz.VirtualMachineStateStopped || st == vz.VirtualMachineStateError {
				cancel()
				v.mu.Lock()
				if v.vm == vm {
					v.vm = nil
				}
				v.mu.Unlock()
				done <- fmt.Errorf("VM %v (see %s)", st, filepath.Join(v.Config.DataDir, "console.log"))
				return
			}
		}
	}()
	return done, nil
}

// tokenPort matches opendeploy-guest-agent's TokenPort.
const tokenPort = 1024

func (v *VZ) BootstrapToken(ctx context.Context) (string, error) {
	v.mu.Lock()
	vm := v.vm
	v.mu.Unlock()
	if vm == nil || len(vm.SocketDevices()) == 0 {
		return "", errors.New("VM is not running")
	}
	c, err := vm.SocketDevices()[0].Connect(tokenPort)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	b, err := io.ReadAll(io.LimitReader(c, 4096))
	return strings.TrimSpace(string(b)), err
}

func (v *VZ) Stop(ctx context.Context, timeout time.Duration) error {
	v.mu.Lock()
	vm, cancel := v.vm, v.cancel
	v.vm = nil
	v.mu.Unlock()
	if vm == nil {
		return nil
	}
	defer cancel()
	// The state channel belongs to the watcher started in Start; poll here.
	if vm.CanRequestStop() {
		if ok, err := vm.RequestStop(); ok && err == nil {
			deadline := time.Now().Add(timeout)
			for time.Now().Before(deadline) && ctx.Err() == nil {
				if vm.State() == vz.VirtualMachineStateStopped {
					return nil
				}
				time.Sleep(250 * time.Millisecond)
			}
		}
	}
	return vm.Stop()
}
