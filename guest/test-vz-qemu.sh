#!/bin/sh
# Boot-test the VM guest image (as used by Virtualization.framework) under
# QEMU/KVM on Linux: same kernel, initramfs, read-only modules disk, growing
# root disk and virtio-vsock bridge. The host side reaches the API only over
# vsock, exactly like opendeploy-desktop on macOS.
#
#   guest/test-vz-qemu.sh dist/guest/vz-amd64
set -eu
DIR=$(CDPATH= cd -- "$1" && pwd)
WORK=$(mktemp -d)
QPID=""
trap '[ -n "$QPID" ] && kill "$QPID" 2>/dev/null; rm -rf "$WORK"' EXIT
CID=${GUEST_CID:-42}
gzip -dc "$DIR/disk.img.gz" > "$WORK/disk.img"
truncate -s 16G "$WORK/disk.img"
[ -e /dev/vhost-vsock ] || sudo modprobe vhost_vsock
sudo chmod 666 /dev/vhost-vsock /dev/kvm 2>/dev/null || true
qemu-system-x86_64 -machine q35,accel=kvm -cpu host -smp 4 -m 6144 -nographic -no-reboot \
	-kernel "$DIR/vmlinuz" -initrd "$DIR/initrd.img" \
	-append "console=ttyS0 root=LABEL=odroot rw rootwait systemd.unified_cgroup_hierarchy=1" \
	-drive file="$WORK/disk.img",if=virtio,format=raw,discard=unmap \
	-drive file="$DIR/modules.img",if=virtio,format=raw,readonly=on \
	-netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
	-device vhost-vsock-pci,guest-cid="$CID" \
	-device virtio-rng-pci > "$WORK/console.log" 2>&1 &
QPID=$!

vsock() { # vsock PORT REQUEST -> response
	python3 - "$CID" "$1" "$2" <<'PY'
import socket, sys
cid, port, req = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3].replace("\\r", "\r").replace("\\n", "\n")
s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
s.settimeout(10)
s.connect((cid, port))
if req:
    s.sendall(req.encode())
out = b""
while True:
    b = s.recv(65536)
    if not b:
        break
    out += b
sys.stdout.write(out.decode(errors="replace"))
PY
}

echo "booting (console: $WORK/console.log)"
ok=""
for i in $(seq 1 240); do
	kill -0 "$QPID" 2>/dev/null || { echo "QEMU exited"; tail -80 "$WORK/console.log"; exit 1; }
	if vsock 8080 "GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n" 2>/dev/null | head -1 | grep -q ' 200 '; then ok=1; break; fi
	sleep 3
done
if [ -z "$ok" ]; then
	echo "API never answered over vsock"; tail -120 "$WORK/console.log"; exit 1
fi
tok=$(vsock 1024 "")
[ -n "$tok" ] || { echo "no bootstrap token over vsock"; exit 1; }
vsock 8080 "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n" | grep -q 'id="root"'
grep -q "odroot" "$WORK/console.log" || true
echo "VM guest image OK (API over vsock, bootstrap token served)"
