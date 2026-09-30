#!/bin/sh
# Build the OpenDeploy managed guest images from a node .deb.
#
#   guest/build.sh --deb dist/opendeploy_<ver>_linux-amd64.deb --arch amd64 --kind wsl2 --out dist/guest
#   guest/build.sh --deb dist/opendeploy_<ver>_linux-arm64.deb --arch arm64 --kind vz   --out dist/guest
#
# Outputs (in --out):
#   wsl2: opendeploy.wsl              WSL custom distribution (gzip tar)
#   vz:   vmlinuz initrd.img modules.img disk.img.gz manifest.json
# OPENDEPLOY_BUILD_CA_BUNDLE: extra CA bundle for TLS-inspecting proxies.
# Needs docker (buildx; QEMU binfmt for a foreign --arch), root (sudo) to keep
# file ownership while repacking, e2fsprogs >= 1.43 (mkfs.ext4 -d), python3.
set -eu

DEB="" ARCH="" KIND="" OUT=""
while [ $# -gt 0 ]; do
	case "$1" in
	--deb) DEB="$2"; shift 2 ;;
	--arch) ARCH="$2"; shift 2 ;;
	--kind) KIND="$2"; shift 2 ;;
	--out) OUT="$2"; shift 2 ;;
	*) echo "unknown option $1" >&2; exit 2 ;;
	esac
done
[ -f "$DEB" ] && [ -n "$ARCH" ] && [ -n "$OUT" ] || { echo "usage: $0 --deb FILE --arch amd64|arm64 --kind wsl2|vz --out DIR" >&2; exit 2; }
case "$KIND" in wsl2|vz) ;; *) echo "--kind must be wsl2 or vz" >&2; exit 2 ;; esac
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO=sudo
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$OUT"
OUT=$(CDPATH= cd -- "$OUT" && pwd)
WORK=$(mktemp -d)
trap '$SUDO rm -rf "$WORK"' EXIT
say() { printf '==> %s\n' "$*"; }

say "building the $KIND guest for $ARCH"
mkdir -p "$WORK/ctx"
cp -a "$HERE/Dockerfile" "$HERE/rootfs" "$WORK/ctx/"
cp "$DEB" "$WORK/ctx/opendeploy.deb"
TAG="opendeploy-guest:$KIND-$ARCH"
set -- --platform "linux/$ARCH" --build-arg GUEST_KIND="$KIND" --load -t "$TAG"
# Optional TLS-inspection CA for the pinned downloads (never stored in the image).
[ -n "${OPENDEPLOY_BUILD_CA_BUNDLE:-}" ] && set -- "$@" --secret id=build-ca,src="$OPENDEPLOY_BUILD_CA_BUNDLE"
docker buildx build "$@" "$WORK/ctx"

say "exporting the root filesystem"
CID=$(docker create --platform "linux/$ARCH" "$TAG" /bin/true)
docker export "$CID" -o "$WORK/rootfs.tar"
docker rm "$CID" >/dev/null
ROOT="$WORK/root"
$SUDO mkdir -p "$ROOT"
$SUDO tar -xpf "$WORK/rootfs.tar" -C "$ROOT" --numeric-owner
rm -f "$WORK/rootfs.tar"
# Container runtime placeholders are not part of the system.
$SUDO rm -f "$ROOT/.dockerenv"
echo opendeploy | $SUDO tee "$ROOT/etc/hostname" >/dev/null
printf '127.0.0.1\tlocalhost\n127.0.1.1\topendeploy\n::1\tlocalhost ip6-localhost ip6-loopback\n' | $SUDO tee "$ROOT/etc/hosts" >/dev/null
$SUDO rm -f "$ROOT/etc/resolv.conf"
[ "$KIND" = vz ] && $SUDO ln -s /run/systemd/resolve/stub-resolv.conf "$ROOT/etc/resolv.conf"
# A fresh machine-id per install (systemd generates it on first boot).
$SUDO sh -c ': > "$1/etc/machine-id"' _ "$ROOT"

if [ "$KIND" = wsl2 ]; then
	say "packing opendeploy.wsl"
	$SUDO tar --numeric-owner -C "$ROOT" -czf "$OUT/opendeploy.wsl" .
	$SUDO chown "$(id -u):$(id -g)" "$OUT/opendeploy.wsl"
	ls -lh "$OUT/opendeploy.wsl"
	exit 0
fi

say "extracting kernel and initramfs"
KVER=$(ls "$ROOT/usr/lib/modules" | sort -V | tail -n1)
[ -n "$KVER" ] || { echo "no kernel installed in the image" >&2; exit 1; }
$SUDO cp "$ROOT/boot/vmlinuz-$KVER" "$WORK/vmlinuz.raw"
$SUDO cp "$ROOT/boot/initrd.img-$KVER" "$OUT/initrd.img"
$SUDO chown "$(id -u):$(id -g)" "$WORK/vmlinuz.raw" "$OUT/initrd.img"
# Virtualization.framework on Apple silicon boots an uncompressed arm64
# Image: unwrap gzip or EFI zboot kernels.
python3 - "$WORK/vmlinuz.raw" "$OUT/vmlinuz" <<'PY'
import gzip, struct, subprocess, sys
src, dst = sys.argv[1], sys.argv[2]
b = open(src, "rb").read()
if b[:2] == b"\x1f\x8b":
    b = gzip.decompress(b)
elif b[:2] == b"MZ" and b[4:8] == b"zimg":
    off, size = struct.unpack_from("<II", b, 8)
    comp = b[24:32].rstrip(b"\0").decode()
    payload = b[off:off + size]
    if comp == "gzip":
        b = gzip.decompress(payload)
    elif comp == "zstd":
        b = subprocess.run(["zstd", "-dc"], input=payload, capture_output=True, check=True).stdout
    else:
        sys.exit("unsupported zboot compression " + comp)
open(dst, "wb").write(b)
PY

say "building modules.img ($KVER)"
MSIZE=$(( $($SUDO du -sm "$ROOT/usr/lib/modules" | cut -f1) * 12 / 10 + 64 ))
truncate -s "${MSIZE}M" "$OUT/modules.img"
$SUDO mkfs.ext4 -q -F -L odmods -d "$ROOT/usr/lib/modules" "$OUT/modules.img"
$SUDO sh -c 'rm -rf "$1"/usr/lib/modules/* "$1"/boot/*' _ "$ROOT"

say "building the root disk"
RSIZE=$(( $($SUDO du -sm "$ROOT" | cut -f1) * 13 / 10 + 1024 ))
truncate -s "${RSIZE}M" "$WORK/disk.img"
$SUDO mkfs.ext4 -q -F -L odroot -d "$ROOT" "$WORK/disk.img"
$SUDO chown "$(id -u):$(id -g)" "$WORK/disk.img"
gzip -c -6 "$WORK/disk.img" > "$OUT/disk.img.gz"

VERSION=$(dpkg-deb -f "$DEB" Version 2>/dev/null || echo unknown)
python3 - "$OUT" "$VERSION" "$ARCH" "$KVER" <<'PY'
import hashlib, json, os, sys
out, version, arch, kver = sys.argv[1:5]
files = {}
for f in ("vmlinuz", "initrd.img", "modules.img", "disk.img.gz"):
    h = hashlib.sha256()
    with open(os.path.join(out, f), "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    files[f] = h.hexdigest()
json.dump({"version": version, "arch": arch, "kernel": kver, "sha256": files}, open(os.path.join(out, "manifest.json"), "w"), indent=2)
PY
ls -lh "$OUT"
