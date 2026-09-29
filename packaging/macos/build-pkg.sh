#!/bin/sh
# Build the macOS installer package.
#
#   packaging/macos/build-pkg.sh --version 2.1.0 --bin DIR --guest DIR --out dist/OpenDeploy-2.1.0-arm64.pkg
#
# DIR (--bin) holds opendeploy-desktop (cgo, darwin) and opendeployctl;
# --guest holds the vz guest image (guest/build.sh --kind vz).
# Signing: MACOS_SIGN_IDENTITY ("Developer ID Application: ...") signs the
# binaries with the hardened runtime, MACOS_INSTALLER_IDENTITY ("Developer
# ID Installer: ...") signs the package, and NOTARY_PROFILE (a notarytool
# keychain profile) notarizes and staples it. Without them the binaries are
# ad-hoc signed (the virtualization entitlement still applies locally).
set -eu
VERSION="" BIN="" GUEST="" OUT=""
while [ $# -gt 0 ]; do
	case "$1" in
	--version) VERSION="$2"; shift 2 ;;
	--bin) BIN="$2"; shift 2 ;;
	--guest) GUEST="$2"; shift 2 ;;
	--out) OUT="$2"; shift 2 ;;
	*) echo "unknown option $1" >&2; exit 2 ;;
	esac
done
[ -n "$VERSION" ] && [ -d "$BIN" ] && [ -d "$GUEST" ] && [ -n "$OUT" ] || { echo "usage: $0 --version V --bin DIR --guest DIR --out FILE.pkg" >&2; exit 2; }
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT
install -d "$ROOT/Library/OpenDeploy/bin" "$ROOT/Library/OpenDeploy/guest"
install -m 0755 "$BIN/opendeploy-desktop" "$BIN/opendeployctl" "$ROOT/Library/OpenDeploy/bin/"
for f in vmlinuz initrd.img modules.img disk.img.gz manifest.json; do
	install -m 0644 "$GUEST/$f" "$ROOT/Library/OpenDeploy/guest/$f"
done
install -m 0755 "$HERE/uninstall.sh" "$ROOT/Library/OpenDeploy/uninstall.sh"

ID="${MACOS_SIGN_IDENTITY:--}"
OPTS=""
[ "$ID" != "-" ] && OPTS="--options runtime --timestamp"
codesign --force $OPTS --sign "$ID" --entitlements "$HERE/entitlements.plist" "$ROOT/Library/OpenDeploy/bin/opendeploy-desktop"
codesign --force $OPTS --sign "$ID" "$ROOT/Library/OpenDeploy/bin/opendeployctl"
codesign --verify --strict "$ROOT/Library/OpenDeploy/bin/opendeploy-desktop"
codesign -d --entitlements - "$ROOT/Library/OpenDeploy/bin/opendeploy-desktop" 2>&1 | grep -q com.apple.security.virtualization

mkdir -p "$(dirname "$OUT")"
UNSIGNED="$OUT.unsigned.pkg"
pkgbuild --root "$ROOT" --scripts "$HERE/scripts" --identifier io.github.anreddykarthikreddy3003.opendeploy \
	--version "$VERSION" --install-location / "$UNSIGNED"
if [ -n "${MACOS_INSTALLER_IDENTITY:-}" ]; then
	productsign --sign "$MACOS_INSTALLER_IDENTITY" "$UNSIGNED" "$OUT"
	rm -f "$UNSIGNED"
else
	mv "$UNSIGNED" "$OUT"
fi
if [ -n "${NOTARY_PROFILE:-}" ]; then
	xcrun notarytool submit "$OUT" --keychain-profile "$NOTARY_PROFILE" --wait
	xcrun stapler staple "$OUT"
fi
ls -lh "$OUT"
