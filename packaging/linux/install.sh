#!/bin/sh
# OpenDeploy Linux installer / upgrader.
#
# Run as root from an extracted release archive (opendeploy_<ver>_linux-<arch>.tar.gz)
# or from the package payload (/usr/lib/opendeploy/release):
#
#   sudo ./packaging/linux/install.sh [--domain apps.example.com] [--email admin@example.com] [--no-start] [--force]
#
# It creates per-service users, state directories, the A/B release slots and
# systemd units, writes /etc/opendeploy/node.yaml on first install, and starts
# opendeploy.target. Re-running it upgrades: the release is staged into the
# inactive slot and activated (the previous slot stays for rollback).
set -eu

SRC=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
PKG="$SRC/packaging/linux"
OPT=/opt/opendeploy
ETC=/etc/opendeploy
UNIT_DIR=/etc/systemd/system
DOMAIN=""
EMAIL=""
START=1
FORCE=0

while [ $# -gt 0 ]; do
	case "$1" in
	--domain) DOMAIN="$2"; shift 2 ;;
	--email) EMAIL="$2"; shift 2 ;;
	--no-start) START=0; shift ;;
	--force) FORCE=1; shift ;;
	-h|--help) sed -n '2,13p' "$0"; exit 0 ;;
	*) echo "unknown option $1" >&2; exit 2 ;;
	esac
done

say() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"
[ -d /run/systemd/system ] || die "systemd is required"
[ -x "$SRC/bin/platformd" ] || die "no release binaries next to this script ($SRC/bin)"
VERSION=$("$SRC/bin/opendeployctl" version 2>/dev/null | awk '{print $2}')

# ---- prerequisites ---------------------------------------------------------------
missing=""
command -v nft >/dev/null 2>&1 || missing="$missing nftables"
command -v caddy >/dev/null 2>&1 || missing="$missing caddy"
[ -S /run/containerd/containerd.sock ] || command -v containerd >/dev/null 2>&1 || missing="$missing containerd"
{ command -v buildkitd && command -v buildctl; } >/dev/null 2>&1 || missing="$missing buildkit"
command -v rootlesskit >/dev/null 2>&1 || missing="$missing rootlesskit"
command -v newuidmap >/dev/null 2>&1 || missing="$missing uidmap"
if [ -n "$missing" ]; then
	warn "missing prerequisites:$missing"
	warn "install them (e.g. apt install nftables containerd uidmap; Caddy and BuildKit from their official releases) and re-run"
fi
command -v runsc >/dev/null 2>&1 || warn "gVisor (runsc) not found: Untrusted projects and fork previews will fail closed until it is installed"
[ -f /sys/fs/cgroup/cgroup.controllers ] || die "cgroup v2 is required"

# ---- users, groups, directories -------------------------------------------------------
say "creating service users and directories"
install -D -m 0644 "$PKG/sysusers.d/opendeploy.conf" /usr/lib/sysusers.d/opendeploy.conf
install -D -m 0644 "$PKG/tmpfiles.d/opendeploy.conf" /usr/lib/tmpfiles.d/opendeploy.conf
systemd-sysusers /usr/lib/sysusers.d/opendeploy.conf
if ! grep -q '^od-buildkit:' /etc/subuid 2>/dev/null; then
	usermod --add-subuids 1000000-1065535 --add-subgids 1000000-1065535 od-buildkit
fi
systemd-tmpfiles --create /usr/lib/tmpfiles.d/opendeploy.conf

# Ubuntu 23.10+ confines unprivileged user namespaces with AppArmor; rootless
# BuildKit needs them for rootlesskit only (the same profile Docker's rootless
# setup installs).
if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = 1 ] &&
	command -v apparmor_parser >/dev/null 2>&1 && [ -x /usr/bin/rootlesskit ]; then
	say "allowing user namespaces for rootlesskit (AppArmor)"
	cat > /etc/apparmor.d/opendeploy-rootlesskit <<'PROFILE'
abi <abi/4.0>,
include <tunables/global>

profile opendeploy-rootlesskit /usr/bin/rootlesskit flags=(unconfined) {
  userns,
  include if exists <local/opendeploy-rootlesskit>
}
PROFILE
	apparmor_parser -r /etc/apparmor.d/opendeploy-rootlesskit || warn "could not load the rootlesskit AppArmor profile"
fi

# ---- release slots -----------------------------------------------------------------
mkdir -p "$OPT/slots"
STAGE=1
if [ "$FORCE" -eq 0 ] && [ -L "$OPT/slots/current" ] && [ -x "$OPT/slots/current/bin/opendeployctl" ]; then
	RUNNING=$("$OPT/slots/current/bin/opendeployctl" version 2>/dev/null | awk '{print $2}')
	# The node may already run a newer release applied by the verified
	# updater; a package upgrade carrying an older payload must not downgrade it.
	if [ -n "$RUNNING" ] && [ -n "$VERSION" ] && [ "$RUNNING" != "$VERSION" ] &&
		[ "$(printf '%s\n%s\n' "${RUNNING#v}" "${VERSION#v}" | sort -V | tail -n1)" = "${RUNNING#v}" ]; then
		say "keeping the running release $RUNNING (newer than $VERSION)"
		STAGE=0
	elif [ "$RUNNING" = "$VERSION" ]; then
		say "$VERSION is already installed; refreshing configuration only"
		STAGE=0
	fi
fi
if [ "$STAGE" -eq 0 ]; then
	:
elif [ -L "$OPT/slots/current" ]; then
	ACTIVE=$(readlink "$OPT/slots/current")
	TARGET=a; [ "$ACTIVE" = a ] && TARGET=b
	say "upgrading: staging $VERSION into slot $TARGET (active: $ACTIVE)"
else
	TARGET=a
	say "installing $VERSION into slot a"
fi
if [ "$STAGE" -eq 1 ]; then
	rm -rf "$OPT/slots/$TARGET.new"
	mkdir -p "$OPT/slots/$TARGET.new"
	cp -a "$SRC/bin" "$OPT/slots/$TARGET.new/bin"
	cp -a "$SRC/packaging" "$OPT/slots/$TARGET.new/packaging"
	chown -R root:root "$OPT/slots/$TARGET.new"
	chmod -R go-w "$OPT/slots/$TARGET.new"
	rm -rf "$OPT/slots/$TARGET"
	mv "$OPT/slots/$TARGET.new" "$OPT/slots/$TARGET"
	ln -sfn "$TARGET" "$OPT/slots/.current-tmp"
	mv -T "$OPT/slots/.current-tmp" "$OPT/slots/current"
	# hostd reconciles slots/state.json with the running release at start.
fi
ln -sfn "$OPT/slots/current" "$OPT/current"
ln -sfn "$OPT/current/bin/opendeployctl" /usr/local/bin/opendeployctl

# ---- configuration -----------------------------------------------------------------
install -d -m 0755 "$ETC"
if [ ! -f "$ETC/node.yaml" ]; then
	say "writing $ETC/node.yaml"
	install -m 0640 -g od-ipc "$PKG/etc/node.yaml" "$ETC/node.yaml"
	[ -n "$DOMAIN" ] && sed -i "s|^  base_domain: \"\"|  base_domain: \"$DOMAIN\"|" "$ETC/node.yaml"
	[ -n "$EMAIL" ] && sed -i "s|^  acme_email: \"\"|  acme_email: \"$EMAIL\"|" "$ETC/node.yaml"
fi
[ -f "$PKG/etc/tuf-root.json" ] && [ ! -f "$ETC/tuf-root.json" ] && install -m 0644 "$PKG/etc/tuf-root.json" "$ETC/tuf-root.json"
"$OPT/current/bin/opendeployctl" admin caddy-config --config "$ETC/node.yaml" > "$ETC/caddy.json.tmp"
chmod 0644 "$ETC/caddy.json.tmp"
mv "$ETC/caddy.json.tmp" "$ETC/caddy.json"

# ---- systemd -----------------------------------------------------------------------
say "installing systemd units"
for u in "$PKG"/systemd/*.service "$PKG"/systemd/opendeploy.target; do
	install -m 0644 "$u" "$UNIT_DIR/$(basename "$u")"
done
systemctl daemon-reload
systemctl enable opendeploy.target >/dev/null
if [ "$START" -eq 1 ]; then
	say "starting OpenDeploy"
	systemctl restart opendeploy.target
	for i in $(seq 1 30); do
		if curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1; then break; fi
		sleep 1
	done
fi

echo
say "OpenDeploy $VERSION installed"
if TOKEN=$("$OPT/current/bin/opendeployctl" admin bootstrap-token --config "$ETC/node.yaml" 2>/dev/null); then
	echo "    Open http://127.0.0.1:8080 (tunnel it over SSH for remote access) and create the owner"
	echo "    account with this one-time bootstrap token:"
	echo
	echo "        $TOKEN"
	echo
fi
echo "    Check the host with: opendeployctl doctor"
