#!/bin/sh
# Builds a deliberately broken release from a good deb for the upgrade
# rollback test: platformd exits at once, so the release can never pass the
# readiness gate. opendeployctl reports VERSION and SCHEMA (the schema
# decides whether install.sh may roll back automatically).
#
#   tests/package/broken-deb.sh good.deb out.deb 9.9.9-broken 1
set -eu
GOOD=$1 OUT=$2 VERSION=$3 SCHEMA=$4
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
dpkg-deb -R "$GOOD" "$W/pkg"
BIN="$W/pkg/usr/lib/opendeploy/release/bin"
printf '#!/bin/sh\necho "broken release: platformd refuses to start" >&2\nexit 1\n' >"$BIN/platformd"
mv "$BIN/opendeployctl" "$BIN/opendeployctl.real"
cat >"$BIN/opendeployctl" <<EOF
#!/bin/sh
if [ "\${1:-}" = version ]; then echo "opendeployctl $VERSION schema=$SCHEMA"; exit 0; fi
exec "\$(dirname "\$0")/opendeployctl.real" "\$@"
EOF
chmod 0755 "$BIN/platformd" "$BIN/opendeployctl"
sed -i "s/^Version: .*/Version: $VERSION/" "$W/pkg/DEBIAN/control"
# The payload changed: drop the stale checksums rather than ship wrong ones.
rm -f "$W/pkg/DEBIAN/md5sums"
dpkg-deb --build --root-owner-group "$W/pkg" "$OUT" >/dev/null
echo "$OUT"
