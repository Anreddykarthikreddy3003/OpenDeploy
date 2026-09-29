#!/bin/sh
# Remove OpenDeploy from this Mac. Pass --purge to also delete the VM and all
# node data (take a backup first: opendeployctl / dashboard -> Backups).
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
PURGE=""
[ "${1:-}" = "--purge" ] && PURGE="--purge"
/Library/OpenDeploy/bin/opendeploy-desktop uninstall $PURGE || true
rm -f /usr/local/bin/opendeployctl /usr/local/bin/opendeploy-desktop
rm -rf /Library/OpenDeploy
pkgutil --forget io.github.anreddykarthikreddy3003.opendeploy >/dev/null 2>&1 || true
echo "OpenDeploy removed."
