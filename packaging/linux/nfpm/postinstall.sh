#!/bin/sh
# deb postinst / rpm %post: install or upgrade the node from the package payload.
set -e
case "${1:-}" in
abort-upgrade|abort-remove|abort-deconfigure) exit 0 ;;
esac
if [ ! -d /run/systemd/system ]; then
	echo "opendeploy: systemd is not running (container or chroot?); run /usr/lib/opendeploy/release/packaging/linux/install.sh on the target host" >&2
	exit 0
fi
START=""
[ "${OPENDEPLOY_NO_START:-}" = 1 ] && START="--no-start"
exec /usr/lib/opendeploy/release/packaging/linux/install.sh $START
