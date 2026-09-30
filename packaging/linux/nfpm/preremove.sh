#!/bin/sh
# deb prerm / rpm %preun: stop the node on removal, not on upgrade. State in
# /var/lib/opendeploy and /etc/opendeploy is kept (purge it by hand after
# taking a backup).
set -e
case "${1:-}" in
remove|0) ;;
*) exit 0 ;;
esac
if [ -d /run/systemd/system ]; then
	systemctl disable --now opendeploy.target >/dev/null 2>&1 || true
	for u in /etc/systemd/system/opendeploy-*.service; do
		[ -e "$u" ] && systemctl stop "$(basename "$u")" >/dev/null 2>&1 || true
	done
fi
rm -f /usr/local/bin/opendeployctl
