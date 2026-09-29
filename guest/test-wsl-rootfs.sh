#!/bin/sh
# Boot-test a WSL guest rootfs without Windows: import it as a container
# image, run its systemd as PID 1, and check that first-boot setup installs
# the node and the dashboard/API comes up. (WSL-only integration, such as
# /etc/wsl.conf, is covered by the Windows host tests.)
#
#   guest/test-wsl-rootfs.sh dist/guest/wsl2-amd64/opendeploy.wsl
set -eu
IMG="$1"
TAG=opendeploy-guest-test:wsl2
NAME=opendeploy-guest-test
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker import "$IMG" "$TAG" >/dev/null
# The kind marker makes hostd report the data plane as wsl2.
docker run -d --name "$NAME" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
	--tmpfs /run --tmpfs /run/lock --tmpfs /tmp "$TAG" /sbin/init >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
ex() { docker exec "$NAME" "$@"; }

echo "waiting for first-boot setup"
for i in $(seq 1 180); do
	st=$(ex systemctl show -p ActiveState --value opendeploy-guest-setup.service 2>/dev/null || true)
	[ "$st" = active ] && break
	[ "$st" = failed ] && { ex journalctl --no-pager -u opendeploy-guest-setup.service | tail -60; exit 1; }
	sleep 2
done
[ "$st" = active ] || { echo "setup did not finish ($st)"; ex journalctl --no-pager -u opendeploy-guest-setup.service | tail -60; exit 1; }

echo "waiting for the API"
ok=""
for i in $(seq 1 90); do
	if ex curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1; then ok=1; break; fi
	sleep 2
done
if [ -z "$ok" ]; then
	ex systemctl --no-pager --failed || true
	ex journalctl --no-pager -n 200 -u 'opendeploy-*' || true
	exit 1
fi
ex grep -q '^  mode: lan' /etc/opendeploy/node.yaml
ex grep -q 'base_domain: "localhost"' /etc/opendeploy/node.yaml
ex opendeployctl admin bootstrap-token >/dev/null
test "$(ex cat /usr/lib/opendeploy-guest-kind)" = wsl2
for u in hostd auditd secretd artifactd runtimed routemgr egressd platformd caddy; do
	printf '%-10s %s\n' "$u" "$(ex systemctl is-active opendeploy-$u.service || true)"
done
echo "WSL guest rootfs OK"
