#!/bin/sh
# OpenDeploy release gate, runnable on any Linux host: everything the ci,
# e2e, security-gate and package workflows prove, without GitHub.
#
#   sudo scripts/release-gate.sh                 # every stage
#   sudo scripts/release-gate.sh unit e2e        # selected stages
#
# Stages: lint web vuln unit soak e2e adversarial fuzz package node upgrade
#
# Host requirements (the gate checks and reports each as BLOCKED, never as
# passed): root, Go, Node 22, Docker with the runsc (gVisor) runtime, a
# system containerd at /run/containerd/containerd.sock, nftables, caddy,
# git >= 2.37, and on PATH: govulncheck, actionlint, goreleaser, pebble.
# The Windows MSI, macOS pkg and QEMU/KVM guest boot need those platforms
# and are covered by .github/workflows/package.yml only.
#
# Environment:
#   GATE_FUZZTIME     per fuzz target (default 20s)
#   GATE_CA_BUNDLE    PEM bundle of a TLS-inspecting proxy; passed to guest
#                     image builds and installed on the test node
#   GATE_SNAPSHOTTER  containerd snapshotter for the test node (e.g. native
#                     on hosts where nested overlayfs is unavailable)
#   GATE_BASELINE     release to upgrade from (default: latest v* tag, else
#                     the first packaged release candidate)
set -u
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
ROOT=$(pwd)
OUT=${GATE_OUT:-$ROOT/.gate}
mkdir -p "$OUT"
FUZZTIME=${GATE_FUZZTIME:-20s}
BASELINE_DEFAULT=f883e2c2f00a66d5276dea4327ad6478290c2b14
export OPENDEPLOY_REQUIRE_CAPS=1
# Behind a TLS-inspecting proxy, builds trust its CA (as build.ca_bundle).
[ -z "${GATE_CA_BUNDLE:-}" ] || export OPENDEPLOY_BUILD_CA_BUNDLE="$GATE_CA_BUNDLE"
RESULTS=""

say() { printf '\n==> %s\n' "$*"; }
record() { RESULTS="$RESULTS$1 $2${3:+ ($3)}
"; }
have() { command -v "$1" >/dev/null 2>&1; }
# run STAGE: executes stage_STAGE, logging to .gate/STAGE.log.
run() {
	say "stage $1"
	log="$OUT/$1.log"
	blocked=""
	if ! blocked=$(check_"$1" 2>&1); then
		echo "BLOCKED: $blocked"
		record BLOCKED "$1" "$blocked"
		return
	fi
	# Not as an if condition: sh ignores set -e there, even in a subshell,
	# and the stage would only report its last command.
	( set -e; stage_"$1" ) >"$log" 2>&1
	rc=$?
	if [ $rc -eq 0 ]; then
		record PASS "$1"
		echo "PASS ($log)"
	else
		record FAIL "$1" "see $log"
		tail -n 40 "$log"
		echo "FAIL ($log)"
	fi
}
need() { for c in "$@"; do have "$c" || { echo "missing $c"; return 1; }; done; }
need_root() { [ "$(id -u)" -eq 0 ] || { echo "run as root"; return 1; }; }
need_docker() { docker info >/dev/null 2>&1 || { echo "docker daemon unavailable"; return 1; }; }

# ---------------------------------------------------------------- stages

check_lint() { need go actionlint; }
stage_lint() {
	bad=$(gofmt -l $(git ls-files '*.go'))
	[ -z "$bad" ] || { echo "gofmt: $bad"; exit 1; }
	go vet ./...
	for tag in soak e2e pkginstall adversarial; do go vet -tags "$tag" ./tests/...; done
	actionlint .github/workflows/*.yml
	for f in $(git ls-files '*.sh'); do sh -n "$f"; done
}

check_web() { need node npm; }
stage_web() {
	cd web
	npm ci --no-audit --no-fund
	npm test
	npm run build
	npm audit --omit=dev --audit-level=high
}

check_vuln() { need govulncheck; }
stage_vuln() { govulncheck ./...; }

check_unit() { need_root && need_docker; }
stage_unit() {
	eval "$(tests/s3/minio.sh)"
	trap 'tests/s3/minio.sh stop' EXIT
	go test -race -count=1 ./...
}

check_soak() { need go; }
stage_soak() { go test -tags soak -count=1 -timeout 30m -run TestSoak -v ./tests/integration/; }

check_e2e() { need_root && need_docker && need caddy pebble; }
stage_e2e() {
	OPENDEPLOY_DOCKER_TESTS=1 go test -count=1 -run Docker ./internal/runtime/ ./internal/build/builder/
	go test -tags e2e -count=1 -timeout 40m -v ./tests/e2e/
}

check_adversarial() {
	need_root && need_docker && need nft || return 1
	docker info --format '{{json .Runtimes}}' | grep -q runsc || { echo "docker has no runsc runtime (runsc install; restart dockerd)"; return 1; }
	[ -S /run/containerd/containerd.sock ] || { echo "no system containerd at /run/containerd/containerd.sock"; return 1; }
}
stage_adversarial() {
	OPENDEPLOY_CONTAINERD_TESTS=1 OPENDEPLOY_CONTAINERD_SOCKET=/run/containerd/containerd.sock go test -count=1 -run Containerd -v ./internal/runtime/
	# (no pipes: POSIX sh has no pipefail, and a pipe would hide the status)
	rc=0
	go test -tags adversarial -count=1 -v ./tests/adversarial/ >"$OUT/adversarial-suite.log" 2>&1 || rc=$?
	cat "$OUT/adversarial-suite.log"
	[ $rc -eq 0 ]
	! grep -q CAPABILITY-BLOCKED "$OUT/adversarial-suite.log"
	go test -race -count=1 ./internal/relay/ ./internal/domains/
	go test -race -count=1 -run 'Domain|RelayMode' ./internal/platform/
}

check_fuzz() { need go; }
stage_fuzz() {
	grep -rl --include='*_test.go' '^func Fuzz' internal | while read -r f; do
		pkg=./$(dirname "$f")
		for name in $(grep -o '^func Fuzz[A-Za-z0-9_]*' "$f" | sed 's/func //'); do
			echo "--- $name ($pkg)"
			if ! go test -run '^$' -fuzz "^${name}\$" -fuzztime "$FUZZTIME" "$pkg" >"$OUT/fuzz-$name.log" 2>&1; then
				# Time budget ending during minimization is not a finding.
				if grep -q 'Failing input written to' "$OUT/fuzz-$name.log" || ! grep -q 'context deadline exceeded' "$OUT/fuzz-$name.log"; then
					cat "$OUT/fuzz-$name.log"; exit 1
				fi
			fi
		done
	done
}

check_package() { need_root && need_docker && need goreleaser; }
stage_package() {
	[ -f web/dist/index.html ] || (cd web && npm ci --no-audit --no-fund && npm run build)
	# linux/amd64 only (the arm64, Windows and macOS builds run in CI).
	sed -e 's/goarch: \[amd64, arm64\]/goarch: [amd64]/g' -e 's/goos: \[linux, darwin, windows\]/goos: [linux]/' .goreleaser.yaml >"$OUT/goreleaser.yaml"
	goreleaser release --snapshot --clean --config "$OUT/goreleaser.yaml" --skip=before,sign,sbom,publish,validate,announce
	deb=$(ls dist/opendeploy_*_linux-amd64.deb)
	dpkg-deb -I "$deb" | grep -q 'git (>= 1:2.37)'
	dpkg-deb -c "$deb" | grep -q './usr/lib/opendeploy/release/packaging/linux/install.sh'
	OPENDEPLOY_BUILD_CA_BUNDLE=${GATE_CA_BUNDLE:-} guest/build.sh --deb "$deb" --arch amd64 --kind wsl2 --out dist/guest/wsl2-amd64
	if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
		guest/test-wsl-rootfs.sh dist/guest/wsl2-amd64/opendeploy.wsl
	else
		echo "guest first-boot test needs a cgroup v2 host; covered by the node stage"
	fi
}

# The node and upgrade stages run the package's installer on a systemd node
# (the guest image booted as a privileged container).
check_node() {
	need_root && need_docker || return 1
	[ -f dist/guest/wsl2-amd64/opendeploy.wsl ] || { echo "run the package stage first"; return 1; }
}
NODE=od-gate-node
R=/usr/lib/opendeploy/release
node_up() {
	docker rm -f $NODE >/dev/null 2>&1 || true
	docker import dist/guest/wsl2-amd64/opendeploy.wsl od-gate-node:latest >/dev/null
	docker create --name $NODE --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
		--tmpfs /run --tmpfs /run/lock --tmpfs /tmp od-gate-node:latest /sbin/init >/dev/null
	# The gate installs the release itself, so mask the image's first-boot
	# setup before systemd starts: stopping it after boot races with it, and
	# on a fast host it has installed the release before the gate can.
	mask=$(mktemp -d)
	mkdir -p "$mask/etc/systemd/system"
	ln -s /dev/null "$mask/etc/systemd/system/opendeploy-guest-setup.service"
	tar -C "$mask" -cf - etc | docker cp - $NODE:/
	rm -rf "$mask"
	docker start $NODE >/dev/null
	sleep 3
	docker exec $NODE chmod 666 /dev/net/tun
	if docker exec $NODE test -e /opt/opendeploy/slots/current; then
		echo "a release was installed on the test node before the gate installed one"; exit 1
	fi
	go test -tags pkginstall -c -o "$OUT/pkg.test" ./tests/package/
	docker exec $NODE mkdir -p /root/tests/package /root/tests/e2e
	docker cp tests/e2e/fixtures $NODE:/root/tests/e2e/
	docker cp "$OUT/pkg.test" $NODE:/root/tests/package/pkg.test
}
# node_patch adapts the installer to this test host only: a cgroup v1 host
# cannot give the node cgroup v2, which install.sh (correctly) requires.
node_patch() {
	if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
		echo "NOTE: cgroup v1 test host: skipping install.sh's cgroup v2 check on the test node"
		docker exec $NODE sed -i 's|^\[ -f /sys/fs/cgroup/cgroup.controllers \] \|\| die "cgroup v2 is required"|: # gate: cgroup v1 test host|' $R/packaging/linux/install.sh
	fi
}
node_install() { # [install.sh args]
	ca=""
	if [ -n "${GATE_CA_BUNDLE:-}" ]; then docker cp "$GATE_CA_BUNDLE" $NODE:/root/ca.pem; ca="--ca-bundle /root/ca.pem"; fi
	docker exec $NODE $R/packaging/linux/install.sh --no-start --mode lan --domain localhost $ca "$@"
	if [ -n "${GATE_SNAPSHOTTER:-}" ]; then
		docker exec $NODE sed -i "s|^  # containerd_snapshotter:.*|  containerd_snapshotter: $GATE_SNAPSHOTTER|" /etc/opendeploy/node.yaml
	fi
	docker exec $NODE systemctl restart opendeploy.target
	# Releases before /readyz (404) are waited for on /healthz.
	docker exec $NODE sh -c 'for i in $(seq 1 120); do
		c=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/readyz)
		[ "$c" = 200 ] && exit 0
		[ "$c" = 404 ] && curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1 && exit 0
		sleep 1
	done; exit 1'
}
pkgtest() { docker exec -w /root/tests/package -e OPENDEPLOY_BASE_DOMAIN=localhost -e OPENDEPLOY_REQUIRE_CAPS=1 -e OPENDEPLOY_PKG_STATE=/root/owner.json $NODE ./pkg.test -test.v "$@"; }
stage_node() {
	trap 'docker rm -f $NODE >/dev/null 2>&1 || true' EXIT
	node_up
	node_patch
	node_install
	pkgtest -test.run TestInstalledNode
	# Re-install upgrades into the other slot and keeps state.
	docker exec $NODE $R/packaging/linux/install.sh --force
	docker exec $NODE sh -c 'readlink /opt/opendeploy/slots/current | grep -qx b && curl -fsS -H "Host: static.localhost" http://127.0.0.1/ | grep -q "hello from static"'
	# Removal stops the node and keeps its data.
	docker exec $NODE dpkg -r opendeploy
	docker exec $NODE sh -c '! systemctl is-active --quiet opendeploy-platformd.service && test -d /var/lib/opendeploy/platformd'
}

check_upgrade() { check_node; }
stage_upgrade() {
	trap 'docker rm -f $NODE >/dev/null 2>&1 || true; git worktree remove --force "$OUT/baseline" 2>/dev/null || true' EXIT
	base=${GATE_BASELINE:-$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo $BASELINE_DEFAULT)}
	echo "upgrading from $base"
	git worktree remove --force "$OUT/baseline" 2>/dev/null || true
	git worktree add -f "$OUT/baseline" "$base"
	mkdir -p "$OUT/baseline/web/dist" && cp -r web/dist/. "$OUT/baseline/web/dist/"
	(cd "$OUT/baseline" && make build VERSION=0.0.0-baseline)
	make build VERSION=0.0.1-gate
	stage_rel() { # DIR: put a release payload where the package puts it
		docker exec $NODE rm -rf $R/bin $R/packaging
		docker exec $NODE mkdir -p $R/packaging
		docker cp "$1/bin" $NODE:$R/bin
		docker cp "$1/packaging/linux" $NODE:$R/packaging/linux
		node_patch
	}
	node_up
	stage_rel "$OUT/baseline"
	node_install
	docker exec $NODE sh -c 'for i in $(seq 1 90); do test -S /run/opendeploy/egressd.sock && break; sleep 1; done'
	pkgtest -test.run 'TestInstalledNode/^(units|deploy)$/^static$'
	stage_rel .
	docker exec $NODE $R/packaging/linux/install.sh
	docker exec $NODE sh -c 'opendeployctl version | grep -q 0.0.1-gate && readlink /opt/opendeploy/slots/current | grep -qx b'
	pkgtest -test.run TestUpgradedNode
	for schema in 1 2; do
		rm -rf "$OUT/broken" && mkdir -p "$OUT/broken" && cp -r bin packaging "$OUT/broken/"
		printf '#!/bin/sh\nexit 1\n' >"$OUT/broken/bin/platformd"
		mv "$OUT/broken/bin/opendeployctl" "$OUT/broken/bin/opendeployctl.real"
		printf '#!/bin/sh\nif [ "${1:-}" = version ]; then echo "opendeployctl 9.9.%s-broken schema=%s"; exit 0; fi\nexec "$(dirname "$0")/opendeployctl.real" "$@"\n' $schema $schema >"$OUT/broken/bin/opendeployctl"
		chmod +x "$OUT/broken/bin/platformd" "$OUT/broken/bin/opendeployctl"
		stage_rel "$OUT/broken"
		if docker exec -e OPENDEPLOY_READY_TIMEOUT=25 $NODE $R/packaging/linux/install.sh >"$OUT/broken-$schema.log" 2>&1; then
			echo "a release that never became ready was accepted"; exit 1
		fi
		cat "$OUT/broken-$schema.log"
		if [ $schema = 1 ]; then
			grep -q "rolled back" "$OUT/broken-$schema.log"
			docker exec $NODE sh -c 'readlink /opt/opendeploy/slots/current | grep -qx b && curl -fsS http://127.0.0.1:8080/readyz'
		else
			grep -q "automatic rollback is unsafe" "$OUT/broken-$schema.log"
			docker exec $NODE sh -c 'readlink /opt/opendeploy/slots/current | grep -qx a'
		fi
		docker exec $NODE sh -c 'curl -fsS -H "Host: static.localhost" http://127.0.0.1/ | grep -q "hello from static"'
	done
}

# ---------------------------------------------------------------- main

ALL="lint web vuln unit soak e2e adversarial fuzz package node upgrade"
STAGES=${*:-$ALL}
for s in $STAGES; do
	case " $ALL " in *" $s "*) run "$s" ;; *) echo "unknown stage $s"; exit 2 ;; esac
done
say "summary"
printf '%s' "$RESULTS"
echo "not covered here (CI only): Windows MSI, macOS pkg, arm64 builds, QEMU/KVM guest boot"
! printf '%s' "$RESULTS" | grep -q '^FAIL\|^BLOCKED'
