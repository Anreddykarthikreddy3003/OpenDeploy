# Physical test report: Windows 11 25H2 (Insider build 26220), 2026-09-30

- Commit tested: 31cd606 (fixes, if any, are listed under Findings)
- Machine: Intel Core i5-9300H (4 cores / 8 threads), 32 GB RAM, NVMe SSD
  (Samsung 970, system drive) plus a second NVMe and an HDD; Windows 11 Home
  Single Language, Insider Preview, version 25H2, build 26220.9568; WSL
  2.6.3.0, kernel 6.6.87.2-1
- Tester: the machine's owner with Claude Code
- Verdict: in progress

## Summary
In progress. Part A is done; B0 (tools) is waiting on the tester's approval
to install the missing tools.

## Part A: documentation review

23 claims checked: 21 Confirmed, 2 Wrong. Lines are at commit 31cd606.

| # | Claim | Source | Checked in | Result |
|---|---|---|---|---|
| A-01 | The MSI installs `opendeploy-desktop.exe`, `opendeployctl.exe` and the WSL image under `C:\Program Files\OpenDeploy` | install.md:76 | packaging/windows/opendeploy.wxs:27-41 (`bin\` and `guest\`) | Confirmed; the doc now names the `bin` and `guest` subfolders and the PATH entry |
| A-02 | Service account `opendeploy-svc`: hidden, random password, "log on as a service" **only** | install.md:77 | cmd/opendeploy-desktop/host_windows.go:162-230 | **Wrong.** Hidden (UserList value, :203-206), random 44-character password never stored (:162-173), `SeServiceLogonRight` granted (:210-230). Nothing restricts it to service logon: `NetUserAdd` with `USER_PRIV_USER` (:185) makes it a member of Users, and no deny-logon rights (interactive, network, batch, RDP) are set. The code comment at :24-27 ("no interactive logon") says the same. Doc fixed to state what the code does (finding F-1); hardening proposed |
| A-03 | The service starts at boot without a login | install.md:78 | host_windows.go:282-283 | Confirmed: automatic with delayed start (the doc now says "delayed") |
| A-04 | First start imports the distro into `C:\ProgramData\OpenDeploy\wsl` | install.md:80 | host_windows.go:54; internal/desktop/wsl.go:103-129 | Confirmed |
| A-05 | `opendeploy-desktop status` prints the bootstrap token once running | install.md:81-84 | cmd/opendeploy-desktop/main.go:128-151; internal/desktop/desktop.go:230-233, 252-266 | Confirmed |
| A-06 | Apps are served at `http://<project>.localhost` | install.md:84 | guest/rootfs/common/etc/systemd/system/opendeploy-guest-setup.service:13 (`--domain localhost`) | Confirmed |
| A-07 | The distro has interop, drive automounts and PATH sharing disabled | install.md:86; register Q3 | guest/rootfs/wsl2/etc/wsl.conf:8-14 | Confirmed |
| A-08 | Only the service account and Administrators can access the node data | install.md:86 | host_windows.go:239-257 (protected DACL: SYSTEM, Administrators, service account) | Confirmed; the doc now also names SYSTEM and the folder |
| A-09 | `uninstall --purge` deletes everything | install.md:88-91 | host_windows.go:341-375 | **Wrong in part.** It deletes the account and `%ProgramData%\OpenDeploy`, but never unregisters the distro (`WSL.Unregister`, internal/desktop/wsl.go:222, has no caller) and never deletes the account's profile `C:\Users\opendeploy-svc` (its `.wslconfig` and the registry hive holding the distro registration). `NetUserDel` does not remove profiles. To be confirmed on the machine in W-18 before fixing (finding F-2) |
| A-10 | Apps & features uninstall removes the service and keeps the data | install.md:88 | opendeploy.wxs:54, 58 (`uninstall` without `--purge`, not during upgrades) | Confirmed |
| A-11 | W-17: a downgrade is refused with "A newer version…" | physical-test-plan.md W-17 | opendeploy.wxs:20 | Confirmed |
| A-12 | W-18: the PATH entry is removed on uninstall | physical-test-plan.md W-18 | opendeploy.wxs:34 (`Permanent="no"`) | Confirmed |
| A-13 | W-13: the service restarts after a crash | physical-test-plan.md W-13 | host_windows.go:311-313 (restart after 15 s, 15 s, 60 s; reset after 24 h) | Confirmed in code; tested in W-13 |
| A-14 | B2 is the same as CI's `windows` job | physical-test-plan.md B2 | .github/workflows/package.yml (job `windows`) | Confirmed |
| A-15 | Found and fixed: chained symlinks in a source upload | production-readiness.md:52 | internal/build/builder/builder_test.go:191-230 (`chained-link`, `write-through-link`, `dangling-chain` cases) | Confirmed |
| A-16 | Found and fixed: a rate-limiter flood reset every bucket | production-readiness.md:54 | internal/api/server.go:477-498 (only fully refilled buckets are dropped; fails closed); internal/api/ready_test.go:43 | Confirmed |
| A-17 | Found and fixed: DNS rebinding between the clone-URL check and the fetch; git 2.37 required | production-readiness.md:56 | internal/git/fetch.go:100-124, 225; .goreleaser.yaml:77, 91; packaging/linux/install.sh:62-66 | Confirmed |
| A-18 | Found and fixed: Java builds behind a TLS-inspecting proxy | production-readiness.md:61 | internal/build/detect/ca.go:22-37; internal/build/builder/ca_test.go:74 | Confirmed |
| A-19 | SC-11: loopback by default; a wildcard or non-loopback bind is refused without acknowledged remote admin | register SC-11; configuration.md:28 | internal/config/config.go:247, 377-392; config_test.go:19, 30; packaging/linux/etc/node.yaml:7 | Confirmed |
| A-20 | SC-10: hostd registers exactly the closed op set | register SC-10 | internal/hostd/hostd_test.go:30-40 | Confirmed |
| A-21 | SC-20: the audit log is append-only | register SC-20 | internal/audit/migrations/0001_init.sql:24-26 (update and delete triggers); internal/audit/audit_test.go:74 | Confirmed |
| A-22 | `/readyz` checks auditd, secretd, artifactd, builderd, runtimed, routemgr and hostd | operations.md:23 | internal/services/platformd.go:93-97; internal/api/system.go:158-178 | Confirmed |
| A-23 | Defaults: `dns_resolver` 1.1.1.1:53; limits 100 MiB / 200 rps / 1024 connections; `proxy_listen` 0.0.0.0:3128; registry 127.0.0.1:5010; 10 GiB images; backups `@daily`, `opendeploy/`, 30 days | configuration.md | internal/config/config.go:247-292 | Confirmed |

## Release gate on this hardware (B1)
`sudo scripts/release-gate.sh` as root in the `Ubuntu-24.04` builder distro
(WSL 2.6.3, kernel 6.6.87.2, cgroup v2, Docker 29.1.3 with the containerd
overlayfs snapshotter, gVisor release-20260928.0). The first run found three
defects; the stages they failed were re-run on the fixed commit.

| Stage | Run 1: 2646e5a (31 min) | Run 2: ee7d18a (12 min), `GATE_SNAPSHOTTER=native` |
|---|---|---|
| lint | PASS | not re-run |
| web | PASS | not re-run |
| vuln | PASS | not re-run |
| unit (race, real MinIO) | PASS | not re-run |
| soak | PASS | not re-run |
| e2e (real apps, Pebble ACME) | FAIL: F-5 | PASS |
| adversarial (gVisor, nftables) | FAIL: F-5 | PASS |
| fuzz | PASS | not re-run |
| package (deb, guest image, first boot) | PASS | PASS |
| node (installed systemd node, chaos) | FAIL: F-6, and nested overlayfs on this host | PASS |
| upgrade (baseline f883e2c to this build; broken releases roll back or stop) | FAIL: F-6 | PASS |

The lint, web, vuln, unit, soak and fuzz stages were not re-run after the
fixes. The fixed code (internal/runtime, cmd/opendeploy-desktop,
scripts/release-gate.sh) was covered by gofmt, go vet and its package
tests on Windows and in the builder. `GATE_SNAPSHOTTER=native` is the
gate's documented setting for hosts without nested overlayfs (this host's
Docker stores container filesystems on overlayfs). The Windows MSI is not
a gate stage; it is tested below.

## Test results
| ID | Result | Evidence (command/output or observation) | Time |
|---|---|---|---|

## Findings
| # | Test | Severity | Description | Status |
|---|---|---|---|---|
| F-1 | A-02 | Low (docs and hardening) | install.md said the service account was "log on as a service" only. It is a standard Users member with that right added; nothing denies interactive, network or batch logon. The random, never-stored password is what keeps it from being used. | Docs fixed. Hardening approved by the tester and fixed in bbccbc7: the account is denied interactive, Remote Desktop, network and batch logon, and purge removes its rights (`TestServiceAccountRightsDenyEveryOtherLogon` fails on the old code). To verify on the machine in W-01 and W-18 |
| F-2 | A-09 | To be confirmed (W-18) | `uninstall --purge` leaves the account's profile, with the WSL distro registration, and does not unregister the distro. | Open: verify in W-18 |
| F-3 | code review | Low | `opendeploy-desktop install --data DIR` is not kept across an MSI upgrade. The MSI runs `install` with no flags (opendeploy.wxs:53), and the upgrade path rewrites the service command line with the default `--data` (host_windows.go:287, 298). Status, log and token then move back to `%ProgramData%\OpenDeploy`, and `uninstall --purge` misses the custom folder. | Fixed in 12a53f3: install, upgrade, status, uninstall and purge follow the service's own `--data`, the MSI takes `DATADIR`, unsafe folders are refused, and purge deletes only a folder with the `.opendeploy-data` marker (`TestChooseDataDirFollowsInstalledService`, `TestChooseDataDirRefusesMovingNodeData`, `TestPurgeDeletesOnlyMarkedDataFolder` fail on the old code). To verify on the machine |
| F-4 | code review; to confirm in W-17 | High (upgrades) | An MSI upgrade does not update the node. The new `opendeploy.wsl` is only imported when the distro does not exist yet (internal/desktop/wsl.go:116-128), and the guest's first-boot setup runs only while `/opt/opendeploy/slots/current` is missing (opendeploy-guest-setup.service:4). The node's own TUF updater is off by default (`update.repository_url: ""`, packaging/linux/etc/node.yaml:56) and no TUF root is shipped. So a desktop node keeps its first-installed version and has no working update path. | Open: confirm in W-17 |
| F-5 | B1 gate (e2e, adversarial) | Medium (dev/CI runtime) | The Docker runtime adapter pins Engine API 1.43 (internal/runtime/docker.go:94, 258, 581). Docker Engine 29 (Ubuntu 24.04 docker.io 29.1.3) refuses it: "client version 1.43 is too old. Minimum supported API version is 1.44". `TestDockerIntegration` and `TestNetworkSegmentation` fail, and the e2e stage stops before the deploy suite. Production nodes use containerd and are not affected; `opendeployctl dev` and CI with a current Docker are. | Fixed in ae5534f (the client negotiates the API version, 1.43 to 1.52; `TestDockerAPIVersionNegotiation` and three more fail on the old code). Verified on Docker 29.1.3: `TestDockerIntegration`, `TestNetworkSegmentation` pass. Gate re-run on ee7d18a: e2e and adversarial PASS |
| F-6 | B1 gate (node, upgrade) | Low (test harness) | The gate booted the guest image, slept 3 s, then stopped its first-boot setup unit. On this NVMe host the unit had already installed the image's release (0.0.1-next), so the upgrade stage kept that newer release instead of installing the baseline and upgrading ("keeping the running release 0.0.1-next (newer than 0.0.0-baseline)"). | Fixed in ee7d18a: the unit is masked before boot, and the gate fails if a release is present before its own install. Gate re-run on ee7d18a: node and upgrade PASS |

## Measurements
Not measured yet.

## Not tested and why
Not decided yet.

## Running log
- 2026-09-30, Part A. Read physical-test-plan.md, production-readiness.md,
  README.md, install.md, operations.md, runbooks.md, configuration.md,
  security/register.md and CLAUDE.md, and the whole Windows desktop path
  (opendeploy.wxs, cmd/opendeploy-desktop, internal/desktop). 23 claims
  checked above. install.md fixed for A-01, A-02, A-03 and A-08.
- 2026-09-30, B0. Machine recorded above. The terminal is not elevated.
  Present: Git 2.38.1, Node 24.12.0, WSL 2.6.3.0 with an existing personal
  `Ubuntu` distro (24.04.3) and `docker-desktop`. Missing: Go, .NET 8 SDK,
  WiX. Free disk: C: 27 GB (below the plan's 80 GB), D: 119 GB. No earlier
  OpenDeploy install (no service, account, `%ProgramData%\OpenDeploy` or
  `C:\Program Files\OpenDeploy`). Firmware virtualization reads "False"
  in `Win32_Processor` because Hyper-V is already running
  (`HypervisorPresent: True`); WSL2 distros run, so virtualization works.
- 2026-09-30, B0 tools. The tester installed Go 1.27.0 (go.mod needs
  1.26.6), .NET SDK 8.0.425 and WiX 5.0.2. Disk layout: C: is a 236 GB NVMe
  with 26 GB free; A: is a Samsung 970 NVMe with 235 GB free; D: and E: are
  on an HDD. Everything that can leave C: goes to A:: the builder distro
  `Ubuntu-24.04` (moved from D: with `wsl --manage Ubuntu-24.04 --move
  A:\WSL\Ubuntu-24.04`, after `wsl --shutdown` released the disk) and Go's
  caches (`go env -w GOMODCACHE=A:\go\mod GOCACHE=A:\go\cache`). The node
  itself stays at the MSI's fixed location, `C:\ProgramData\OpenDeploy`,
  because that is the path under test. C: free space is watched through
  the run. The checkout is `D:\MY\OpenDeploy` (`/mnt/d/MY/OpenDeploy` in
  WSL) rather than the plan's `C:\src\OpenDeploy`.
- 2026-09-30, Part A committed after `gofmt -l .` (empty) and
  `go vet ./...` (clean) on Windows.
- 2026-09-30/10-01, B1. Builder distro set up as root (script in the log
  of this session): Go 1.26.6, Node 22.23.3, Caddy 2.11.4, gVisor
  release-20260928.0 (`runsc` registered in Docker), Docker 29.1.3,
  containerd 2.2.1, nftables 1.0.9, git 2.43.0, govulncheck, actionlint,
  goreleaser, pebble. Clone at `/root/OpenDeploy` (2646e5a). The gate runs
  as a systemd transient unit (`systemd-run --unit=od-gate`), because WSL
  ends a session's background processes when `wsl.exe` returns.
  Results so far: lint PASS, web PASS, vuln PASS, unit PASS, soak PASS,
  e2e FAIL (F-5), adversarial FAIL (F-5: `TestMaliciousBuilds`,
  `TestUntrustedBuildSandbox` and `TestContainerdIntegration` pass;
  `TestNetworkSegmentation` fails on the Docker API version).
- 2026-10-01. The tester approved: keep the MSI (a setup.exe wrapper is a
  possible follow-up), a custom data folder chosen at install and followed
  by upgrade, status, uninstall and purge (F-3, with an MSI `DATADIR`
  property), and the F-1 account hardening. The node will be installed
  on A:\OpenDeploy (Samsung NVMe). An update design (signed, per-commit
  channel) waits until after this run.
- 2026-10-01, B1 gate, first full run (2646e5a, 31 minutes):
  lint, web, vuln, unit, soak, fuzz, package PASS; e2e, adversarial FAIL
  (F-5); node, upgrade FAIL. The upgrade failure is F-6. The node stage's
  `deploy/node` failed with `failed to mount rootfs component: invalid
  argument`: Docker here uses the containerd overlayfs snapshotter, so the
  test node's containerd stacks overlayfs on overlayfs. That is a
  limitation of the test host, and the documented setting for it is
  `GATE_SNAPSHOTTER=native`; the real WSL node keeps its data on ext4.
- 2026-10-01. Two parallel agents fixed F-5 (ae5534f) and F-3/F-1
  (12a53f3, bbccbc7); both reviewed and merged. On Windows after the
  merge: `gofmt -l .` empty, `go vet ./...` clean, `go test` of
  internal/desktop, cmd and internal/runtime ok.
- 2026-10-01, B1 step 4 (ee7d18a), in a clean clone `/root/od-build`:
  web build, `goreleaser release --snapshot`, `guest/build.sh --kind wsl2`
  and `guest/test-wsl-rootfs.sh` all passed. Artifacts copied to the
  Windows checkout's `dist\`: `opendeploy_0.0.1-next_linux-amd64.deb`
  (104 MB) and `.rpm`, `opendeployctl_0.0.1-next_windows-amd64.zip`, and
  `guest\wsl2-amd64\opendeploy.wsl` (348 MB, sha256 e6be1b72…d4b22).
- 2026-10-01, B2 (ee7d18a): `opendeploy-desktop.exe version` prints
  0.0.1 and `opendeployctl.exe version` prints 0.0.1-next schema=1.
  `wix build` exit 0; `dist\OpenDeploy-0.0.1-x64.msi`, 356 MB, sha256
  AE1312F8…BD54B33A. Build outputs go under the git-ignored `dist\`
  instead of the plan's `out\`, which is not ignored. The MSI is unsigned.
- 2026-10-01, gate re-run of the failed stages on ee7d18a with
  `GATE_SNAPSHOTTER=native`: e2e PASS, adversarial PASS; package, node and
  upgrade running.
- 2026-10-01, W-01 attempt 1: the tester ran `msiexec /i … DATADIR=A:\OpenDeploy /qn`
  from a non-elevated terminal. Result 1603, "Error 1925. You do not have
  sufficient privileges to complete this installation for all users"
  (a silent per-machine install cannot raise UAC; expected). The rollback
  was clean: no `C:\Program Files\OpenDeploy`, `A:\OpenDeploy`,
  `%ProgramData%\OpenDeploy`, `opendeploy-svc` account, `HKLM\SOFTWARE\OpenDeploy`,
  uninstall entry or PATH entry was left. Re-run from an elevated terminal.
