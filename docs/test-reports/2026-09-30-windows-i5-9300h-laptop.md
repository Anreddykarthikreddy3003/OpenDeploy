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
Not run yet.

## Test results
| ID | Result | Evidence (command/output or observation) | Time |
|---|---|---|---|

## Findings
| # | Test | Severity | Description | Status |
|---|---|---|---|---|
| F-1 | A-02 | Low (docs); hardening open | install.md said the service account was "log on as a service" only. It is a standard Users member with that right added; nothing denies interactive, network or batch logon. The random, never-stored password is what keeps it from being used. | Docs fixed. Code hardening (deny-logon rights) proposed, waiting on the tester |
| F-2 | A-09 | To be confirmed (W-18) | `uninstall --purge` leaves the account's profile, with the WSL distro registration, and does not unregister the distro. | Open: verify in W-18 |

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
