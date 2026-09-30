# Physical-machine test plan

This plan tests OpenDeploy on a real Windows or macOS computer, as a
customer would use it. The cloud release gate (`scripts/release-gate.sh`)
already proves the Linux node. It cannot prove the parts that need real
hardware:
- the Windows MSI with WSL2;
- the macOS pkg with Virtualization.framework;
- reboots, sleep and network changes;
- the dashboard in a real browser.

The plan is written so that Claude Code on the test machine can carry it out
with a person at the keyboard. The prompt to start it is in
[physical-test-prompt.md](physical-test-prompt.md).

**Outputs**
- A report in `docs/test-reports/`, one per machine and run, using the
  [template](#report-template) at the end of this page.
- A fix, with a regression test, for every real bug found.
- An updated status in [production-readiness.md](production-readiness.md).

## Ground rules

1. **Evidence, not claims.** A test passes only when its pass criterion was
   observed. Record the command and the relevant output, or what was seen on
   screen. "Should work" is not a result.
2. **Four results only:**
   - **PASS**: the criterion was observed.
   - **FAIL**: a defect, with reproduction steps.
   - **BLOCKED**: the machine or the tester cannot run it. Give the reason.
   - **N/A**: does not apply. Give the reason.

   Never mark something PASS to get through the list.
3. **Never weaken a test.** Do not skip, disable or loosen a test, a pass
   criterion or a security control to make a result green. A control that
   fails is a finding.
4. **Fix real bugs properly.** For every FAIL:
   - reproduce it;
   - find the root cause in the code;
   - write a test that fails on the old code;
   - fix it;
   - run the checks in [Fixing a failure](#fixing-a-failure);
   - rebuild and re-run the failed test and everything it could affect.

   Stop and ask the person when a fix would change a security control, an
   API or the on-disk format, or when the root cause is unclear.
5. **Ask before destructive or outward-facing steps.** Examples: uninstalling
   with `--purge`, deleting data, changing firewall or BIOS settings,
   exposing a port to the network, pushing to GitHub. Also ask when the
   person has to act: approve a UAC prompt, scan a TOTP code, reboot, sleep
   the machine, or switch networks.
6. **Secrets stay local.** Never commit the following, or paste them into
   the report:
   - bootstrap tokens, passwords, TOTP secrets or recovery codes;
   - API tokens or backup master keys;
   - the machine's user name, serial numbers or IP addresses.

   Write `<redacted>` instead.

## Part A: Review what exists

Before testing, read these and check their claims against the code:
- [README](../README.md) and [production-readiness.md](production-readiness.md);
- [install.md](install.md), [operations.md](operations.md), [runbooks.md](runbooks.md) and [configuration.md](configuration.md);
- [security/register.md](../security/register.md).

Spot-check at least ten claims. For each one, open the code or test it cites
and confirm that the code does what the document says. Pick at least three
from the "Found and fixed" table and three security controls (SC-xx).

Record each claim as **Confirmed** or **Wrong**, with the file and line. A
wrong or missing document is a finding (docs defect). Fix it in the same
run.

## Part B: Windows 10/11

### B0. Machine and tools

**Requirements**
- Windows 11, or Windows 10 22H2, 64-bit.
- 16 GB RAM or more; 8 GB works slowly.
- 80 GB free disk.
- Virtualization enabled in the firmware (Task Manager → Performance → CPU
  shows "Virtualization: Enabled").
- An administrator account.

**Install the tools** from an administrator PowerShell, then open a new
terminal:
```powershell
winget install -e --id Git.Git
winget install -e --id GoLang.Go            # must be >= the version in go.mod
winget install -e --id OpenJS.NodeJS.LTS    # Node 22 or newer
winget install -e --id Microsoft.DotNet.SDK.8
dotnet tool install --global wix --version 5.0.2
wsl --install --no-distribution             # reboot if asked
wsl --update
wsl --install -d Ubuntu-24.04               # the builder distro (not OpenDeploy's own)
```

Clone the repository to a short path, for example
`C:\src\OpenDeploy`, and check out `main`. The repository's
`.gitattributes` keeps Unix line endings on scripts.

**Where to run Claude Code.** Run it from an administrator terminal in that
folder, because the MSI, the Windows service and WSL management need
elevation. The person approves every command, so they can see exactly what
runs as administrator.

**Record in the report:**
- the Windows edition and build (`winver`);
- the CPU, RAM and disk type;
- the output of `wsl --version`;
- the versions of Go, Node, .NET and WiX;
- the commit tested (`git rev-parse HEAD`).

### B1. Linux build and release gate on this hardware (builder distro)

The Linux node, the `.deb` and the WSL image are built in the
`Ubuntu-24.04` distro. Linux artifacts cannot be built on Windows directly.

1. **Set up the builder.** In `wsl -d Ubuntu-24.04`, as root:
   - Check that systemd is PID 1 (`ps -p 1 -o comm=` prints `systemd`). If it
     does not, set `[boot] systemd=true` in `/etc/wsl.conf` and run
     `wsl --shutdown`.
   - Install the packages:
     ```sh
     apt-get update && apt-get install -y docker.io docker-buildx containerd nftables git make e2fsprogs python3 curl ca-certificates debian-keyring debian-archive-keyring apt-transport-https
     ```
   - Install Go (same version as `go.mod`, from go.dev), Node 22,
     [Caddy](https://caddyserver.com/docs/install#debian-ubuntu-raspbian)
     and [gVisor](https://gvisor.dev/docs/user_guide/install/). Then run
     `runsc install` and `systemctl restart docker`.
   - Install the gate's tools:
     ```sh
     go install golang.org/x/vuln/cmd/govulncheck@latest
     go install github.com/rhysd/actionlint/cmd/actionlint@latest
     go install github.com/goreleaser/goreleaser/v2@latest
     go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
     ```
     Put `~/go/bin` on root's PATH.
2. **Clone into the Linux filesystem.** Use
   `git clone /mnt/c/src/OpenDeploy ~/OpenDeploy`, not a build under
   `/mnt/c`, which is slow and loses file modes. After a fix on the Windows
   side, sync it with
   `git -C ~/OpenDeploy pull /mnt/c/src/OpenDeploy <branch>`, or copy the
   changed files.
3. **Run the release gate on real hardware:** `sudo scripts/release-gate.sh`.
   - Every stage must be PASS or BLOCKED with a reason that is really about
     the WSL kernel, such as a missing kernel feature.
   - Put the summary table in the report.
   - A FAIL is a finding, unless it is an environment problem you can show,
     such as no disk space or no network. In that case fix the environment
     and re-run.
4. **Build the artifacts:**
   ```sh
   cd web && npm ci && npm run build && cd ..
   goreleaser release --snapshot --clean --skip=before,sign,sbom,publish,validate,announce
   sudo guest/build.sh --deb dist/opendeploy_*_linux-amd64.deb --arch amd64 --kind wsl2 --out out/wsl2-amd64
   sudo guest/test-wsl-rootfs.sh out/wsl2-amd64/opendeploy.wsl
   mkdir -p /mnt/c/src/OpenDeploy/dist/guest/wsl2-amd64
   cp dist/opendeployctl_*_windows-amd64.zip /mnt/c/src/OpenDeploy/dist/
   cp out/wsl2-amd64/opendeploy.wsl /mnt/c/src/OpenDeploy/dist/guest/wsl2-amd64/
   ```
   Behind a TLS-inspecting proxy, export `OPENDEPLOY_BUILD_CA_BUNDLE` (and
   `GATE_CA_BUNDLE` for the gate) with the proxy's CA bundle.

### B2. Build the MSI (Windows, PowerShell)

These are the same steps as `.github/workflows/package.yml` (job `windows`).
Use version `0.0.1` for the first build.

```powershell
go test -count=1 ./internal/desktop/... ./cmd/opendeploy-desktop/...
go build -trimpath -ldflags "-s -w -X main.version=0.0.1" -o out/bin/opendeploy-desktop.exe ./cmd/opendeploy-desktop
$zip = Get-ChildItem dist/opendeployctl_*_windows-amd64.zip | Select-Object -First 1
Expand-Archive $zip.FullName -DestinationPath out/ctl -Force
Copy-Item out/ctl/bin/opendeployctl.exe out/bin/
./out/bin/opendeploy-desktop.exe version
wix build -arch x64 -d Version=0.0.1 -d BinDir=out\bin -d GuestDir=dist\guest\wsl2-amd64 packaging\windows\opendeploy.wxs -o out\OpenDeploy-0.0.1-x64.msi
```

The MSI is unsigned, so SmartScreen may warn. That is expected until
Authenticode signing is set up; record it but do not count it as a failure.

### B3. Windows test cases

Run them in order; later cases depend on earlier ones. "Admin PS" means an
administrator PowerShell.

| ID | Test | Pass criterion |
|---|---|---|
| W-01 | **Install.** Admin PS: `msiexec /i out\OpenDeploy-0.0.1-x64.msi /qn /l*v msi-install.log`. Also do one run through the normal UI on a later reinstall. | Exit code 0. `Get-Service OpenDeploy` shows it running and automatic. The service runs as `.\opendeploy-svc`. `Get-LocalUser opendeploy-svc` exists and the account is not in Administrators (`Get-LocalGroupMember Administrators`). `opendeployctl` is on PATH in a new terminal. |
| W-02 | **First start.** `opendeploy-desktop status`, repeated until running. Time it. | Reports `running` within 15 minutes; record the time. Prints a bootstrap token. `%ProgramData%\OpenDeploy\status.json` exists. |
| W-03 | **Data protection.** `icacls` on `%ProgramData%\OpenDeploy` and on its `wsl` folder. From a normal, non-admin user, try to read the files. | Only SYSTEM, Administrators and `opendeploy-svc` have access. A normal user is denied. |
| W-04 | **Loopback only.** `Get-NetTCPConnection -State Listen` for ports 8080, 80 and 443. From another device on the same network, open `http://<this-pc-ip>:8080`. `Get-NetFirewallRule` for rules mentioning OpenDeploy. | Listeners are on 127.0.0.1 or ::1 only. The other device cannot connect. The MSI created no inbound firewall rules. |
| W-05 | **Owner setup and MFA.** Open http://127.0.0.1:8080 in Edge or Chrome and create the owner with the token. | MFA enrolment is forced. The person enrols TOTP with an authenticator app, and recovery codes are shown once. The token no longer works after use: a second bootstrap attempt is refused. |
| W-06 | **Login security.** Log out, then: <br>1. log in with a wrong password; <br>2. log in with the right password and a wrong TOTP code; <br>3. log in with the right code; <br>4. try one recovery code. | 1 and 2 are refused. 3 works. The used recovery code cannot be used again. Repeated failures lock the account (then wait or unlock as the runbook says). |
| W-07 | **Dashboard walkthrough.** Visit every page and settings tab, in light and dark mode and in a narrow window. Watch the browser console (F12). | Nothing is broken or empty-by-error. The console shows no errors. The layout works at narrow width. List any cosmetic issues separately as minor. |
| W-08 | **CLI.** Create an API token in the dashboard. Then run `opendeployctl login --url http://127.0.0.1:8080 --token <token>`, `opendeployctl projects` and `opendeployctl help`. | Login succeeds and commands work. A viewer-role token cannot deploy (403). |
| W-09 | **Deploy every runtime.** For each of `static`, `node`, `python`, `go` and `java` under `tests\e2e\fixtures`, run `opendeployctl upload e2e-<name> tests\e2e\fixtures\<name>`. Time the first build. | Each deploy succeeds. `http://e2e-<name>.localhost` serves the app in the browser and with `curl.exe`. Build and runtime logs show in the dashboard. |
| W-10 | **Redeploy and rollback.** `opendeployctl env set e2e-node GREETING=v2`, then redeploy (`opendeployctl upload e2e-node …`). Then roll back, once from the dashboard and once with `opendeployctl rollback <deployment>`. | The new version is served after the deploy, and the old one keeps serving until then. After rollback the old response returns. The secret value is never shown in logs or in the UI after saving. |
| W-11 | **Isolation from Windows.** Admin PS: `wsl -l -v` (as the service account's distro this may not be listed; record it). From inside a deployed app, try to reach Windows: <br>- a test listener on the host, e.g. `python -m http.server 9999` on Windows; <br>- `/mnt/c`; <br>- `cmd.exe`. <br>If there is no documented way to run commands in an app container, make a small fixture app that tries these and reports the results over HTTP. | The app cannot see Windows drives or run Windows programs. Record whether the host listener is reachable. Unexpected reachability is a security finding: compare it with the egress policy in `docs/configuration.md`. |
| W-12 | **Reboot without login.** Restart Windows and wait 5 minutes at the lock screen without logging in. From another device this cannot be checked, so log in afterwards and check the service start time and the app uptime. | The service started at boot, before login. All apps serve within 5 minutes of login, with no user action. |
| W-13 | **Crash recovery.** <br>1. Admin PS: `Stop-Process -Name opendeploy-desktop -Force`. <br>2. Later, `wsl --shutdown`. | After each, the service and the node come back by themselves and the apps serve again. Record how long it took. If the service does not restart after a process kill, that is a finding (check the service's failure actions with `sc.exe qfailure OpenDeploy`). |
| W-14 | **Sleep and resume.** Sleep the machine for 10 minutes, then resume. Hibernate too, if enabled. | Apps serve and the dashboard works after resume. The node's clock is right: TOTP login still works. |
| W-15 | **Network changes.** Switch Wi-Fi to a phone hotspot, or connect and disconnect a VPN, then redeploy. | Builds can still fetch dependencies. Apps and the dashboard keep working. |
| W-16 | **Backup and restore.** Configure a backup (a local directory target, `backup.local_dir`, or S3). Run "Back up now". Export the master key. Then restore onto a fresh install, as in runbook R5. | The backup completes and the restore brings back the owner, projects, apps and secrets. The audit chain verifies (Audit page in the dashboard). If there is no supported way to configure backups on the desktop edition, record that as a finding with a proposal. |
| W-17 | **Upgrade.** Build a second MSI with version `0.0.2` (B2 with a new version; rebuild the deb and guest if the node changed), then install it over 0.0.1. Afterwards, install 0.0.1 again. | Data, the owner, projects and apps survive, and the service runs 0.0.2. The downgrade is refused with "A newer version…". |
| W-18 | **Uninstall, reinstall, purge.** <br>1. Uninstall from Apps & features. <br>2. Reinstall. <br>3. After asking the person: Admin PS `opendeploy-desktop uninstall --purge`, then uninstall the MSI. | After 1, the service is gone and data is kept. After 2, the old data is back. After 3: <br>- no service; <br>- no OpenDeploy distro in `wsl -l` for any account; <br>- no `%ProgramData%\OpenDeploy`; <br>- no `C:\Program Files\OpenDeploy`; <br>- the PATH entry is removed. <br>Record whether `opendeploy-svc` is removed. |
| W-19 | **Resources.** With 5 apps idle for 30 minutes, check the memory and CPU of `vmmem`/`VmmemWSL` and the virtual disk size. | Record the numbers; the node must stay responsive. Idle CPU near 0%. |
| W-20 | **Windows security tools.** Microsoft Defender scan of `C:\Program Files\OpenDeploy`. Check the Event Viewer (Application and System) for OpenDeploy errors. | No detections. No repeating errors (list any). |

## Part C: macOS 13+ (Apple silicon or Intel)

1. **Tools.**
   - Xcode command-line tools (`xcode-select --install`), Go, Node 22.
   - Docker Desktop or another Docker engine, for the guest image.
   - `brew install e2fsprogs` (the guest build needs `mkfs.ext4`).
2. **Build.**
   - The VM image: `guest/build.sh --kind vz --arch arm64` (or `amd64` on
     Intel). If it cannot be built on the Mac, build it on the Windows
     builder distro above or any Linux host and copy `out/vz-<arch>` over.
   - The pkg: follow the `macos` job in `.github/workflows/package.yml`:
     - build `opendeploy-desktop` with `CGO_ENABLED=1`;
     - take `opendeployctl` from `dist/opendeployctl_*_darwin-<arch>.tar.gz`;
     - run `packaging/macos/build-pkg.sh`.

     Without a Developer ID, the build is signed ad hoc, which is fine
     locally.
3. **Test cases.** Run the same cases as Windows as M-01…M-20, with these
   substitutions:
   - install with `sudo installer -pkg …`;
   - check the service with `sudo launchctl print system/io.github.anreddykarthikreddy3003.opendeploy.desktop`;
   - check status with `sudo opendeploy-desktop status`;
   - check file protection on `/Library/Application Support/OpenDeploy`
     (root only);
   - check listeners with `lsof -iTCP -sTCP:LISTEN`;
   - in the reboot test, use FileVault's pre-boot login;
   - for resources, change them with
     `sudo opendeploy-desktop install --cpus N --memory M`;
   - uninstall with `/Library/OpenDeploy/uninstall.sh` and then
     `uninstall.sh --purge`.

   Gatekeeper warnings on the unsigned pkg are expected until notarization
   is set up.

## Part D: Optional, with real services

These need the person's accounts. Skip them (N/A) if they are not
available.

- **D-01 GitHub App.** Platform → GitHub, create the App from the manifest,
  and import a repository. A push deploys automatically. A pull request
  gets a preview. A pull request from a fork is refused until the sandbox
  is available.
- **D-02 Public access through a relay** (`docs/relay.md`), with a custom
  domain and a Let's Encrypt certificate.
- **D-03 S3 with object lock** for backups, with the policy from
  `tests/s3/minio.sh`. The node's credentials cannot delete a backup.

## Fixing a failure

1. Reproduce the failure, then find the root cause in the code.
2. Write a regression test: a Go test next to the code, or an integration
   test under `tests/`. It must fail before the fix.
3. Fix the code, and update the documentation if it was wrong.
4. Run the checks:
   - On Windows:
     ```powershell
     gofmt -l .
     go vet ./...
     go test ./internal/desktop/... ./cmd/...
     ```
     `gofmt -l .` must print nothing.
   - In the builder distro: `go test -race ./...`, plus the affected
     `scripts/release-gate.sh` stages.
5. Rebuild the MSI or pkg, reinstall, and re-run the failed case and every
   case it could affect.
6. Commit one fix per commit, with a message that names the test ID, e.g.
   `desktop: restart the service after a crash (W-13)`.

## Report template

Save the report as
`docs/test-reports/<YYYY-MM-DD>-<windows|macos>-<short-machine-label>.md`.
Also update the "Physical desktops" item in
[production-readiness.md](production-readiness.md) with the date, the
result and a link to the report.

```markdown
# Physical test report: <Windows 11 23H2 | macOS 15.x>, <date>

- Commit tested: <sha> (and the commit after fixes, if any)
- Machine: <CPU>, <RAM>, <disk>; <OS build>; WSL <version> / macOS <version>
- Tester: <person> with Claude Code
- Verdict: PASS | PASS WITH FINDINGS | FAIL

## Summary
<3–6 sentences: what was tested, what failed, what was fixed, what is left.>

## Part A: documentation review
| Claim | Source | Checked in | Result |
|---|---|---|---|

## Release gate on this hardware (B1)
<The gate's summary table.>

## Test results
| ID | Result | Evidence (command/output or observation) | Time |
|---|---|---|---|

## Findings
| # | Test | Severity | Description | Status (fixed in <sha> / open) |
|---|---|---|---|---|

## Measurements
First install to running: … · First build per runtime: … · Idle memory/CPU: … · Disk: …

## Not tested and why
<Everything BLOCKED or N/A, with the reason.>
```
