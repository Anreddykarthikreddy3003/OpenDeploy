# Production readiness

OpenDeploy is feature-complete against the PRD, and every release-gate
workflow is green. This page says what is proven and how, what the
readiness pass found and fixed, and what still depends on things outside
the repository. Its verdict is **release-candidate quality**. General
availability waits on the items in [Before general availability](#before-general-availability).

## Running the release gate anywhere

`sudo scripts/release-gate.sh` runs, on any Linux host, everything the CI
workflows below prove. Each stage reports PASS, FAIL or BLOCKED; a stage
the host cannot run is reported as BLOCKED, never as passed. The stages are:
lint, web, vulnerabilities, unit and integration (real MinIO), soak, e2e
(real apps and Pebble), adversarial (gVisor, nftables), fuzz, the deb
package and guest image, an installed systemd node, and upgrade/rollback.
Only the Windows MSI, the macOS pkg, arm64 builds and the QEMU/KVM guest
boot need other platforms (CI).

For hosts behind a TLS-inspecting proxy, set `GATE_CA_BUNDLE`. For hosts
without nested overlayfs, set `GATE_SNAPSHOTTER=native`.

Latest full run: all 11 stages PASS, on an Ubuntu 24.04 cloud container
behind a TLS-inspecting proxy with a cgroup v1 kernel. On that host the test
node skips install.sh's cgroup v2 check, and says so in the log.

## What CI proves on every push

Every workflow below is a release gate (`release.yml` calls it). CI sets
`OPENDEPLOY_REQUIRE_CAPS=1`, so a proof test that cannot run on the
runner fails the build instead of skipping (`internal/testcap`).

| Area | Proof | Workflow |
|---|---|---|
| Unit and integration | `go test -race ./...`, including the full stack with real IPC services and the auth, RBAC and MFA flows. | ci |
| Backups | Backup through the job queue to real S3 (MinIO) with compliance-mode object lock, and restore onto a clean node. Neither the node's credentials nor the storage administrator can delete a locked backup. | ci (`tests/s3/minio.sh`) |
| Resource leaks | Soak smoke: rounds of concurrent deploys, supersession bursts and a duplicated webhook storm. Goroutines, file descriptors, heap and DB growth stay bounded; the queue converges; one live workload per environment. | ci; `soak.yml` runs a long version nightly |
| Real deployments | Node, Python, Go, Java and static apps built with BuildKit, run hardened and served through a real Caddy edge. | e2e |
| HTTPS | A custom domain is claimed and proven through an authoritative DNS server. Let's Encrypt's test CA (Pebble) validates it over HTTP-01 against Caddy, and the node serves a certificate chaining to that CA. HTTP redirects to HTTPS, and detaching the domain stops serving it. | e2e (`acme_test.go`) |
| Isolation (ST-01..ST-12) | Malicious builds, the gVisor build sandbox, network segmentation with nftables, relay isolation, domain takeover attempts. | security-gate |
| Supply chain | govulncheck (reachable vulnerabilities), npm audit, fuzzing of every parser that takes outside input. | security-gate |
| Installed package | The deb on a real systemd host: services run under their own identities, `/readyz` is green, apps deploy through rootless BuildKit, containerd and Caddy, and the chaos sequence passes. Reinstalling, upgrading into the other slot and removing are also tested. | package: deb-install |
| Upgrades | The previous release (latest `v*` tag) is installed with live data and upgraded to this build. The owner still logs in with password and TOTP; projects, apps and the audit chain survive; the node still deploys. A release that never becomes ready is rolled back automatically. One that may have migrated the schema is stopped for the operator (runbook R4). | package: upgrade |
| Desktop | The WSL2 and VM guest images boot under systemd and QEMU/KVM. The Windows MSI and the macOS pkg install and uninstall. | package |

## Found and fixed by this readiness pass

Each fix has a regression test that fails against the old code.

| Finding | Severity | Fix |
|---|---|---|
| A crafted source upload (Developer role) could write outside the source tree as builderd, through chained symlinks (`d -> .`, `e -> d/..`). | High | Extraction never writes through a symlink. Each symlink is resolved against the finished tree, and a link that escapes is rejected even if its target does not exist yet. |
| MFA could be bypassed with only a password, three ways. <br>1. Brute-force or replay of `/auth/totp/confirm` from a pre-MFA session. <br>2. Enrolling TOTP on a key-only account. <br>3. A pending session became a full one when TOTP was disabled or re-enrolled. | High | Factor changes need an MFA-verified, re-authenticated session and sign out other sessions. Confirmation is rate-limited, lockable and replay-checked. |
| Flooding the rate limiter with new keys reset every bucket, including the MFA throttle. | Medium | Only fully refilled buckets are forgotten; a flood fails closed. |
| A locked account answered differently for the right password, confirming guesses. Second-factor failures never locked. | Medium | The lock is checked first. Second-factor failures count towards it. |
| Clone URLs were resolved to check for SSRF, then git resolved them again (DNS rebinding). | Medium | The fetch is pinned to the validated addresses (`http.curloptResolve`). The package requires git 2.37 or later, and fetches fail closed on older git. |
| Object-lock uploads carried no checksum. AWS S3 rejects that; MinIO does not. | Medium | Uploads send a signed payload hash, `Content-MD5` and `x-amz-checksum-sha256`. |
| A package upgrade switched slots without checking the result, so a bad release left the node down. | Medium | Upgrades gate on the new `/readyz`, with the rollback rules described above. |
| Old generations kept running forever if platformd restarted during the in-process drain delay. | Medium | The reconciler drains replaced generations durably. |
| A deploy submitted while egressd was restarting failed permanently. | Low | It is retried, and still fails closed. |
| Behind a TLS-inspecting proxy, Java builds (Maven, Gradle) failed even with `build.ca_bundle`: the JVM ignores `SSL_CERT_FILE`. | Medium | Generated steps import the extra CAs into a throwaway JDK trust store (`TestDockerBuildTrustsBuildCA`, e2e Java). |
| With `build.ca_bundle` set, every untrusted (gVisor) build failed: the sandbox refused the CA, which is attached as a build secret, and its BuildKit could not pull through the proxy. | High (for proxied networks) | The CA bundle is the only secret allowed into the sandbox; real secrets are still refused (`TestUntrustedBuildSandbox`). |
| An owner's MFA reset left security keys and recovery codes. Account-recovery actions left API tokens valid. Read-only tokens could revoke sessions. The remote-admin gate failed open on an unparsable client address. | Low–Medium | Fixed. |

## Before general availability

These need people, credentials or hardware. The repository has the hooks
and the documentation for each.

1. **Signing.** Set up Authenticode (Windows) and an Apple Developer ID
   with notarization (macOS), plus the offline TUF root ceremony
   (`tools/opendeploy-release`, register Q43). Then tag `v0.1.0-rc1`;
   `release.yml` produces signed installers and a signed update channel.
2. **Real services.** Register a GitHub App, set up a relay host with a
   wildcard DNS record, and an S3 bucket with object lock and a
   delete-denied node user (`tests/s3/minio.sh` shows the policy). Run the
   smoke checklist in [install](install.md) on a real VPS with a public
   domain and Let's Encrypt.
3. **Physical desktops.** Install once on Windows (WSL2) and once on a Mac
   (Virtualization.framework). Hosted CI runners cannot run nested
   virtualization, so there the desktop packages only prove that they
   install and report their status. Follow the
   [physical test plan](physical-test-plan.md); the results go in
   [test-reports](test-reports/).
   - Windows: not yet run.
   - macOS: not yet run.
4. **External penetration test** (PRD Phase 8), scoped to the API,
   authentication, the build sandbox, the relay and the domain flow.
   Record the findings in the [security register](../security/register.md).
5. **A beta period.** Two to four weeks with a few real users and
   repositories, with backups restored at least once (runbook R5) and a
   package upgrade done on each node.

Volumetric DDoS protection for public deployments (register Q33) is
always upstream: the relay provider, a CDN, or the hosting provider.
