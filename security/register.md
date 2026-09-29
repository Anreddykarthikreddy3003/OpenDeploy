# OpenDeploy security register

This register maps every question in the PRD (Q1–Q80) and every security
control (SC-01–SC-24) to the enforcing code and the test that proves it.

It is the release gate's checklist. A control counts as resolved only when its
proof test runs in CI (PRD §30.1).

| Status | Meaning |
|---|---|
| **Proven** | A test asserts the negative outcome (the attack fails). It runs in CI on every push. |
| **Proven (cap)** | Proven wherever the host can enforce the control (gVisor, nftables, KVM, root). Elsewhere the test is skipped with an explicit capability reason and never silently passes. The CI runners have these capabilities. |
| **Design** | A structural property with no runtime path to test, such as a component that simply has no such API. The structure itself is covered by tests where possible. |
| **External** | Depends on something outside the repository: an external pen test, provider features, or organisational key custody. |

The test suites cited below are:

| Suite | Location | Workflow |
|---|---|---|
| Unit | `internal/**` | `ci` |
| Integration (full stack) | `tests/integration` | `ci` |
| Adversarial | `tests/adversarial` (build tag `adversarial`) | `security-gate` |
| E2E | `tests/e2e` | `e2e` |
| Package / guest | `tests/package`, `guest/test-*.sh` | `package` |
| Fuzz | `Fuzz*` targets | corpora run in `ci`; timed runs in `security-gate` |

## Controls (SC)

| Control | Enforcement (code) | Proof | Status |
|---|---|---|---|
| SC-01 Trust classes, fail-closed | `internal/trust` (classification; repository files cannot raise trust); builderd/runtimed refuse Untrusted without a sandbox | `trust_test.go` (UntrustedFailsClosedWithoutSandbox, RepoCannotRaiseTrust, ExplicitSandboxRequestNeverDowngrades); `builder_test.go` UntrustedFailsClosedAndNoSecrets; integration fork PR fails closed | Proven |
| SC-02 Untrusted sandbox | Untrusted builds run in gVisor via `builder/sandboxed.go`; runtime handler `runsc` in runtimed | `tests/adversarial/build_test.go` TestUntrustedBuildSandbox | Proven (cap) |
| SC-03 Rootless build boundary | Rootless buildkitd (rootlesskit, own user, no entitlements) in `opendeploy-buildkitd.service`; `Buildctl` never requests entitlements | Adversarial ST-01: insecure and host-network entitlements refused; no runtime sockets | Proven (cap) |
| SC-04 FS / socket isolation | Workload spec validation (`runtime.Validate`: no host binds or sockets); symlink-safe build context | `runtime_test.go` TestValidateRejects; adversarial "no runtime sockets", "host files unreadable"; `detect_test.go` SymlinkEscape; `builder_test.go` RootDirEscape, ArchiveSourceSafety | Proven |
| SC-05 Segmentation + egress | egressd nftables per environment (`internal/network`); SSRF-safe egress proxy; host firewall table (hostd) | `network_test.go` ProxyPolicyAndSSRF, RenderValidation; adversarial TestNetworkSegmentation; `hostd_test.go` FirewallRules | Proven (cap) |
| SC-06 Secret broker | secretd envelope encryption, scope chain, versioned handles, file injection | `secrets_test.go` (PreviewIsolation, CrossProjectIsolation, ListNeverReturnsSensitiveValues, CiphertextSwapDetected, KEKRotation) | Proven |
| SC-07 GitHub least privilege | App manifest permissions; installation tokens restricted to one repository and never persisted | `github_test.go` ManifestMinimumPermissions, InstallationTokenRestricted | Proven |
| SC-08 Webhook authenticity / replay / order | Raw-body HMAC before parsing; delivery dedupe; generation numbers | `github_test.go` VerifySignature; `FuzzVerifySignature`, `FuzzParseEvent`; integration webhook section (bad signature, replay, out-of-order); `store_test.go` OutOfOrderCompletion | Proven |
| SC-09 Preview isolation | Previews get their own env, secrets and network; fork previews gated on the sandbox | `trust_test.go` ForkPR, PreviewNeverGetsProdSecrets; `secrets_test.go` PreviewIsolation; integration preview section | Proven |
| SC-10 Tier-0 split | Separate binaries and users (`packaging/linux/sysusers.d`); IPC peer-UID allowlists; hostd closed op set | `ipc_test.go` PeerCredIdentity, DeniedIdentity, DeclaredIdentityIgnoredOutsideDevMode; `hostops_test.go` NoFreeFormFields; `hostd_test.go` RegistersExactlyTheClosedOpSet; `audit_test.go` IPCIdentityEnforced; package test checks each unit's user | Proven |
| SC-11 Admin auth | Loopback by default; wildcard bind refused without acknowledgement; Argon2id; WebAuthn/TOTP; mandatory MFA for owner/admin; `__Host-` SameSite=Strict cookies; CSRF; re-auth; rate limits | `config_test.go` WildcardBindRefused, DefaultsLoopback; `auth_test.go`; integration TestAuthMFAAndSessions (ST-06) | Proven |
| SC-12 Only the edge publishes | Workloads cannot request host ports or host network; hostd host firewall; database templates private | `runtime_test.go` ValidateRejects; `hostd_test.go` FirewallRules; `trust_test.go` Capabilities | Proven |
| SC-13 Relay metadata-only | SNI/Host peek plus raw TLS passthrough; TLS terminates at the local Caddy | `relay_test.go` RelayCarriesOnlyCiphertext, CompromisedRelayMisrouteFailsTLS, CrossTenantRoutesDenied; `FuzzPeekSNI`, `FuzzPeekHost` | Proven |
| SC-14 Domain claim lifecycle | Fresh random TXT proof checked against authoritative NS; unique active claims; tombstones | `domains_test.go` AuthoritativeTXT; `platform/domains_test.go` DomainClaimLifecycle; integration custom-domain section | Proven |
| SC-15 Generation-safe promotion | Monotonic `desired_generation`; only the current generation promotes; rollback creates a new generation | `store_test.go` GenerationMonotonicAndSupersede, BeginPromotionSupersedesStaleCandidate, RollbackIsNewGeneration; `chaos_test.go` ConcurrentDeploymentsConverge | Proven |
| SC-16 State integrity | WAL plus integrity check; transactional migrations; checksummed snapshots; promotion journal; circuit breaker; degraded mode | `state/db_test.go`; `store_test.go` InvariantViolationDegrades, SnapshotVerify, Breaker; `chaos_test.go` crash-point tests, LiveCorruptionEntersDegradedMode | Proven |
| SC-17 Layered health | Startup/readiness/smoke gates before promotion; the edge verifies the deployment marker | `chaos_test.go` InterruptedPromotionUnhealthyCandidateRestores, RouterFailureKeepsPrevious; e2e deploys | Proven |
| SC-18 TUF updater | go-tuf client (root, targets, snapshot, timestamp); A/B slots; readiness gate; migration-aware rollback; no downgrade; halt/revoke | `update_test.go` UpdateSupplyChainAttacks, ReleasePolicy, SlotsRollbackAndMigrationSafety; `hostd_test.go` StageCommitAndRollback; `FuzzExtractRelease` | Proven |
| SC-19 Provenance and pinning | goreleaser SBOMs, cosign keyless signatures, SLSA provenance (`release.yml`); guest image third-party binaries pinned by sha256/sha512; artifactd validates digests | `artifact_test.go` IngestRejectsTamperedBlob; guest build verifies digests; release workflow | Proven (release pipeline); dependency scanning in `security-gate` |
| SC-20 Tamper-evident audit | auditd separate DB; hash chain; signed checkpoints; append-only triggers; off-host forwarding | `audit_test.go` TamperDetected, TruncationDetectedByCheckpoint, AppendOnlyTriggers, Forwarding | Proven |
| SC-21 Backups | Per-backup DEK, wrapped master key, signed manifest, object lock, credentials that cannot delete, clean-node restore | `backup_test.go`; `FuzzVerifyManifest`, `FuzzDecryptor`, `FuzzUntarDir`; integration TestBackupAndCleanNodeRestore (ST-11) | Proven; object-lock enforcement is provider-side (External) |
| SC-22 DB / volume isolation | Opaque volume IDs with ownership checks; no host paths; private DB templates | `runtime_test.go` ValidateRejects; adversarial cross-project denial | Proven |
| SC-23 Special capabilities | Devices, host network etc. denied in normal mode; privileged is MFA-gated with a warning | `trust_test.go` Capabilities; `runtime_test.go` ServiceAuditsAndDeniesMissingDevice | Proven |
| SC-24 DDoS / capacity truth | Per-host body, connection and header limits at the edge; docs state the limits of a single host | `router_test.go` (limits rendered); `docs/operations.md` "Capacity and DDoS" | Proven (local limits); volumetric protection is External |

## Questions (Q1–Q80)

**Legend for the Tests column:**

| Short name | Test |
|---|---|
| ADV-B | `tests/adversarial/build_test.go` |
| ADV-N | `tests/adversarial/network_test.go` |
| INT | `tests/integration/stack_test.go` |
| INT-A | `tests/integration/auth_test.go` |
| INT-B | `tests/integration/backup_test.go` |

| Q | Answer in one line | Controls | Tests | Status |
|---|---|---|---|---|
| Q1 | The boundary is per trust class: runc and namespaces for Trusted, gVisor for Untrusted. The control plane runs split under separate users. | SC-01,02,04,05,10 | trust_test, ADV-B, ADV-N, ipc_test | Proven (cap) |
| Q2 | runc is not treated as a boundary against hostile code; Untrusted code requires runsc. | SC-01,02 | trust_test UntrustedFailsClosedWithoutSandbox | Proven |
| Q3 | Escape attempts hit gVisor, dropped capabilities, seccomp, no sockets, no host mounts and nftables. The WSL guest disables interop and automount. | SC-01,02,04,05,23 | ADV-B, ADV-N, runtime_test ValidateRejects, `guest/rootfs/wsl2/etc/wsl.conf` | Proven (cap) |
| Q4 | BuildKit is rootless, has no entitlements, and runs in its own user namespace; Untrusted builds run under gVisor. | SC-01,02,03,04 | ADV-B | Proven (cap) |
| Q5 | Build egress goes through egressd's policy proxy; loopback, host, RFC1918 and metadata ranges are blocked. | SC-03,05,06 | ADV-B "builds cannot reach host…"; network_test ProxyPolicyAndSSRF | Proven (cap) |
| Q6 | A malicious Dockerfile gets no entitlements, sockets or host files; its output is validated by artifactd. | SC-01–04 | ADV-B; artifact_test; FuzzIngestOCILayout | Proven (cap) |
| Q7 | BuildKit has no containerd or Docker socket. | SC-04 | ADV-B "no runtime sockets" | Proven (cap) |
| Q8 | BuildKit runs as od-buildkit; the DB is 0700 under od-platformd. | SC-04,10 | package test (unit users); tmpfiles modes | Proven |
| Q9 | secretd scopes secrets by project and environment; workloads get only their own files. | SC-06 | secrets_test CrossProjectIsolation | Proven |
| Q10 | Build secrets are BuildKit secret mounts (never ENV or ARG); generated Dockerfiles never persist them. | SC-06 | builder_test SecretMaskingAndLeakReport; detect ca_test (no ENV) | Proven |
| Q11 | Masking is hygiene. Leaks are reported as incidents and the secret must be rotated. | SC-06 | builder_test SecretMaskingAndLeakReport | Proven |
| Q12 | Secrets are injected as tmpfs files by default; env mode is opt-in with a warning. | SC-06 | secrets_test ResolveProduction; INT (secret as file) | Proven |
| Q13 | Repository content cannot raise trust. Webhooks are verified; tokens are scoped and short-lived. | SC-01,07,08 | trust_test RepoCannotRaiseTrust; github_test | Proven |
| Q14 | Contents: read; Pull requests: read; Checks: write only if enabled. | SC-07 | github_test ManifestMinimumPermissions | Proven |
| Q15 | An `installation` deleted event blocks new builds immediately; running deployments and retained artifacts are unaffected. | SC-07,15 | INT "Q15: uninstalling the GitHub App" | Proven |
| Q16 | Delivery-ID dedupe plus generation numbers: a replayed webhook is a no-op. | SC-08 | INT (replay); FuzzParseEvent | Proven |
| Q17 | Fork previews run only under gVisor, without secrets, and are opt-in; otherwise they fail closed. | SC-01,02,09 | trust_test ForkPR; INT fork gating | Proven |
| Q18 | Previews have separate networks and no production DB references. | SC-05,09,22 | ADV-N cross-project; trust_test | Proven (cap) |
| Q19 | There is no production-to-preview secret inheritance. | SC-06,09 | secrets_test PreviewIsolation; trust_test PreviewNeverGetsProdSecrets | Proven |
| Q20 | Every preview environment is its own nftables island. | SC-05,09 | ADV-N | Proven (cap) |
| Q21 | Compromise is contained by the service split and closed hostd ops; the audit chain survives off-host; runbook R1 revokes every credential and rotates the KEK. | SC-10,20 | hostd_test, ipc_test, audit_test Forwarding; INT "ST-12 incident drill" | Proven |
| Q22 | Workloads cannot reach the admin API (loopback plus netns) or the IPC sockets. | SC-05,10 | ADV-N "workload to host denied" | Proven (cap) |
| Q23 | RBAC matrix, capped tokens, re-auth for sensitive actions, CSRF. | SC-11 | auth_test RBACMatrix; INT RBAC; INT-A | Proven |
| Q24 | Refused unless acknowledged; MFA is mandatory; rate limits and security keys apply. | SC-11 | config_test WildcardBindRefused; INT-A | Proven |
| Q25 | No generic exec exists anywhere; hostd's operations are a closed, typed set. | SC-10 | hostops_test NoFreeFormFields; hostd_test | Proven |
| Q26 | WebAuthn is preferred, TOTP supported, recovery codes exist; MFA is mandatory for owner/admin. | SC-11 | auth_test; INT-A (ST-06) | Proven |
| Q27 | The relay knows SNI/Host, timing and sizes, and instance identity. | SC-13 | relay_test RelayCarriesOnlyCiphertext | Proven |
| Q28 | The relay is trusted for availability only, not confidentiality. | SC-13 | relay_test CompromisedRelayMisrouteFailsTLS | Proven |
| Q29 | Credentials are short-lived mTLS certificates, revocable and bound to a tenant route set. | SC-13 | relay_test CredentialLifecycle | Proven |
| Q30 | Routes are keyed by (tenant, instance, verified host). | SC-13 | relay_test CrossTenantRoutesDenied | Proven |
| Q31 | Yes: the host firewall admits only the edge ports (and the relay tunnel, outbound). | SC-12 | hostd_test FirewallRules | Proven |
| Q32 | No hostPort or hostNetwork; the spec is rejected. | SC-12 | runtime_test ValidateRejects | Proven |
| Q33 | Local limits are enforced; volumetric protection must come upstream (relay or provider). | SC-24 | router limits; docs/operations.md | External |
| Q34 | A fresh TXT proof via authoritative DNS is required, plus unique active claims. | SC-14 | domains_test; platform domains_test | Proven |
| Q35 | Tombstones plus re-verification before re-attachment. | SC-14 | platform domains_test DomainClaimLifecycle | Proven |
| Q36 | 128-bit expiring tokens, checked against the authoritative server and not caches. | SC-14 | domains_test AuthoritativeTXT, Tokens | Proven |
| Q37 | The blast radius is its own environment's data and secrets. | SC-04–06,22 | ADV-N; secrets_test | Proven (cap) |
| Q38 | Yes: per-environment network namespaces with nftables default-deny. | SC-05 | ADV-N | Proven (cap) |
| Q39 | Opaque IDs with ownership checks and no host paths. | SC-22 | runtime_test | Proven |
| Q40 | Databases are not trusted: they sit on private networks, have scoped secrets, and are backed up. | SC-22 | runtime_test; ADV-N | Proven (cap) |
| Q41 | DB templates are private by default; public exposure is an explicit, audited act. | SC-12,22 | trust_test Capabilities | Proven |
| Q42 | TUF thresholds and expiring metadata; no downgrade; halt/revoke. | SC-18 | update_test UpdateSupplyChainAttacks | Proven |
| Q43 | Root keys offline and threshold-signed; online roles in CI secrets (`tools/opendeploy-release`). | SC-18 | — | External (key custody) |
| Q44 | Automatic rollback on a failed readiness gate. After a schema migration, operator restore from the pre-update backup. | SC-18 | update_test SlotsRollbackAndMigrationSafety; hostd_test | Proven |
| Q45 | Pinned digests, SBOM and provenance; artifactd validation. | SC-19 | guest digest pins; artifact_test | Proven (pinning); scanning in security-gate |
| Q46 | Reproducible flags (trimpath, fixed build IDs, commit timestamps); app builds are content-addressed. | SC-19 | `.goreleaser.yaml` | Design |
| Q47 | No: only the current generation promotes. | SC-15 | store_test OutOfOrderCompletion | Proven |
| Q48 | A promotion lock plus the supersede rule. | SC-15 | store_test ConcurrentPromotionLock; chaos ConcurrentDeploymentsConverge | Proven |
| Q49 | Yes: rollback uses retained artifacts and is a new generation. | SC-15 | store_test RollbackIsNewGeneration; INT rollback | Proven |
| Q50 | Startup, readiness, smoke and edge-marker verification. | SC-17 | chaos_test; e2e | Proven |
| Q51 | The edge verifies the deployment marker it injected; the app cannot forge routing. | SC-17 | chaos_test RouterFailureKeepsPrevious; router_test | Proven |
| Q52 | Transactions, integrity checks, checksummed snapshots, degraded mode. | SC-16 | state/db_test; store_test | Proven |
| Q53 | The reconciler converges or the breaker opens with an alert; it never loops forever. | SC-16 | chaos_test RebootRestoresDesiredState, BreakerOpensOnRepeatedRestoreFailures | Proven |
| Q54 | A signed, hash-chained audit trail, forwarded off-host. | SC-20 | audit_test | Proven |
| Q55 | Yes: auditd is a separate DB and service with its own identity. | SC-20 | audit_test IPCIdentityEnforced | Proven |
| Q56 | Backups are encrypted client-side and secrets double-sealed. | SC-21 | backup_test; INT-B | Proven |
| Q57 | Object lock plus credentials that cannot delete (provider). | SC-21 | backup_test S3TargetObjectLock | Proven (client); External (provider) |
| Q58 | No single point of trust: the service split, hostd closed ops and off-host audit. | SC-10,20 | as SC-10 | Proven |
| Q59 | "Any project that builds to OCI or static under the policy"; others need the wizard or a Dockerfile. | SC-01 | detect_test NeedsWizard | Design |
| Q60 | Denied by default; plugin/policy gated; privileged requires MFA and a warning. | SC-23 | trust_test Capabilities | Proven |
| Q61 | In platformd's API, with sessions, MFA and tokens; never in the relay or the edge. | SC-11,13 | INT-A | Proven |
| Q62 | No: certificates live only on the node. | SC-13 | relay_test CompromisedRelayMisrouteFailsTLS | Proven |
| Q63 | Sockets are never mounted; the spec is rejected. | SC-04 | runtime_test; ADV-B | Proven |
| Q64 | Symlink/escape-safe context; rootless; no host binds. | SC-03,04 | ADV-B; detect_test SymlinkEscape | Proven (cap) |
| Q65 | Previews never receive production secrets. | SC-06,09 | secrets_test PreviewIsolation | Proven |
| Q66 | Separate network; no production DB reference. | SC-05,09,22 | ADV-N | Proven (cap) |
| Q67 | Cross-project traffic is denied by nftables. | SC-05 | ADV-N cross-project denied | Proven (cap) |
| Q68 | Workload-to-host traffic is denied. | SC-05 | ADV-N workload to host denied | Proven (cap) |
| Q69 | The workload's localhost is its own network namespace; host loopback is unreachable. | SC-05 | ADV-N | Proven (cap) |
| Q70 | No host ports; the firewall admits only the edge. | SC-12 | runtime_test; hostd_test | Proven |
| Q71 | Sensitive actions still require re-auth; sessions and tokens are revocable node-wide (incident response); everything is audited. | SC-11,20 | INT-A; INT "ST-12 incident drill" | Proven |
| Q72 | Dedupe by delivery ID. | SC-08 | INT webhook replay | Proven |
| Q73 | Generations: late events cannot promote. | SC-08,15 | store_test OutOfOrderCompletion; INT ordering | Proven |
| Q74 | They can route traffic to us but cannot claim without a fresh TXT proof. | SC-14 | domains_test | Proven |
| Q75 | A tombstone plus a new proof are required. | SC-14 | platform domains_test | Proven |
| Q76 | Availability loss only; no plaintext or cross-tenant routing. | SC-13 | relay_test | Proven |
| Q77 | Short-lived certificates, revocation, and a route set bound to the tenant. | SC-13 | relay_test CredentialLifecycle | Proven |
| Q78 | Root thresholds and key rotation; nodes refuse expired or rolled-back metadata. | SC-18 | update_test UpdateSupplyChainAttacks | Proven (client); External (custody) |
| Q79 | Halt/revoke on the channel; A/B rollback; provenance visible. | SC-18,19 | update_test ReleasePolicy | Proven |
| Q80 | Invariant checks put the node in degraded read-only mode; the reconciler repairs deterministically. | SC-16 | store_test InvariantViolationDegrades; chaos_test | Proven |

## ST-12 (Tier-0 incident drill)

| Drill step | Covered by |
|---|---|
| Preserve remote audit | audit forwarding (`audit_test` Forwarding) |
| Revoke credentials; rotate KEK | INT "ST-12 incident drill" |
| Rebuild and restore | INT-B clean-node restore |

The procedure is `docs/runbooks.md` R1.

## Findings fixed during hardening

**Fuzzing (M9):**

| Finding | Status |
|---|---|
| `backup.NewDecryptor` indexed a manifest-supplied nonce prefix without a length check, so a crafted backup could panic restore. | Fixed |
| The relay's HTTP Host peek accepted malformed hosts (spaces), because `http.ReadRequest` does not validate them. Route keys now must be DNS names or IP literals, for SNI as well. | Fixed |

**Booting the packaged guest (M8):**

| Finding | Status |
|---|---|
| Group-shared exchange files were created 0600 under `UMask=0077`. | Fixed |
| The Caddy admin socket was created 0200. | Fixed |
| runtimed was killed by its seccomp filter when creating network namespaces. | Fixed |
| The spent bootstrap token file lingered until the next restart. | Fixed |

Details are in the M8 commit message.

## Externally owned items
- A Phase 8 external penetration test before GA.
- Offline TUF root key ceremony and custody.
- Authenticode and Apple Developer ID signing credentials.
- Object-lock and delete-denying credentials at the backup provider.
- Upstream volumetric DDoS protection for public deployments.
