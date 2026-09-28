**OpenDeploy**

**Product Requirements Document + Production Architecture Specification**

**v2.0 - Security-Hardened / Adversarially Reviewed**

*Open-source, local-first Git-to-production application hosting for Windows, Linux, and macOS*

| **Item**              | **Definition**                                                                                                           |
|-----------------------|--------------------------------------------------------------------------------------------------------------------------|
| Version               | 2.0                                                                                                                      |
| Status                | Production architecture baseline; implementation and security-test specification                                         |
| Date                  | 20 September 2026                                                                                                        |
| Primary target        | Single-node local appliance; future multi-node extension                                                                 |
| Core UX               | Connect GitHub -\> select repo -\> detect -\> build -\> deploy -\> domain -\> auto-deploy future commits                 |
| Security posture      | Treat source, build, PR, app, webhook, relay and update inputs as potentially malicious                                  |
| Compatibility promise | Common-stack zero-config; universal fallback for source that can produce a compatible Linux OCI image or static artifact |

# Document Control and v2.0 Change Summary

| **Why v2.0 exists** The v1.0 architecture provided a practical single-node PaaS design, but its adversarial review correctly demanded exact, testable answers for build isolation, runtime escape, cross-project boundaries, secrets, GitHub events, relay trust, domain takeover, update signing, state integrity and blast radius. v2.0 converts those concerns into enforceable security controls and release-gate tests. |
|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

| **Area**        | **v1.0 baseline**                        | **v2.0 decision**                                                                                                                   |
|-----------------|------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| Hostile code    | Container isolation and capability drops | Three trust classes; hostile builds/workloads require gVisor or disposable VM/microVM; fail closed if unavailable.                  |
| Build boundary  | BuildKit isolated from runtime socket    | Rootless OCI-worker BuildKit + egress gateway + artifact handoff; untrusted builds get stronger isolation.                          |
| Control plane   | platformd plus host service              | Split Tier-0 services with typed host API, separate secrets/audit/router/runtime/build identities.                                  |
| Networking      | Private project network                  | Per-project/environment netns + nftables default-deny; control-plane and LAN/metadata egress blocked.                               |
| Deploy ordering | Durable queue and immutable deployments  | Monotonic desired_generation prevents stale/out-of-order commits from auto-promoting.                                               |
| Relay           | Authenticated outbound tunnel            | TLS pass-through; local Caddy owns cert/key; relay trusted for routing metadata/availability, not plaintext.                        |
| Domains         | Ownership verification where required    | Fresh TXT proof mandatory; unique claims + tombstones prevent stale-domain reassignment.                                            |
| Updates         | Ed25519-signed manifest                  | TUF-style threshold roles, offline root/targets keys, provenance, A/B slots, migration-aware rollback.                              |
| Audit/backup    | Audit table + encrypted backup           | Separate tamper-evident audit and optional off-host stream; encrypted off-host versioned backups with delete-resistant credentials. |
| Security proof  | Security release gate                    | 80-question review register + mandatory negative/chaos tests; no issue is resolved without control + test.                          |

# Table of Contents

# 1. Executive Summary

OpenDeploy is a proposed open-source, local-first Platform as a Service (PaaS) that turns user-controlled hardware into a Git-to-production hosting appliance. The product goal is a Vercel-like developer experience - connect GitHub, import a repository, auto-detect the stack, build an immutable release, publish a generated URL, attach a custom domain with managed HTTPS, and automatically deploy future commits - while retaining local ownership of runtime, domains, data and operational policy.

v2.0 changes the security model materially. A normal Linux container is no longer presented as a sufficient hard boundary for intentionally hostile source. The architecture distinguishes Trusted, Untrusted and Privileged/Unsafe workloads; separates control-plane duties into smaller services; treats GitHub webhooks as unordered events rather than deployment order; uses a constrained relay that cannot read end-to-end HTTPS traffic; and upgrades platform self-update from a single signature to a threshold-role model inspired by TUF.

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th>GitHub App / Git push<br />
| signed webhook + desired_generation<br />
v<br />
platformd -----&gt; auditd<br />
| |<br />
+--&gt; builderd --&gt; isolated BuildKit / Untrusted sandbox --&gt; OCI artifact<br />
| |<br />
+--&gt; artifactd --&gt; runtimed --&gt; project sandbox/netns<br />
| |<br />
+--&gt; secretd ---- scoped secret ---+<br />
|<br />
+--&gt; routemgr --&gt; Caddy :443 --&gt; application<br />
^<br />
Internet --&gt; Direct OR Relay (TLS pass-through)</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

*Figure 1 - v2.0 high-level control and data flow*

| **Production-ready does not mean cloud-equivalent** A single laptop can be engineered safely and recoverably, but it cannot provide a global CDN, multi-region high availability, unlimited bandwidth, or hyperscale DDoS absorption. v2.0 treats these as explicit infrastructure limits, not software features. |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

# 2. Product Vision, Goals, Non-Goals, and Defensible Claims

## 2.1 Vision

Make application hosting feel like a managed platform while operating on a machine the user owns: one installer, one dashboard, one CLI, Git-based deployments, domains, HTTPS, rollback, logs, backups and reboot recovery. Internally, OpenDeploy may bundle specialized open-source components, but the operator should manage one product and one lifecycle.

## 2.2 Goals

- Native installation on supported Linux, Windows and macOS hosts without requiring the user to assemble Docker, reverse proxy, TLS or process supervisors manually.

- GitHub App integration with repository selection, minimum permissions, short-lived tokens, push/PR triggers and deterministic source SHA capture.

- Auto-detection for common Node.js/TypeScript, Python, Java/Kotlin, Go, .NET, PHP, Ruby, Rust, Elixir and static projects; Dockerfile/OCI as the broad compatibility boundary.

- Immutable production and preview deployments, health/smoke gating, atomic route promotion, generation-safe ordering and local rollback without GitHub.

- Generated URLs, custom domains from any registrar, automatic public TLS, direct and relay ingress modes, and explicit DNS ownership lifecycle.

- Security boundaries that remain meaningful when repository/build/application code is malicious, with stronger sandboxing for Untrusted code.

- Automatic service start and desired-state recovery before interactive user login after host reboot.

- Low-resource profiles suitable for spare hardware without weakening isolation controls.

## 2.3 Non-goals / limits

- No claim to reproduce a global edge/CDN or multi-region serverless infrastructure on one node.

- No zero-config guarantee for literally every language/build system. The defensible compatibility claim is source that can build to a supported Linux OCI image or static artifact.

- No promise of public reachability behind CGNAT without a routable IPv4/IPv6 path or an external relay.

- No cloud-scale DDoS absorption on a home/office Internet link.

- No safe multi-tenant promise for Privileged/Unsafe workloads sharing a node with sensitive projects.

- No arbitrary desktop GUI application hosting; the platform runs network services, jobs and supported backing services.

# 3. Threat Model, Trust Classes, and Blast Radius

## 3.1 Default adversarial assumption

Treat the following as potentially malicious or compromised: Git repository, Dockerfile, package dependency, build hook, pull request, application process, database content, webhook payload, HTTP request, domain configuration, admin session, relay connection, third-party package and update artifact. Security does not depend on an application behaving well.

## 3.2 Workload trust classes

| **Class**           | **Examples**                                              | **Execution policy**                                                                     | **Secrets / network**                                                                         |
|---------------------|-----------------------------------------------------------|------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| Trusted             | Owner-controlled production repo; reviewed internal code  | Hardened runc or gVisor per project policy; rootless build boundary.                     | Environment-scoped secrets; Internet egress allowed; LAN/control networks blocked by default. |
| Untrusted           | Public fork PR, unknown Dockerfile, third-party code      | gVisor/runsc sandbox or disposable VM/microVM. If unavailable, execution is disabled.    | No production secrets; tightly controlled egress; isolated preview data.                      |
| Privileged / Unsafe | GPU/device/FUSE/host networking/kernel-sensitive workload | Explicit capability plugin or dedicated host. MFA-gated. Some combinations are rejected. | Only explicitly approved resources; expanded blast-radius warning and audit.                  |

## 3.3 Blast-radius model

| **Compromise**             | **Maximum expected damage**                                                                                   | **Not guaranteed / residual risk**                                                                       |
|----------------------------|---------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| Normal application         | Its container/sandbox, declared project volumes, injected same-environment secrets, allowed outbound targets. | A sandbox/runtime/kernel zero-day can violate the boundary.                                              |
| Untrusted preview/build    | Ephemeral sandbox/VM, source workspace, permitted package-network egress.                                     | Sandbox/VMM or host-kernel vulnerabilities remain residual.                                              |
| Project database           | That project/environment data and services reachable by explicit policy.                                      | Application-level credentials can still be abused inside the same project.                               |
| Relay                      | Connection metadata, availability/routing for affected tunnels.                                               | If endpoint TLS keys are also compromised, plaintext confidentiality is lost.                            |
| platformd / Tier-0 control | Potentially all projects on the node through legitimate orchestration authority.                              | Service split limits direct root/socket access but cannot make an orchestrator compromise project-local. |
| Host root/kernel           | Entire node.                                                                                                  | This is the ultimate single-node trust boundary; rebuild/rotate after compromise.                        |

| **Central security invariant** A fully compromised application or build must not automatically become a compromise of another project, production secrets, control-plane sockets or the host. A Tier-0 or host compromise is handled as a node-wide incident, not disguised as project isolation. |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

# 4. Target System Architecture

## 4.1 Core components

| **Component**    | **Privilege / exposure**                    | **Responsibility**                                                                                                  |
|------------------|---------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| opendeploy-hostd | Minimal host privilege; local IPC only      | Install/start Linux data plane, host lifecycle, firewall bootstrap, update slot handoff. No generic shell API.      |
| platformd        | Unprivileged Tier-0 orchestrator; admin API | Projects, Git, desired state, deployment state machine, RBAC, scheduler, domain coordination.                       |
| builderd         | Dedicated build identity                    | Allocates rootless BuildKit workers or Untrusted disposable sandboxes; resource/network policy.                     |
| artifactd        | Narrow ingest service                       | Accepts OCI/static outputs, validates digest/metadata, stores/imports artifacts. Builder never gets runtime socket. |
| runtimed         | Dedicated runtime identity                  | Creates OCI workloads, namespaces/cgroups, gVisor selection, volumes and lifecycle through typed API.               |
| secretd          | Separate high-sensitivity service           | Envelope encryption, scope checks, secret injection, key rotation and reveal policy.                                |
| routemgr         | Router policy owner                         | Builds Caddy configuration, domain-\>deployment mapping, public edge policy and promotion verification.             |
| Caddy            | Internet-facing 80/443 only                 | TLS termination, HTTP routing, graceful config updates, request constraints.                                        |
| egressd          | Policy gateway/firewall manager             | Build/preview/application outbound policy; blocks host/LAN/link-local/metadata by default.                          |
| auditd           | Write-only typed security sink              | Security audit chain, export/off-host forwarding; separate from application logs.                                   |
| relay-agent      | Outbound connection only                    | Maintains authenticated tunnel to relay when direct ingress is unavailable.                                         |
| relay-server     | Public optional service                     | Tenant/instance/domain route mapping and TLS pass-through; no application TLS private keys.                         |

## 4.2 Technology baseline

| **Layer**        | **Default**                                                                              | **Rationale / constraint**                                                                                                |
|------------------|------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| Control plane    | Go + embedded React/TypeScript UI                                                        | Low idle overhead, cross-compilation, strong networking/concurrency; one runtime package.                                 |
| Metadata         | SQLite WAL on single node                                                                | Zero-admin and transactional; strict integrity/degraded-mode rules. PostgreSQL only when multi-node control plane exists. |
| Build            | BuildKit + Cloud Native Buildpacks/Paketo; Nixpacks adapter                              | BuildKit provides OCI outputs/caching; broad framework detection remains overrideable.                                    |
| Runtime          | containerd + runc; gVisor/runsc for stronger sandbox                                     | OCI-based execution; Docker backend adapter may be supported, but Docker Desktop is not mandatory.                        |
| Router/TLS       | Caddy                                                                                    | Automated HTTPS and API-managed graceful configuration. Caddy admin endpoint stays private/Unix-socket protected.         |
| Update security  | TUF-style metadata + signed artifacts/provenance                                         | Separates trust roles and resists rollback/freeze/mix-and-match better than one static signature.                         |
| Host abstraction | Native Linux; WSL2 managed distro on Windows; Virtualization.framework Linux VM on macOS | One Linux execution contract instead of three independent runtime implementations.                                        |

# 5. Cross-Platform Installation, Linux Data Plane, and Auto-Start

OpenDeploy standardizes build/runtime semantics on Linux. Linux hosts run the data plane natively. Windows packages a managed WSL2 distribution. macOS packages a managed Linux VM using Apple Virtualization.framework. Host-specific services start the data plane before user login, and the guest uses systemd to start platform services.

| **Host**      | **Install/boot model**                                                            | **Key checks**                                                                                                         | **Reboot recovery**                                                                                        |
|---------------|-----------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
| Linux         | deb/rpm/tar installer + systemd units                                             | cgroup v2, namespaces, overlay/snapshotter support, firewall backend, virtualization only when VM sandbox is selected. | systemd starts services; reconciler restores desired production state.                                     |
| Windows 10/11 | Signed MSI + packaged .wsl custom distro; Windows Service controls WSL instance   | Supported WSL version, virtualization, reserved ports/firewall, disk location, service account.                        | Windows Service launches WSL distribution; guest systemd starts OpenDeploy; no interactive login required. |
| macOS         | Signed/notarized app/pkg + Linux guest through Virtualization.framework + launchd | Supported macOS/CPU, virtualization entitlement, VM disk/network, reserved ports.                                      | launchd starts host service and Linux VM, then guest systemd/reconciler.                                   |

| **Old hardware rule** Resource pressure may reduce build concurrency, preview count, metrics frequency and zero-downtime overlap. It must not silently disable sandboxing, network segmentation, secret isolation, signature verification or audit controls. |
|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

# 6. GitHub Integration and Deployment Event Correctness

## 6.1 GitHub App permissions

| **Permission**                  | **Default**                       | **Why**                                                                 |
|---------------------------------|-----------------------------------|-------------------------------------------------------------------------|
| Metadata                        | Read                              | Implicit repository metadata and installation identity.                 |
| Contents                        | Read                              | Clone/fetch selected repository source over authenticated HTTP.         |
| Pull requests                   | Read - only when previews enabled | Receive/inspect PR metadata and head/base refs.                         |
| Checks                          | Write - optional                  | Publish build/deployment status without requesting source write access. |
| Administration / Contents write | No access                         | Not required for core OpenDeploy deploy flow.                           |

GitHub documentation states that apps have no permissions by default, should request minimum permissions, and require repository Contents permission for authenticated HTTP Git access. OpenDeploy therefore treats any permission expansion as an ADR/release review item \[R1-R3\].

## 6.2 Webhook ingress and durable event model

**1.** Receive the raw webhook body on the direct/relay endpoint.

**2.** Verify X-Hub-Signature-256 using HMAC-SHA256 before parsing. Reject missing/invalid signatures \[R2\].

**3.** Record X-GitHub-Delivery, installation ID, repository ID, event type, ref and source SHA in an append-only ingress record.

**4.** Deduplicate delivery IDs; validate that installation/repository/ref belongs to the project.

**5.** For a production-ref change, create a new monotonic desired_generation and durable deployment request.

**6.** Return 2xx only after durable enqueue; build asynchronously.

**7.** At promotion time, compare deployment.generation to environment.desired_generation. Older builds become Superseded even when valid and successful.

## 6.3 Revocation behavior

If GitHub installation/repository access is revoked, existing workloads keep running and retained local rollback remains available. New source fetch/build requests stop, and stale/replayed webhooks cannot restore authority. Short-lived installation tokens are requested only when needed and are not stored as permanent project credentials.

# 7. Repository Detection and Build Architecture

## 7.1 Detection priority

**1.** Explicit opendeploy.yaml

**2.** User-selected Docker Compose multi-service mode

**3.** Dockerfile

**4.** Cloud Native Buildpacks/Paketo detection

**5.** Nixpacks fallback

**6.** Static-site heuristic

**7.** Manual build/start wizard

| **Stack**             | **Signals**                                 | **Default path**                                                |
|-----------------------|---------------------------------------------|-----------------------------------------------------------------|
| Node.js / TypeScript  | package.json + lockfile                     | Buildpacks/Nixpacks; package manager from lockfile.             |
| Python                | pyproject.toml / requirements.txt / Pipfile | Buildpacks; explicit start command when inference is ambiguous. |
| Java / Kotlin         | pom.xml / build.gradle(.kts)                | JVM buildpack.                                                  |
| Go                    | go.mod                                      | Go buildpack or deterministic binary build.                     |
| .NET                  | \*.csproj / \*.sln                          | .NET buildpack.                                                 |
| Ruby                  | Gemfile                                     | Ruby buildpack.                                                 |
| PHP                   | composer.json / index.php                   | PHP buildpack/Nixpacks.                                         |
| Rust / Elixir / other | Cargo.toml / mix.exs / custom               | Nixpacks/community buildpack or Dockerfile.                     |
| Static                | index.html / known framework output         | Build once, serve static artifact through edge/static service.  |

## 7.2 Build trust decision

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th>Repository imported<br />
|<br />
+-- owner/reviewed source --&gt; Trusted build --&gt; rootless BuildKit<br />
|<br />
+-- public fork / unknown --&gt; Untrusted build --&gt; gVisor or disposable VM<br />
|<br />
+-- sandbox capability missing --&gt; FAIL CLOSED</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

*Figure 2 - build isolation selection*

## 7.3 Trusted build boundary

- Rootless BuildKit OCI worker under a dedicated UID/cgroup. Do not use the containerd worker for untrusted project builds.

- No Docker/containerd/runtimed/platform control socket in the builder namespace.

- No insecure entitlements (network.host, security.insecure, device) in normal policy. BuildKit documents these as privileged opt-ins \[R6\].

- RootlessKit isolates the builder network and disables host loopback. BuildKit documents rootless mode and recommends a separate network namespace for host-loopback isolation \[R5\].

- Workspace is ephemeral; approved cache paths are separate from platform state; platform SQLite/secrets are never mounted.

- Build output is exported as OCI archive/content and passed to artifactd for digest validation/import.

## 7.4 Untrusted build boundary

BuildKit itself documents a meaningful security boundary, but it also notes shared-resource and secret semantics that require platform policy \[R4\]. OpenDeploy therefore raises the isolation level for public-fork/unknown builds: use a gVisor-based sandbox or disposable VM/microVM, no production secrets, no host/LAN routes, tight resource quotas and disposable caches. gVisor explicitly positions itself for safely running untrusted code and as a stronger layer than raw host-kernel isolation \[R7-R8\].

## 7.5 Build egress and secrets

- Package registry/Internet egress is policy-controlled. The default blocks loopback, host gateway, RFC1918 private networks, link-local and cloud-metadata ranges.

- Private registries can be enabled through explicit allowlists and short-lived credentials.

- Build-time secrets use secret mounts rather than Dockerfile ARG/COPY. A build that is authorized to read a secret can still intentionally exfiltrate it; therefore hostile/untrusted builds receive no production secrets.

- Exact-value log/artifact scanning is a leakage detector, not a proof against transformed/split secrets.

# 8. Runtime Isolation and Workload Model

| **Workload**          | **Ingress**                | **Default sandbox**                       | **Persistence**                |
|-----------------------|----------------------------|-------------------------------------------|--------------------------------|
| Static site           | Caddy/static               | No long-running app process when possible | None by default                |
| Web/API               | Caddy -\> private endpoint | Trusted runc/gVisor by policy             | Optional owned volumes         |
| Worker                | None                       | Same as project trust class               | Optional                       |
| Cron / one-off        | None                       | Same as project trust class               | Optional                       |
| Database/cache        | Private project network    | Hardened container; not assumed trusted   | Required/optional owned volume |
| Untrusted preview     | Unique preview URL         | gVisor or disposable VM                   | Ephemeral by default           |
| Privileged capability | Explicit policy only       | Unsafe/dedicated host recommendation      | Explicit                       |

## 8.1 Runtime default restrictions

- No privileged flag, hostNetwork, hostPID, hostIPC, runtime socket, arbitrary /dev access or arbitrary host bind mounts.

- Drop capabilities; no-new-privileges; seccomp/AppArmor/SELinux where supported; read-only root filesystem where compatible; tmpfs for transient writable paths.

- Per-workload CPU, memory, PID and file-descriptor limits. Quotas are security/reliability controls, not a substitute for sandboxing.

- Each project/environment has isolated service networking and volume ownership metadata.

- Unsafe/special capabilities are never inferred from Dockerfile; they require explicit administrator action and audit.

# 9. Network Segmentation, Egress, Edge, and DDoS

## 9.1 Network zones

| **Zone**        | **May reach**                                    | **Denied by default**                                              |
|-----------------|--------------------------------------------------|--------------------------------------------------------------------|
| Public edge     | Caddy/relay listener only                        | Admin API, databases, raw app ports                                |
| Project runtime | Own project services + policy-approved Internet  | Other projects, management namespace, host/LAN/link-local/metadata |
| Preview         | Own preview services + restricted egress         | Production network/data/secrets, other previews                    |
| Build           | Registries/approved Internet via egress policy   | Host/LAN/control plane/runtime sockets                             |
| Management      | Tier-0 services over local IPC/private namespace | Public ingress except explicit remote-admin gateway                |

routemgr owns host edge mappings; container requests cannot create host NAT rules. Caddy is the only normal public web listener. Its admin API is not published; use a permissioned Unix socket or protected loopback endpoint. Caddy documents localhost as the default admin endpoint and warns operators to protect it when untrusted code exists \[R12\].

## 9.2 DDoS and abuse controls

- Per-domain connection limits, request-rate limits, body-size limits, header/timeouts and backend concurrency caps.

- Resource quotas prevent one project from exhausting all worker capacity.

- Relay deployments can integrate upstream provider filtering and connection admission.

- A local host cannot defend against link-saturating volumetric attacks after the ISP circuit is full; production guidance must recommend upstream protection for Internet-critical services.

# 10. Domains, DNS, TLS, and Public Reachability

## 10.1 Ingress modes

| **Mode** | **Requirements**                                  | **Use**                                                                   |
|----------|---------------------------------------------------|---------------------------------------------------------------------------|
| LAN only | No public DNS needed                              | Internal development/intranet; local TLS optional.                        |
| Direct   | Public IPv4/IPv6 plus firewall/NAT path to 80/443 | Lowest dependency; user controls network edge.                            |
| Relay    | Outbound connectivity to public relay             | CGNAT/dynamic/home network; stable public endpoint without inbound ports. |

## 10.2 Custom-domain claim workflow

**1.** User enters hostname.

**2.** OpenDeploy allocates a random, expiring claim ID and TXT token bound to hostname + instance/tenant.

**3.** User creates the TXT record at any DNS provider. Optional provider plugins may automate this only with explicit credentials.

**4.** OpenDeploy checks authoritative DNS for the exact current token; an old token is not accepted.

**5.** OpenDeploy validates A/AAAA/CNAME path for the selected ingress mode.

**6.** Claim is stored as unique active ownership. Caddy route and ACME issuance are enabled only after ownership proof.

**7.** Detach/delete creates a tombstone. A future claimant must complete a fresh TXT challenge even if stale A/CNAME still points at OpenDeploy.

Caddy provides automatic HTTPS and renewal once the domain is correctly routed and validation succeeds \[R13\]. DNS ownership is an external trust root: an attacker who controls authoritative DNS can legitimately prove control of that domain. That proof never grants OpenDeploy administrator or secret authority.

## 10.3 Hardened relay architecture

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th>Browser/client<br />
| HTTPS (certificate owned by local Caddy)<br />
v<br />
Public OpenDeploy Relay<br />
| TLS bytes remain encrypted<br />
v<br />
Outbound mTLS/QUIC tunnel<br />
|<br />
v<br />
Local Caddy --&gt; Project runtime</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

*Figure 3 - relay forwards encrypted application traffic*

- Relay authenticates an instance using a per-instance, short-lived/rotatable credential and authorizes only verified domain routes.

- Relay does not store application TLS private keys in the hardened mode. It may observe client IP, SNI/domain, connection timing, byte counts and tunnel IDs.

- Cross-tenant route lookup is keyed by tenant + instance + verified domain; a connection cannot supply an arbitrary backend identifier.

- If relay is compromised, assume metadata disclosure and availability/routing attacks. Endpoint certificate validation should prevent transparent HTTPS impersonation unless endpoint key/trust is separately compromised.

# 11. Deployment Orchestration, Promotion, and Rollback

## 11.1 Durable deployment state

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th>RECEIVED -&gt; VALIDATING -&gt; FETCHING -&gt; DETECTING -&gt; BUILDING -&gt; ARTIFACT_READY<br />
-&gt; STARTING_CANDIDATE -&gt; HEALTH_CHECKING -&gt; PROMOTION_INTENT<br />
-&gt; ROUTER_SWITCHED -&gt; COMMITTING_POINTER -&gt; DRAINING_OLD -&gt; SUCCEEDED<br />
<br />
Any stage -&gt; FAILED<br />
Older generation after a newer desired_generation exists -&gt; SUPERSEDED</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

## 11.2 Generation-safe ordering

Every environment has a monotonic desired_generation. A production push/manual deployment that becomes desired increments it. Build completion order is irrelevant. Before automatic promotion, the candidate must still match the current desired_generation. A deliberate rollback is represented as a new desired generation pointing to a retained deployment, preserving monotonic history rather than moving time backward.

## 11.3 Promotion protocol across SQLite and Caddy

**1.** Acquire per-environment promotion lock / compare-and-swap generation.

**2.** Persist promotion_intent with candidate deployment ID, previous deployment ID and target router configuration digest.

**3.** Apply Caddy config tagged with the candidate deployment ID.

**4.** Verify Caddy accepted config and candidate receives staged/health traffic.

**5.** Commit environment.current_deployment and observed_generation in one DB transaction.

**6.** Mark promotion_intent complete; drain old runtime.

**7.** On crash/reboot, reconciler compares promotion_intent, DB pointer and router config and deterministically completes or restores the last known-good route.

| **Why a journal is necessary** SQLite and Caddy cannot participate in one ACID transaction. v2.0 therefore specifies explicit crash-recovery semantics instead of assuming an atomic database+router switch. |
|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

## 11.4 Rollback

Rollback starts a retained immutable artifact locally, verifies readiness/smoke policy and creates a new generation that promotes that artifact. It does not require GitHub, a webhook service or a source rebuild. Internet users still depend on DNS and the selected ingress path being available.

# 12. Preview Environments

| **Rule**        | **Production default**                                                                                                                              |
|-----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| Public fork PRs | Disabled unless Untrusted sandbox capability is installed and healthy.                                                                              |
| Secrets         | Preview scope only; no production inheritance.                                                                                                      |
| Database        | Ephemeral/preview-specific by default; production DB linkage requires explicit administrator override and is forbidden for untrusted fork previews. |
| Network         | Separate namespace; deny production, other previews and management network.                                                                         |
| Domain          | Unique generated preview hostname; optional access authentication.                                                                                  |
| Lifecycle       | Stop/delete after PR close/merge with configurable metadata/log retention.                                                                          |
| Quotas          | Preview count/build concurrency constrained by resource profile; cannot starve production rollback/deploy.                                          |

This is deliberately stricter than a convenience-only preview feature. Contemporary self-hosted platforms warn that pull requests can execute code on the deployment server and recommend keeping public PR deployments disabled unless the risk is accepted \[R20-R21\].

# 13. Secrets, Configuration, and Credential Lifecycle

## 13.1 Secret scope and broker

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th>instance defaults<br />
-&gt; project defaults<br />
-&gt; environment: production | staging | preview<br />
-&gt; workload identity / deployment generation</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

- Secret values are envelope-encrypted at rest. The instance wrapping key is protected using OS facilities where practical and can integrate with TPM/Keychain/DPAPI or external KMS in future.

- secretd receives typed requests containing project/environment/workload identity and returns only allowed injection material. List APIs return metadata, not plaintext values.

- Prefer file/tmpfs secret injection. Environment-variable mode exists for compatibility and carries an exposure warning.

- GitHub installation tokens and relay credentials are short-lived/rotatable; avoid long-lived PATs.

- Log masking is best-effort hygiene. Applications that legitimately possess a secret can disclose it; use least privilege, short lifetime and rotation to constrain consequences.

## 13.2 Secret rotation after incidents

Project compromise requires rotation of that project/environment credentials. Tier-0/platformd/host compromise requires treating all node-resident secrets as potentially exposed, rebuilding the node from trusted media and rotating GitHub, relay, application, database and backup credentials according to the incident runbook.

# 14. Persistent Data, Databases, and Backups

## 14.1 Volume and database isolation

- Opaque volume IDs are owned by one project/environment/service. Runtime API accepts volume references, not arbitrary host paths.

- Database templates are reachable on the project private network only. Public database publishing is blocked in normal mode.

- Database containers are not trusted simply because the platform provisioned them; they receive the same lateral-movement restrictions as application workloads.

- Deletion protection/tombstones and explicit backup policy are recorded per volume.

## 14.2 Backup security

| **Property**        | **v2.0 requirement**                                                                                                                                   |
|---------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| Confidentiality     | Client-side encryption before upload; per-backup data encryption key (DEK).                                                                            |
| Key separation      | DEK wrapped by a separately protected backup master key/passphrase/KMS key.                                                                            |
| Integrity           | Authenticated manifest with content hashes, schema version and source instance ID.                                                                     |
| Deletion resistance | Prefer versioned/immutable storage and a runtime credential that may create new backup objects but cannot delete/overwrite existing ones.              |
| Scope               | Metadata DB, encrypted secrets/key export package, database-aware dumps, persistent volumes, project config; certificates may be restored or reissued. |
| Proof               | Scheduled restore test to a clean node. A backup is not considered production-ready until restore has been demonstrated.                               |

# 15. Admin Dashboard, API, RBAC, and MFA

## 15.1 Exposure

The dashboard/admin API binds to loopback/private interfaces by default. Remote administration is an explicit feature with TLS, MFA and interface/allowlist policy. An unsafe wildcard bind without an acknowledged remote-management configuration fails startup rather than silently exposing Tier-0 APIs.

## 15.2 Roles and sensitive operations

| **Role**      | **Typical rights**                                               | **Explicitly denied**                                                     |
|---------------|------------------------------------------------------------------|---------------------------------------------------------------------------|
| Owner         | Node policy, update, backup restore, users, all projects         | No generic host shell through normal admin API.                           |
| Project Admin | Project settings, deployments, domains, environment secrets      | Platform updates, other projects, host policy.                            |
| Developer     | Deploy/rollback within assigned projects, logs, preview controls | Secret reveal, user/RBAC changes, privileged capabilities unless granted. |
| Viewer        | Read status/logs/metadata                                        | Mutations and secret values.                                              |

- WebAuthn preferred; TOTP supported. Production mode requires MFA for owner/admin.

- Argon2id password hashing; secure SameSite/HttpOnly cookies; CSRF protection; rate limits and login backoff.

- Sensitive actions (secret reveal/export, privileged capability, update-channel/root trust, remote admin) require recent re-authentication/MFA.

- Sessions can be individually revoked. Audit records actor, session, MFA state, source and operation result.

- No endpoint accepts arbitrary shell strings for hostd; privileged operations are typed and allowlisted.

# 16. State Integrity, Audit, and Incident Response

## 16.1 SQLite/state integrity

- WAL mode with durable sync policy, foreign keys and explicit invariants; migrations are transactional where possible.

- Startup performs schema/version checks and integrity checks; checksummed snapshots exist before risky upgrades.

- Reconciler actions are idempotent and generation-aware. Permanent errors use exponential backoff and a circuit-break state.

- If state is inconsistent in a way that could delete, reattach or misroute resources, enter degraded read-only mode and require repair/restore.

## 16.2 Audit separation

Application stdout/stderr is untrusted. Security audit events are typed messages accepted only from control-plane identities and written by auditd. Include monotonic sequence, previous-event hash, actor/session/IP, resource, Git delivery, commit/artifact digest, secret metadata change, domain claim, capability grant and update metadata. For meaningful evidence after node compromise, optionally stream the chain to an off-host/WORM target.

## 16.3 Incident classes

| **Class**    | **Example**                                 | **Required response**                                                                                                                   |
|--------------|---------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| Project      | App compromised                             | Stop/isolate project as needed; rotate project secrets; inspect volumes/logs; redeploy known-good artifact.                             |
| Relay        | Tunnel credential/relay service compromised | Revoke/rotate instance credential; inspect route audit; re-establish tunnels; endpoint TLS keys remain local.                           |
| Tier-0       | platformd/secretd/host service compromise   | Assume all node project credentials may be affected; disconnect, preserve remote audit, rebuild node, restore data, rotate credentials. |
| Update trust | Signing/update infrastructure compromise    | Freeze updates; revoke/rotate TUF roles; publish trusted root recovery; rebuild/revalidate release artifacts.                           |

# 17. Self-Update and Software Supply Chain

## 17.1 TUF-style update trust

| **Role**  | **Key posture**                                         | **Purpose**                                                                   |
|-----------|---------------------------------------------------------|-------------------------------------------------------------------------------|
| Root      | Offline/hardware-backed, threshold (for example 2-of-3) | Defines trusted keys/thresholds; rare rotation and out-of-band recovery root. |
| Targets   | Offline/release-controlled, threshold                   | Authorizes exact release artifacts and metadata.                              |
| Snapshot  | Separate online/offline policy                          | Provides consistent view of repository metadata versions.                     |
| Timestamp | Online short-lived key                                  | Freshness; limits freeze/rollback window.                                     |

The Update Framework separates these roles specifically to resist rollback, freeze, mix-and-match and key-compromise scenarios \[R14-R15\]. A single Ed25519 signature on a manifest is therefore not sufficient for the production update threat model.

## 17.2 Release artifact controls

- Pin source dependencies and bundled container/runtime/router versions by version and digest.

- Produce SBOM and signed provenance; support Cosign/Sigstore-compatible verification for OCI/release artifacts \[R16\].

- Use SLSA-style provenance concepts so a release identifies source, builder and build inputs \[R17\].

- Scan dependencies/images and require documented exception for critical findings.

- Install into A/B version slots. Candidate host/control-plane must pass readiness and state checks before committing the new slot.

- Irreversible schema migrations require explicit backup/compatibility plan; automatic binary rollback is not claimed when data format cannot safely roll back.

- A correctly signed malicious insider release remains possible; reduce with threshold approval, isolated CI, review, canary rollout, transparency and rapid metadata revocation.

# 18. Startup, Reboot Recovery, and Low-Resource Operation

## 18.1 Startup ordering

**1.** OS service manager starts opendeploy-hostd.

**2.** Host service starts/mounts the managed Linux data plane.

**3.** systemd starts auditd/secretd/runtime/router/build dependencies in declared order.

**4.** platformd opens metadata, validates schema/integrity, acquires single-instance lock and starts the reconciler.

**5.** Reconciler restores production supporting services, production applications/routes, then staging/previews within resource budget.

**6.** Router loads/keeps last-known-good configuration until backends pass readiness.

**7.** Interrupted jobs resume only when the state transition is idempotent; otherwise they are marked recoverable failed/superseded.

## 18.2 Resource profiles

| **Profile** | **Planning baseline**           | **Policy**                                                                                                                                                    |
|-------------|---------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Tiny        | 2 CPU, 4 GB RAM, 30+ GB SSD     | One build at a time; previews off; trusted workloads primarily; static fast path; aggressive GC. Stronger sandbox availability may limit untrusted execution. |
| Standard    | 4 CPU, 8 GB RAM, 80+ GB SSD     | 1-2 builds; limited previews; local DBs; zero-downtime when headroom allows.                                                                                  |
| Performance | 8+ CPU, 16+ GB RAM, 150+ GB SSD | More concurrent builds/previews and stronger VM isolation options.                                                                                            |

These are planning baselines, not guarantees. Scheduler decisions use measured free memory/disk/CPU. Tiny mode may use stop-then-start promotion when there is insufficient memory to overlap old and new versions; correctness is preferred over host OOM.

# 19. Functional and Security Requirements

| **ID** | **Area**          | **Requirement**                                                                                 |
|--------|-------------------|-------------------------------------------------------------------------------------------------|
| FR-001 | Install           | One installer/command reaches healthy local dashboard; no manual container/router/TLS assembly. |
| FR-002 | Cross-platform    | Same Linux execution contract on Linux, Windows WSL2 and macOS VM.                              |
| FR-003 | GitHub            | GitHub App, selected repos, minimum permissions, short-lived tokens.                            |
| FR-004 | Import            | Repo/branch/root selection and transparent detection/build decision.                            |
| FR-005 | Build             | Exact SHA, immutable artifact, logs, cache, time/resources, trust-class isolation.              |
| FR-006 | Deploy            | Generation-safe candidate start, layered health, promotion journal and rollback.                |
| FR-007 | Auto deploy       | Push/PR events durable, authentic, deduplicated and order-safe.                                 |
| FR-008 | Preview           | Separate URL/network/secrets/data; public fork fail-closed without untrusted sandbox.           |
| FR-009 | Domains           | Fresh TXT ownership, any registrar manual instructions, provider plugins optional.              |
| FR-010 | TLS               | Automatic public HTTPS/renewal; relay passes TLS to local edge in hardened mode.                |
| FR-011 | Networking        | Only edge publishes host web ports; project/control/LAN segmentation by default.                |
| FR-012 | Secrets           | Encrypted brokered secrets; no implicit prod-\>preview inheritance; rotation/audit.             |
| FR-013 | Data              | Owned volumes and private databases with backup/restore.                                        |
| FR-014 | Observability     | Separate workload logs, platform metrics and tamper-evident security audit.                     |
| FR-015 | Autostart         | Production restored before user login after reboot.                                             |
| FR-016 | Update            | Threshold-role metadata, signed artifacts/provenance, A/B slots.                                |
| FR-017 | Resource controls | CPU/RAM/PID/disk/build concurrency and safe disk-pressure behavior.                             |
| FR-018 | Compatibility     | Buildpacks/Nixpacks common stacks; Dockerfile/OCI/static fallback.                              |
| FR-019 | Admin             | RBAC, MFA, secure sessions, sensitive re-auth, local default exposure.                          |
| FR-020 | Security proof    | Release blocked unless mandatory adversarial tests pass for required host profile.              |

# 20. Data Model and API Boundaries

| **Entity**        | **Key fields / constraints**                                                          |
|-------------------|---------------------------------------------------------------------------------------|
| users             | id, identity, password_hash/WebAuthn/TOTP metadata, role, session policy              |
| git_connections   | provider, app/installation IDs, encrypted app credentials; token cache short-lived    |
| projects          | repo ID, root, production branch, trust policy, capability policy                     |
| environments      | project, type, desired_generation, observed_generation, current_deployment            |
| deployments       | commit SHA, generation, builder inputs, artifact digest, status, provenance/SBOM refs |
| domains           | hostname, claim nonce/status, owner project/env, tombstone, ingress/TLS state         |
| secrets           | scope, name, encrypted value/version, rotation metadata; plaintext not listable       |
| services          | owner project/env, runtime class, desired state, network policy                       |
| volumes           | opaque ID, owner, mount target, deletion protection, backup policy                    |
| promotion_intents | environment, from/to deployment, generation, router digest, state                     |
| jobs              | type, idempotency key, state, retries/backoff                                         |
| audit_events      | sequence, prev_hash, actor/session/source/action/resource/result                      |
| nodes             | host capabilities, sandbox support, last_seen, update slot/version                    |

## 20.1 Representative API groups

- /api/v2/auth - login, MFA/WebAuthn, sessions, revoke

- /api/v2/git - GitHub App/installations/repositories

- /api/v2/projects and /environments - desired state and policies

- /api/v2/deployments - create/status/log/promote/rollback

- /api/v2/domains - claim/verify/attach/detach

- /api/v2/secrets - metadata/set/rotate and separately authorized reveal

- /api/v2/capabilities - explicit special-device/unsafe requests

- /api/v2/backups and /restore - backup jobs and verified restore

- /api/v2/system/update - metadata check/download/stage/commit/rollback

- /webhooks/github - signature-verified event ingress only

# 21. Open-Source Landscape and Build-vs-Adopt Decision

| **Project** | **Strong fit**                                       | **Gap relative to OpenDeploy v2 goal**                                                                                                                               |
|-------------|------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Coolify     | Git-based self-hosting, domains, previews, services  | Linux/server-centric product; public preview code is explicitly a security concern; not focused on bundled Windows/macOS appliance or hostile-source sandbox policy. |
| Dokploy     | Applications/databases, Compose, previews, modern UI | Docker/server orientation; same public-PR execution concern; cross-platform local appliance is not primary.                                                          |
| CapRover    | Mature Docker-based PaaS, HTTPS, deployment/rollback | Docker-centric and host Docker control is part of architecture; not the v2 isolated build/control model.                                                             |
| Dokku       | Mature Heroku-style CLI, buildpacks/Dockerfile       | Linux/CLI-first; dashboard, relay, local cross-platform packaging and v2 security model require additional platform work.                                            |

| **Build-vs-adopt conclusion** If the goal is only to deploy trusted applications on a Linux server, adopting Coolify/Dokploy/CapRover/Dokku is rational. OpenDeploy is justified only if the product requires one cross-platform local appliance, low-resource operation, direct/relay/domain lifecycle, and an explicit hostile-source security model. |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

# 22. Architecture Decision Records

| **ADR** | **Decision**                                 | **Status**               | **Rationale**                                                                         |
|---------|----------------------------------------------|--------------------------|---------------------------------------------------------------------------------------|
| ADR-001 | Linux execution contract on all hosts        | Accepted                 | Avoid three divergent runtime implementations.                                        |
| ADR-002 | OCI/static artifact contract                 | Accepted                 | Language-independent immutable deployment boundary.                                   |
| ADR-003 | containerd primary; Docker backend optional  | Accepted                 | Embeddable runtime without mandatory Docker Desktop.                                  |
| ADR-004 | BuildKit/buildpacks with trust-class wrapper | Revised                  | BuildKit retained, but hostile builds receive stronger isolation and egress controls. |
| ADR-005 | gVisor/disposable VM for Untrusted code      | New                      | Native containers are not the sole hostile-code boundary.                             |
| ADR-006 | Caddy public web edge                        | Accepted                 | HTTPS/routing while admin API remains private.                                        |
| ADR-007 | SQLite single-node metadata                  | Accepted with guardrails | Low overhead; integrity/degraded-mode rules added.                                    |
| ADR-008 | No Kubernetes for single-node v2             | Accepted                 | Resource and operational overhead conflicts with appliance/old-hardware goal.         |
| ADR-009 | Direct + Relay + LAN ingress                 | Accepted, relay revised  | Relay uses TLS pass-through and per-instance route credentials.                       |
| ADR-010 | Generation-safe immutable promotion          | Revised                  | Adds desired_generation and promotion-intent journal.                                 |
| ADR-011 | Fresh TXT domain claim + tombstone           | New                      | Prevents stale-domain reassignment.                                                   |
| ADR-012 | Tier-0 service split                         | New                      | Limits direct host/socket exposure and makes privileges auditable.                    |
| ADR-013 | TUF-style update trust                       | New                      | Single-signature updater is insufficient for Tier-0 supply-chain threat.              |
| ADR-014 | Fail closed on unavailable Untrusted sandbox | New                      | Security profile cannot silently downgrade for convenience.                           |

# 23. Agree Review

Review posture: assume the v2.0 design is directionally correct and identify the strongest evidence that it can meet the user experience and security goals.

| **Area**             | **Positive finding**                                                                                                                                      |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| Developer experience | The source-to-URL flow remains simple even though security services are separated internally.                                                             |
| Cross-platform       | One Linux execution contract is feasible across native Linux, a custom WSL distribution \[R18\], and Apple Virtualization.framework Linux guests \[R19\]. |
| Git security         | GitHub App least privilege and signed webhooks align with GitHub guidance \[R1-R3\].                                                                      |
| Build safety         | BuildKit explicitly documents a security boundary and rootless operation \[R4-R6\]; v2 adds platform egress and stronger isolation for hostile code.      |
| Runtime safety       | A stronger sandbox such as gVisor can reduce direct host-kernel exposure for untrusted workloads \[R7-R8\].                                               |
| Correctness          | desired_generation + promotion journal handles out-of-order builds and cross-system crash points explicitly.                                              |
| Domains/relay        | Fresh ownership proof and endpoint TLS prevent the relay from becoming an implicit plaintext trust anchor.                                                |
| Recovery             | Immutable artifacts, local rollback, state integrity checks, backup restore tests and boot reconciliation give a credible single-node recovery model.     |
| Supply chain         | Threshold-role update trust, provenance and A/B slots are substantially stronger than a single update signature.                                          |

# 24. Disagree / Adversarial Review of v2.0

Review posture: assume v2.0 is still over-promising. These objections remain important even after redesign.

| **Objection**                                            | **v2.0 response / residual risk**                                                                                                                                               |
|----------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| A sandbox is still software and can fail                 | Correct. gVisor/VM isolation reduces attack surface; it does not create proof of impossibility. Patch cadence and node-level incident response remain required.                 |
| platformd still controls too much                        | Correct. An orchestrator compromise is Tier-0 even if it lacks a raw host socket. Service split limits direct root paths but cannot make orchestration authority project-local. |
| Relay still sees metadata                                | Correct. TLS pass-through protects payload confidentiality, not SNI/domain/IP/timing metadata. Operators needing metadata privacy require a different network architecture.     |
| DNS ownership is not absolute identity                   | Correct. Whoever controls authoritative DNS can prove domain control. The platform cannot distinguish the legitimate registrar owner from an attacker who compromised DNS.      |
| Signed releases can be malicious                         | Correct. Threshold keys/provenance reduce accidental/single-key compromise, but malicious authorized signers remain a governance risk.                                          |
| Local DDoS defense is limited                            | Correct. Once the access link is saturated, application-level throttles are irrelevant.                                                                                         |
| Old laptop + untrusted VM isolation may be too expensive | Correct. Tiny profile may disable public-fork/untrusted execution rather than weaken the sandbox.                                                                               |
| “Any project” still has exclusions                       | Correct. Compatibility is Linux OCI/static plus supported capabilities, not arbitrary kernel/device/desktop workloads.                                                          |
| Single-node production is not high availability          | Correct. v2.0 is production-grade single-node operations, not HA. Multi-node is a separate product phase.                                                                       |

# 25. Final Revisions Incorporated After Agree + Disagree Review

**1.** Replaced “container = security boundary” language with explicit trust classes and stronger Untrusted isolation.

**2.** Split Tier-0 responsibilities and removed generic privileged host execution from the normal API model.

**3.** Made network segmentation/egress policy a first-class architecture component rather than an implementation detail.

**4.** Defined secret masking as hygiene, not a boundary, and prohibited production secrets for Untrusted preview/build paths.

**5.** Changed webhook correctness from duplicate checking only to signature + dedupe + monotonic generation ordering.

**6.** Changed relay design to end-to-end application TLS termination at local Caddy.

**7.** Made TXT ownership verification mandatory and added domain tombstones.

**8.** Added promotion-intent journaling for router/SQLite crash consistency.

**9.** Added degraded read-only mode for ambiguous control-plane state.

**10.** Added tamper-evident/off-host audit and deletion-resistant encrypted backups.

**11.** Replaced a single signed updater with a TUF-style threshold-role model plus provenance/canary controls.

**12.** Made all security claims release-gated by negative tests; unsupported Untrusted isolation fails closed.

# 26. Implementation Roadmap

| **Phase**                 | **Scope**                                                                                                   | **Exit gate**                                                         |
|---------------------------|-------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------|
| 0 - Security foundations  | Threat model, service identities/IPC, policy schema, audit events, trust classes, runtime abstraction.      | Architecture tests prove apps/builds cannot reach Tier-0 sockets.     |
| 1 - Linux trusted MVP     | GitHub import, build detection, rootless BuildKit, artifactd, containerd, Caddy, immutable deploy/rollback. | Trusted Node/Python/Go/Java apps deploy end to end.                   |
| 2 - Correctness + state   | desired_generation, promotion journal, reconcile/circuit-break, state snapshots/integrity.                  | Out-of-order/race/crash tests pass.                                   |
| 3 - Secrets + networking  | secretd, netns/nftables, egress gateway, private DB/volumes.                                                | Cross-project/preview/LAN/secret negative tests pass.                 |
| 4 - Untrusted sandbox     | gVisor and/or disposable VM worker; public-fork capability gate.                                            | Malicious Dockerfile/PR suite passes without host/Tier-0 access.      |
| 5 - Domains + relay       | TXT claim/tombstones, relay mTLS, TLS pass-through, generated domains.                                      | CGNAT host publishes HTTPS without relay plaintext access.            |
| 6 - Windows/macOS         | MSI + custom WSL; signed/notarized macOS VM package; native host services.                                  | Same security/E2E suite on supported Windows/macOS profiles.          |
| 7 - Supply chain/recovery | TUF updater, SBOM/provenance, encrypted off-host backup, restore automation.                                | Bad update/restore/key-rotation drills pass.                          |
| 8 - Production hardening  | Pen test, fuzzing, rate limits, docs, support bundle redaction, release policy.                             | All release gates and 80-question register accepted/fixed with tests. |

# 27. Production Acceptance Criteria and Release Gates

| **Area**           | **Pass condition**                                                                                                            |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------|
| Install            | Fresh supported Linux/Windows/macOS machine reaches a healthy dashboard and data plane through supported installer.           |
| GitHub             | Selected-repository App flow works with documented minimum permissions; revoked access blocks new source builds.              |
| Build              | Common stacks and Dockerfile path work; untrusted build fails closed without stronger sandbox.                                |
| Isolation          | Project A cannot access Project B network, volumes, secrets or control-plane endpoints.                                       |
| Preview            | Fork preview cannot receive production secret/DB access; public-fork execution capability-gated.                              |
| Deploy correctness | Old/slow/out-of-order builds cannot overwrite current desired generation; promotion crash converges.                          |
| Domain             | Fresh TXT proof required; deleted hostname cannot be reclaimed by stale DNS.                                                  |
| Relay              | Relay packet capture shows encrypted application payload; cross-tenant route confusion denied.                                |
| Admin              | Remote exposure requires explicit policy; MFA/RBAC/re-auth/session revocation tests pass.                                     |
| Update             | Unsigned/expired/rollback/wrong-threshold update metadata is rejected; A/B rollback tested.                                   |
| Backup             | Encrypted off-host restore to clean node succeeds; runtime backup credential cannot delete protected history where supported. |
| Reboot             | Production desired state restores before interactive login; last-known-good routing preserved.                                |
| Audit              | Security events cannot be forged by app logs; off-host audit reconstructs representative incident.                            |
| Resource           | Tiny profile degrades concurrency/features without disabling security controls.                                               |

# 28. Security Control Catalog

| **Control** | **Name**                                         | **Enforcement summary**                                                                                                                                                                                                                |
|-------------|--------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SC-01       | Trust classes and fail-closed policy             | Classify source/workload as Trusted, Untrusted, or Privileged/Unsafe before build or run. Unsupported isolation fails closed instead of silently weakening security.                                                                   |
| SC-02       | Untrusted workload sandbox                       | Use a stronger OCI sandbox (gVisor/runsc) or disposable VM/microVM for hostile code; standard runc is not the sole boundary for intentionally malicious workloads.                                                                     |
| SC-03       | Rootless build boundary                          | Run BuildKit rootless with OCI worker, dedicated identity/cgroup, no privileged entitlements, and an isolated network namespace.                                                                                                       |
| SC-04       | Filesystem and runtime-socket isolation          | Never mount Docker/containerd sockets or platform state into builds/apps. Allow only explicit project volumes and ephemeral workspaces; reject host bind mounts in normal mode.                                                        |
| SC-05       | Network segmentation and egress policy           | Per-project/environment network namespaces plus nftables default-deny cross-project/control-plane paths. Build/preview egress goes through a policy gateway that blocks loopback, host, RFC1918/link-local/metadata ranges by default. |
| SC-06       | Secret broker and scope enforcement              | Separate secretd service, envelope encryption, project/environment identity checks, versioned secret handles, tmpfs/file injection by preference, and no implicit production-to-preview inheritance.                                   |
| SC-07       | GitHub least privilege                           | GitHub App uses minimum repository permissions; source read only by default, PR read for previews, Checks write only when enabled. Use short-lived installation tokens scoped to selected repositories.                                |
| SC-08       | Webhook authenticity, replay, ordering           | Verify raw-body HMAC-SHA256, deduplicate X-GitHub-Delivery, validate installation/repository/ref, and use environment generation numbers so late/old events cannot auto-promote.                                                       |
| SC-09       | Preview isolation                                | Fork previews disabled unless an Untrusted sandbox is available; separate networks, secrets, data, quotas and URLs; no production secret/DB references.                                                                                |
| SC-10       | Tier-0 control-plane split                       | Split platformd, hostd, runtimed, builderd, artifactd, routemgr, secretd, auditd and egressd. Privileged hostd exposes only typed allowlisted operations and no generic shell.                                                         |
| SC-11       | Admin authentication and authorization           | Loopback/private by default; WebAuthn preferred/TOTP MFA for production; Argon2id passwords, RBAC, secure sessions, CSRF, rate limits, sensitive-action re-auth, session revocation and audit.                                         |
| SC-12       | Only edge can publish ports                      | Host firewall/nftables reserves public listeners for Caddy/relay. Workloads cannot request hostNetwork/hostPort in normal mode; database templates are private by default.                                                             |
| SC-13       | Relay is metadata-trusted, not plaintext-trusted | Relay routes TCP/TLS by authenticated instance/domain mapping while TLS terminates at local Caddy. Relay can see routing metadata and cause availability loss, but cannot read HTTPS payloads without endpoint key compromise.         |
| SC-14       | Domain claim lifecycle                           | Require fresh TXT ownership proof before public attachment, enforce globally unique active claims, and retain tombstones after detach/delete so stale DNS cannot silently bind to a new tenant/project.                                |
| SC-15       | Generation-safe deployment promotion             | Each environment has monotonic desired_generation. Only the deployment matching current generation may auto-promote; explicit rollback creates a new generation.                                                                       |
| SC-16       | State integrity and bounded reconciliation       | SQLite WAL/full integrity checks, transactional migrations, invariants, checksummed snapshots, promotion-intent journal, exponential backoff/circuit break, and degraded read-only mode on corruption.                                 |
| SC-17       | Layered health evidence                          | Use startup, liveness, readiness, dependency-aware checks, user smoke tests and optional external synthetic checks. HTTP 200 alone is never treated as proof of correctness.                                                           |
| SC-18       | Hardened updater with TUF model                  | TUF-style Root/Targets/Snapshot/Timestamp metadata, threshold offline root/targets keys, expiring online metadata, signed artifacts, A/B version slots and migration-aware rollback.                                                   |
| SC-19       | Supply-chain provenance and pinning              | Pin upstream versions/digests, generate SBOM, verify signatures/checksums, scan dependencies/images, record SLSA-style provenance, and make update provenance visible to administrators.                                               |
| SC-20       | Tamper-evident security audit                    | Security events originate only from auditd/control plane, include actor/session/source/commit/image/domain/update facts, use sequence/hash chaining, and optionally stream off-host/WORM.                                              |
| SC-21       | Backup confidentiality and deletion resistance   | Encrypt backup contents client-side with per-backup DEKs, protect wrapping keys separately, use versioned off-host storage and credentials that cannot delete/overwrite where provider supports it.                                    |
| SC-22       | Database and volume isolation                    | Opaque volume IDs with ownership checks, per-project private networks, no arbitrary host paths, database private exposure by default, and backup/restore policies per volume/service.                                                  |
| SC-23       | Special-capability workload policy               | GPU/USB/FUSE/kernel-module/host-network/device requests are denied in normal mode; supported capabilities require explicit plugins/policies. Privileged mode is MFA-gated and carries an expanded blast-radius warning.                |
| SC-24       | DDoS and capacity truth                          | Enforce request/connection/body limits and quotas locally, but explicitly state that a single local host/home link does not provide cloud-scale volumetric DDoS absorption; use upstream relay/provider protection when required.      |

# 29. Adversarial Architecture Review Register - Q1 to Q80

This register answers every question in the supplied red-team document using the required review fields. “Specified” means the architecture has an explicit control and proof test; it is not considered operationally resolved until the implementation exists and the stated test passes in CI/lab.

Q1. What exactly is the security boundary of OpenDeploy?

| **Question**                                 | What exactly is the security boundary of OpenDeploy?                                                                                                                                                                                                                              |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | The hard boundary is layered: host/Tier-0 services are separate from project and environment sandboxes; cross-project files, networks, secrets and control sockets are denied. For intentionally hostile code, the boundary is a gVisor sandbox or disposable VM, not runc alone. |
| **Security boundary**                        | SC-01 Trust classes and fail-closed policy; SC-02 Untrusted workload sandbox; SC-04 Filesystem and runtime-socket isolation; SC-05 Network segmentation and egress policy; SC-10 Tier-0 control-plane split                                                                       |
| **Attack path**                              | Compromise Project A, enumerate mounts/routes/sockets, then attempt Project B/control-plane access.                                                                                                                                                                               |
| **Impact**                                   | Cross-project compromise or host/Tier-0 compromise.                                                                                                                                                                                                                               |
| **Existing mitigation from v1.0**            | v1 names namespaces/capability drops but leaves the exact hard boundary ambiguous.                                                                                                                                                                                                |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                                                  |
| **Proof test**                               | Run escape, mount, socket, secret and cross-network negative tests from a fully compromised Project A.                                                                                                                                                                            |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                                                                      |
| **Decision**                                 | **Redesign**                                                                                                                                                                                                                                                                      |
| **Owner**                                    | Security + Runtime                                                                                                                                                                                                                                                                |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                                                       |

Q2. Is the container really considered a security boundary?

| **Question**                                 | Is the container really considered a security boundary?                                                                                                                                           |
|----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | No. Native containers are a defense layer, not the sole hostile-code security boundary. Trusted workloads may use hardened runc; untrusted workloads use gVisor/runsc or a disposable VM/microVM. |
| **Security boundary**                        | SC-01 Trust classes and fail-closed policy; SC-02 Untrusted workload sandbox                                                                                                                      |
| **Attack path**                              | Exploit runc/containerd/kernel from a compromised container.                                                                                                                                      |
| **Impact**                                   | Host compromise and all projects at risk.                                                                                                                                                         |
| **Existing mitigation from v1.0**            | v1 relies heavily on standard container primitives.                                                                                                                                               |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                  |
| **Proof test**                               | Execute known escape-regression and adversarial syscall suites against runc and untrusted sandbox profiles.                                                                                       |
| **Severity**                                 | **Critical**                                                                                                                                                                                      |
| **Decision**                                 | **Redesign**                                                                                                                                                                                      |
| **Owner**                                    | Security + Platform                                                                                                                                                                               |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                       |

Q3. What happens when a project intentionally tries to escape its sandbox?

| **Question**                                 | What happens when a project intentionally tries to escape its sandbox?                                                                                                                                                                                   |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Normal workloads cannot request runtime sockets, host networking, arbitrary host mounts, devices or privileged mode. Egress to host/control networks is blocked. Privileged requests move to an explicit Unsafe class with MFA and blast-radius warning. |
| **Security boundary**                        | SC-01 Trust classes and fail-closed policy; SC-02 Untrusted workload sandbox; SC-04 Filesystem and runtime-socket isolation; SC-05 Network segmentation and egress policy; SC-23 Special-capability workload policy                                      |
| **Attack path**                              | Malicious workload probes /proc, /sys, mounts, sockets, host gateway, devices and WSL integration.                                                                                                                                                       |
| **Impact**                                   | Host or peer-project access.                                                                                                                                                                                                                             |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                           |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                         |
| **Proof test**                               | Automated sandbox escape suite verifies every prohibited path fails closed.                                                                                                                                                                              |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                                             |
| **Decision**                                 | **Redesign**                                                                                                                                                                                                                                             |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                                      |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                              |

Q4. Why should the BuildKit environment be trusted with arbitrary repository code?

| **Question**                                 | Why should the BuildKit environment be trusted with arbitrary repository code?                                                                                                                                                |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | BuildKit is not blindly trusted. Trusted builds run in a dedicated rootless BuildKit boundary; untrusted builds require stronger disposable isolation. Builder processes have no platform DB, secret store or runtime socket. |
| **Security boundary**                        | SC-01 Trust classes and fail-closed policy; SC-02 Untrusted workload sandbox; SC-03 Rootless build boundary; SC-04 Filesystem and runtime-socket isolation                                                                    |
| **Attack path**                              | Repository build hook exploits builder or reaches host/control-plane resources.                                                                                                                                               |
| **Impact**                                   | Tier-0 compromise or secret theft.                                                                                                                                                                                            |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                              |
| **Proof test**                               | Build a malicious fixture that scans mounts, sockets, host network and attempts namespace escape; all must fail.                                                                                                              |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                  |
| **Decision**                                 | **Redesign**                                                                                                                                                                                                                  |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                           |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                   |

Q5. Can a malicious build access the Internet?

| **Question**                                 | Can a malicious build access the Internet?                                                                                                                                                                                     |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Dependency egress is allowed only through a controlled build egress path. It blocks host/LAN/link-local/metadata ranges by default and can enforce registry/domain allowlists. Untrusted builds receive no production secrets. |
| **Security boundary**                        | SC-03 Rootless build boundary; SC-05 Network segmentation and egress policy; SC-06 Secret broker and scope enforcement                                                                                                         |
| **Attack path**                              | Build downloads payload, scans LAN or exfiltrates injected data.                                                                                                                                                               |
| **Impact**                                   | LAN attack, abuse, data exfiltration.                                                                                                                                                                                          |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                 |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                               |
| **Proof test**                               | Fixture attempts RFC1918/link-local/host access and unauthorized domains; policy logs and blocks them.                                                                                                                         |
| **Severity**                                 | **High**                                                                                                                                                                                                                       |
| **Decision**                                 | **Fix**                                                                                                                                                                                                                        |
| **Owner**                                    | Security + Networking                                                                                                                                                                                                          |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                    |

Q6. What happens if the repository contains a malicious Dockerfile?

| **Question**                                 | What happens if the repository contains a malicious Dockerfile?                                                                                                                 |
|----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | A Dockerfile is executable hostile input. It is never granted platform/runtime sockets or host mounts; public-fork Dockerfiles execute only inside the Untrusted sandbox class. |
| **Security boundary**                        | SC-01 Trust classes and fail-closed policy; SC-02 Untrusted workload sandbox; SC-03 Rootless build boundary; SC-04 Filesystem and runtime-socket isolation                      |
| **Attack path**                              | Dockerfile RUN downloads/executes a second-stage payload and attacks its boundary.                                                                                              |
| **Impact**                                   | Builder/host takeover if isolation fails.                                                                                                                                       |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                  |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                |
| **Proof test**                               | Use a malicious Dockerfile corpus and verify no host filesystem/socket/network-policy escape.                                                                                   |
| **Severity**                                 | **Critical**                                                                                                                                                                    |
| **Decision**                                 | **Redesign**                                                                                                                                                                    |
| **Owner**                                    | Security + Platform                                                                                                                                                             |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                     |

Q7. Can BuildKit access containerd?

| **Question**                                 | Can BuildKit access containerd?                                                                                                                                                                         |
|----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Default BuildKit uses the OCI worker and has no containerd/Docker control socket. Build output is exported as an OCI artifact to artifactd, which validates metadata/digest before runtimed imports it. |
| **Security boundary**                        | SC-03 Rootless build boundary; SC-04 Filesystem and runtime-socket isolation; SC-10 Tier-0 control-plane split                                                                                          |
| **Attack path**                              | Compromised build connects to containerd API and launches privileged workload.                                                                                                                          |
| **Impact**                                   | Host/runtime control.                                                                                                                                                                                   |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                          |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                        |
| **Proof test**                               | Assert socket absent at filesystem and namespace level; connection and inherited-FD tests fail.                                                                                                         |
| **Severity**                                 | **Critical**                                                                                                                                                                                            |
| **Decision**                                 | **Fix**                                                                                                                                                                                                 |
| **Owner**                                    | Security + Platform                                                                                                                                                                                     |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                             |

Q8. Can BuildKit access OpenDeploy's SQLite database?

| **Question**                                 | Can BuildKit access OpenDeploy's SQLite database?                                                                                                                                                                                             |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | SQLite and secret state live outside build mount namespaces under different service identities. No platform directories, DB descriptors or control sockets are inherited; symlink-safe openat-style handling is required for artifact intake. |
| **Security boundary**                        | SC-03 Rootless build boundary; SC-04 Filesystem and runtime-socket isolation; SC-10 Tier-0 control-plane split; SC-16 State integrity and bounded reconciliation                                                                              |
| **Attack path**                              | Build traverses mounts/symlinks or inherited FDs into platform state.                                                                                                                                                                         |
| **Impact**                                   | Control-plane corruption or secret theft.                                                                                                                                                                                                     |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                              |
| **Proof test**                               | Path traversal, symlink race, fd inheritance and /proc/fd tests against builder fixtures.                                                                                                                                                     |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                                  |
| **Decision**                                 | **Fix**                                                                                                                                                                                                                                       |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                           |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                   |

Q9. Can a malicious application read another application's secrets?

| **Question**                                 | Can a malicious application read another application's secrets?                                                                                            |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Secrets are fetched by secretd only after checking project, environment and workload identity. Project A cannot request secret handles owned by Project B. |
| **Security boundary**                        | SC-06 Secret broker and scope enforcement                                                                                                                  |
| **Attack path**                              | Compromised A guesses B secret IDs or invokes reveal/injection path.                                                                                       |
| **Impact**                                   | Cross-project credential theft.                                                                                                                            |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                             |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                           |
| **Proof test**                               | Property/integration tests attempt cross-tenant secret ID access and verify deny + audit.                                                                  |
| **Severity**                                 | **Critical**                                                                                                                                               |
| **Decision**                                 | **Fix**                                                                                                                                                    |
| **Owner**                                    | Security + Platform                                                                                                                                        |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                |

Q10. Can build-time secrets accidentally become image-layer data?

| **Question**                                 | Can build-time secrets accidentally become image-layer data?                                                                                                                                                                                                                                        |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Build secrets use BuildKit secret mounts/tmpfs and are excluded from cache inputs; OpenDeploy also scans output/logs for exact secret values. However, a malicious build that legitimately receives a secret can intentionally copy or transform it, so untrusted builds get no production secrets. |
| **Security boundary**                        | SC-03 Rootless build boundary; SC-06 Secret broker and scope enforcement; SC-19 Supply-chain provenance and pinning                                                                                                                                                                                 |
| **Attack path**                              | Authorized build writes secret into image layer/cache/log/artifact.                                                                                                                                                                                                                                 |
| **Impact**                                   | Credential leakage in immutable artifacts.                                                                                                                                                                                                                                                          |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                                                                      |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                                                                    |
| **Proof test**                               | Canary secrets are copied, deleted, encoded and split; verify policy blocks raw leakage and untrusted builds receive none.                                                                                                                                                                          |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                                                                                        |
| **Decision**                                 | **Redesign**                                                                                                                                                                                                                                                                                        |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                                                                                 |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                                                                         |

Q11. Is secret masking actually security or only log hygiene?

| **Question**                                 | Is secret masking actually security or only log hygiene?                                                                                                                       |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Secret masking is log hygiene, not a security boundary. Exact-value and key-pattern masking reduce accidental disclosure but cannot reliably detect arbitrary transformations. |
| **Security boundary**                        | SC-06 Secret broker and scope enforcement                                                                                                                                      |
| **Attack path**                              | Application encodes/splits a secret before logging.                                                                                                                            |
| **Impact**                                   | Secret appears in logs despite masking.                                                                                                                                        |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                 |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                               |
| **Proof test**                               | Document limitation; test exact/base common cases and ensure untrusted code never gets sensitive secrets.                                                                      |
| **Severity**                                 | **High**                                                                                                                                                                       |
| **Decision**                                 | **Accept with limitation**                                                                                                                                                     |
| **Owner**                                    | Security                                                                                                                                                                       |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                    |

Q12. Can environment variables expose secrets through debugging endpoints?

| **Question**                                 | Can environment variables expose secrets through debugging endpoints?                                                                                                                                                              |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | OpenDeploy can minimize env exposure and prefer file/tmpfs injection, but it cannot guarantee that an application will not expose a secret it was intentionally given. Secure defaults, warnings and secret rotation limit impact. |
| **Security boundary**                        | SC-06 Secret broker and scope enforcement                                                                                                                                                                                          |
| **Attack path**                              | App exposes /env, crash dump, debug endpoint or metrics containing own secret.                                                                                                                                                     |
| **Impact**                                   | Own-project secret compromise.                                                                                                                                                                                                     |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                     |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                   |
| **Proof test**                               | Deploy intentionally leaky fixture; verify warnings/scoped credentials/rotation workflow, not false prevention claims.                                                                                                             |
| **Severity**                                 | **High**                                                                                                                                                                                                                           |
| **Decision**                                 | **Accept with guardrails**                                                                                                                                                                                                         |
| **Owner**                                    | Security + Product                                                                                                                                                                                                                 |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                        |

Q13. What prevents a compromised GitHub repository from taking over OpenDeploy?

| **Question**                                 | What prevents a compromised GitHub repository from taking over OpenDeploy?                                                                                                                           |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | A repository controls only its project build/runtime input. It cannot change platform policy, domain ownership, secret scopes, host mounts, admin RBAC or updater settings through repository files. |
| **Security boundary**                        | SC-01 Trust classes and fail-closed policy; SC-04 Filesystem and runtime-socket isolation; SC-07 GitHub least privilege; SC-10 Tier-0 control-plane split                                            |
| **Attack path**                              | Attacker commits config/Dockerfile designed to request platform privilege.                                                                                                                           |
| **Impact**                                   | Project-to-platform escalation.                                                                                                                                                                      |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                       |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                     |
| **Proof test**                               | Malicious repo requests forbidden capabilities and cross-project resources; importer rejects before execution.                                                                                       |
| **Severity**                                 | **Critical**                                                                                                                                                                                         |
| **Decision**                                 | **Fix**                                                                                                                                                                                              |
| **Owner**                                    | Security + Platform                                                                                                                                                                                  |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                          |

Q14. What is the minimum GitHub permission required?

| **Question**                                 | What is the minimum GitHub permission required?                                                                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Default GitHub App permissions are Metadata read and Contents read. Pull Requests read is added only for previews; Checks write is optional for status reporting. Avoid Administration/Contents write unless a future feature proves need. |
| **Security boundary**                        | SC-07 GitHub least privilege                                                                                                                                                                                                               |
| **Attack path**                              | Over-privileged app token is stolen.                                                                                                                                                                                                       |
| **Impact**                                   | Repository/org modification beyond deployment need.                                                                                                                                                                                        |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                             |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                           |
| **Proof test**                               | Contract test GitHub API calls with minimum permission fixture and fail build if new permission is introduced without ADR.                                                                                                                 |
| **Severity**                                 | **High**                                                                                                                                                                                                                                   |
| **Decision**                                 | **Fix**                                                                                                                                                                                                                                    |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                        |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                |

Q15. What happens after GitHub access is revoked?

| **Question**                                 | What happens after GitHub access is revoked?                                                                                                                                                                                     |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Existing local deployment may continue serving after source access is revoked. New source builds are disabled; stale webhooks cannot authorize a deployment; rollback remains available from retained immutable local artifacts. |
| **Security boundary**                        | SC-07 GitHub least privilege; SC-08 Webhook authenticity, replay, ordering; SC-15 Generation-safe deployment promotion                                                                                                           |
| **Attack path**                              | Access revoked but previously queued/stale event starts new build.                                                                                                                                                               |
| **Impact**                                   | Unauthorized post-revocation release.                                                                                                                                                                                            |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                   |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                 |
| **Proof test**                               | Revoke installation mid-queue; verify source fetch/new deploy fail while local rollback succeeds.                                                                                                                                |
| **Severity**                                 | **High**                                                                                                                                                                                                                         |
| **Decision**                                 | **Fix**                                                                                                                                                                                                                          |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                              |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                      |

Q16. Can an attacker replay an old valid webhook?

| **Question**                                 | Can an attacker replay an old valid webhook?                                                                                                                                  |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | HMAC plus delivery-ID dedupe authenticates/rejects duplicates, while monotonic desired_generation prevents a valid older event from becoming production after a newer commit. |
| **Security boundary**                        | SC-08 Webhook authenticity, replay, ordering; SC-15 Generation-safe deployment promotion                                                                                      |
| **Attack path**                              | Replay old valid delivery after newer commit.                                                                                                                                 |
| **Impact**                                   | Production rollback to stale vulnerable code.                                                                                                                                 |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                              |
| **Proof test**                               | Replay and reorder signed webhook fixtures; only current generation can auto-promote.                                                                                         |
| **Severity**                                 | **Critical**                                                                                                                                                                  |
| **Decision**                                 | **Fix**                                                                                                                                                                       |
| **Owner**                                    | Security + Platform                                                                                                                                                           |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                   |

Q17. Why should preview environments ever be allowed to execute fork code?

| **Question**                                 | Why should preview environments ever be allowed to execute fork code?                                                                                                                          |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Public-fork preview execution is disabled by default and remains technically unavailable unless the node supports the Untrusted sandbox policy. A UI toggle cannot bypass the capability gate. |
| **Security boundary**                        | SC-01 Trust classes and fail-closed policy; SC-02 Untrusted workload sandbox; SC-09 Preview isolation                                                                                          |
| **Attack path**                              | External PR submits malicious build and user enables previews.                                                                                                                                 |
| **Impact**                                   | Remote code execution attempt against host.                                                                                                                                                    |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                 |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                               |
| **Proof test**                               | On host without untrusted sandbox, API/UI request for public-fork preview must fail closed.                                                                                                    |
| **Severity**                                 | **Critical**                                                                                                                                                                                   |
| **Decision**                                 | **Redesign**                                                                                                                                                                                   |
| **Owner**                                    | Security + Platform                                                                                                                                                                            |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                    |

Q18. Can preview environments access production databases?

| **Question**                                 | Can preview environments access production databases?                                                                                                                                             |
|----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Preview networks have no route to production DB networks, and production database service handles cannot be attached to preview environments without a separately audited administrator override. |
| **Security boundary**                        | SC-05 Network segmentation and egress policy; SC-09 Preview isolation; SC-22 Database and volume isolation                                                                                        |
| **Attack path**                              | PR code reuses production DATABASE_URL or scans service network.                                                                                                                                  |
| **Impact**                                   | Production data theft/destruction.                                                                                                                                                                |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                    |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                  |
| **Proof test**                               | Preview fixture scans/calls production DB; firewall and service identity deny it.                                                                                                                 |
| **Severity**                                 | **Critical**                                                                                                                                                                                      |
| **Decision**                                 | **Fix**                                                                                                                                                                                           |
| **Owner**                                    | Security + Platform                                                                                                                                                                               |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                       |

Q19. Can preview environments access production secrets?

| **Question**                                 | Can preview environments access production secrets?                                                                                                                    |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Preview secret scope is separate and secretd rejects production-scope handles for preview identities. Fork/untrusted previews receive no sensitive secrets by default. |
| **Security boundary**                        | SC-06 Secret broker and scope enforcement; SC-09 Preview isolation                                                                                                     |
| **Attack path**                              | PR requests prod API/JWT/GitHub credentials.                                                                                                                           |
| **Impact**                                   | Credential exfiltration and production compromise.                                                                                                                     |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                         |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                       |
| **Proof test**                               | Attempt direct, guessed-ID and config-reference access from preview; all denied and audited.                                                                           |
| **Severity**                                 | **Critical**                                                                                                                                                           |
| **Decision**                                 | **Fix**                                                                                                                                                                |
| **Owner**                                    | Security + Platform                                                                                                                                                    |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                            |

Q20. Can preview workloads attack other preview workloads?

| **Question**                                 | Can preview workloads attack other preview workloads?                                                                                  |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Each preview receives its own sandbox/network namespace. Default network policy denies preview-to-preview communication and discovery. |
| **Security boundary**                        | SC-02 Untrusted workload sandbox; SC-05 Network segmentation and egress policy; SC-09 Preview isolation                                |
| **Attack path**                              | PR \#101 scans PR \#102/103 service addresses and names.                                                                               |
| **Impact**                                   | Cross-preview compromise/data theft.                                                                                                   |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                         |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                       |
| **Proof test**                               | Parallel hostile previews run discovery/scan tests; no peer path should exist.                                                         |
| **Severity**                                 | **High**                                                                                                                               |
| **Decision**                                 | **Fix**                                                                                                                                |
| **Owner**                                    | Security + Platform                                                                                                                    |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                            |

Q21. What happens if the OpenDeploy control plane is compromised?

| **Question**                                 | What happens if the OpenDeploy control plane is compromised?                                                                                                                                                                                                                                                |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | platformd is Tier-0. Process splitting prevents direct root/socket access, but compromise of the orchestration authority can still authorize destructive legitimate operations. Treat the node and all project credentials as potentially compromised; isolate hostd/secretd and require incident rotation. |
| **Security boundary**                        | SC-10 Tier-0 control-plane split; SC-20 Tamper-evident security audit                                                                                                                                                                                                                                       |
| **Attack path**                              | Exploit admin/API parser in platformd, then use legitimate orchestration APIs.                                                                                                                                                                                                                              |
| **Impact**                                   | Potential all-project/node impact.                                                                                                                                                                                                                                                                          |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                                                                              |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                                                                            |
| **Proof test**                               | Compromise simulation verifies platformd lacks raw host shell/socket, then run credential-rotation and node-rebuild incident drill.                                                                                                                                                                         |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                                                                                                |
| **Decision**                                 | **Redesign + accept Tier-0 risk**                                                                                                                                                                                                                                                                           |
| **Owner**                                    | Platform + Security                                                                                                                                                                                                                                                                                         |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                                                                                 |

Q22. Can an application invoke platform APIs?

| **Question**                                 | Can an application invoke platform APIs?                                                                                                                                                    |
|----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Application networks do not route to platform control endpoints. Control services use permissioned Unix/vsock endpoints or dedicated management namespace; host gateway aliases are absent. |
| **Security boundary**                        | SC-04 Filesystem and runtime-socket isolation; SC-05 Network segmentation and egress policy; SC-10 Tier-0 control-plane split                                                               |
| **Attack path**                              | App connects to host gateway/localhost-equivalent and invokes platform API.                                                                                                                 |
| **Impact**                                   | Tier-0 control.                                                                                                                                                                             |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                              |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                            |
| **Proof test**                               | From app, scan all interfaces/gateways and known ports; no control API reachable.                                                                                                           |
| **Severity**                                 | **Critical**                                                                                                                                                                                |
| **Decision**                                 | **Fix**                                                                                                                                                                                     |
| **Owner**                                    | Security + Platform                                                                                                                                                                         |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                 |

Q23. What prevents privilege escalation through the admin API?

| **Question**                                 | What prevents privilege escalation through the admin API?                                                                                                                                             |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Every privileged API action has explicit RBAC and project scope. Sensitive operations require recent MFA/re-auth and are audited. hostd exposes typed operations rather than shell/command execution. |
| **Security boundary**                        | SC-10 Tier-0 control-plane split; SC-11 Admin authentication and authorization; SC-20 Tamper-evident security audit                                                                                   |
| **Attack path**                              | Low-privilege admin/developer calls deploy/secret/domain/update operation outside scope.                                                                                                              |
| **Impact**                                   | Privilege escalation/cross-project control.                                                                                                                                                           |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                        |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                      |
| **Proof test**                               | Authorization matrix tests every role x endpoint x resource, including IDOR attempts.                                                                                                                 |
| **Severity**                                 | **Critical**                                                                                                                                                                                          |
| **Decision**                                 | **Redesign**                                                                                                                                                                                          |
| **Owner**                                    | Security + Platform                                                                                                                                                                                   |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                           |

Q24. What happens if the admin dashboard becomes publicly reachable?

| **Question**                                 | What happens if the admin dashboard becomes publicly reachable?                                                                                                                                                                  |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Dashboard/API binds loopback/private by default. Remote management is an explicit mode requiring TLS, MFA and allowlisted interfaces; startup refuses unsafe wildcard exposure without an acknowledged remote-management policy. |
| **Security boundary**                        | SC-11 Admin authentication and authorization                                                                                                                                                                                     |
| **Attack path**                              | User/reverse proxy exposes admin port publicly.                                                                                                                                                                                  |
| **Impact**                                   | Account takeover/Tier-0 operations.                                                                                                                                                                                              |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                   |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                 |
| **Proof test**                               | Start with 0.0.0.0 config without remote policy; service must refuse and log actionable error.                                                                                                                                   |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                     |
| **Decision**                                 | **Fix**                                                                                                                                                                                                                          |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                              |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                      |

Q25. Is the admin dashboard itself a privileged code-execution interface?

| **Question**                                 | Is the admin dashboard itself a privileged code-execution interface?                                                                                                                                                 |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Yes, the admin plane is privileged. It must not expose generic host shell, arbitrary host mounts/network/devices or raw runtime flags in normal mode. Advanced privileged requests are separately gated and audited. |
| **Security boundary**                        | SC-10 Tier-0 control-plane split; SC-11 Admin authentication and authorization; SC-23 Special-capability workload policy                                                                                             |
| **Attack path**                              | Stolen admin creates workload with host mount/socket/device and escapes.                                                                                                                                             |
| **Impact**                                   | Host compromise.                                                                                                                                                                                                     |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                       |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                     |
| **Proof test**                               | Fuzz/admin API tests reject raw privileged runtime parameters outside explicit Unsafe capability flow.                                                                                                               |
| **Severity**                                 | **Critical**                                                                                                                                                                                                         |
| **Decision**                                 | **Redesign**                                                                                                                                                                                                         |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                  |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                          |

Q26. Is there MFA?

| **Question**                                 | Is there MFA?                                                                                                                                                                                                                       |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Production mode requires MFA. WebAuthn is preferred with TOTP recovery option; include Argon2id password hashing, rate limits/backoff, secure cookie flags, session invalidation, login audit and re-auth for sensitive operations. |
| **Security boundary**                        | SC-11 Admin authentication and authorization; SC-20 Tamper-evident security audit                                                                                                                                                   |
| **Attack path**                              | Password/session theft or brute force.                                                                                                                                                                                              |
| **Impact**                                   | Administrative takeover.                                                                                                                                                                                                            |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                      |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                    |
| **Proof test**                               | Automated auth tests for MFA enforcement, throttling, rotation, revocation and stale-session denial.                                                                                                                                |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                        |
| **Decision**                                 | **Fix**                                                                                                                                                                                                                             |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                 |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                         |

Q27. What does the relay actually know?

| **Question**                                 | What does the relay actually know?                                                                                                                                                                                  |
|----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | In hardened relay mode TLS terminates at local Caddy, not relay. Relay can observe client IP, SNI/domain, connection timing and byte counts plus instance/project route IDs, but not HTTPS payloads/cookies/tokens. |
| **Security boundary**                        | SC-13 Relay is metadata-trusted, not plaintext-trusted                                                                                                                                                              |
| **Attack path**                              | Relay operator/attacker inspects forwarded traffic.                                                                                                                                                                 |
| **Impact**                                   | Metadata exposure; plaintext exposure if design terminates TLS upstream.                                                                                                                                            |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                      |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                    |
| **Proof test**                               | Packet capture at relay verifies payload remains TLS ciphertext and local Caddy owns certificate key.                                                                                                               |
| **Severity**                                 | **High**                                                                                                                                                                                                            |
| **Decision**                                 | **Redesign**                                                                                                                                                                                                        |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                 |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                         |

Q28. Is the relay a trusted component?

| **Question**                                 | Is the relay a trusted component?                                                                                                                                                                                                      |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Relay is trusted for availability/routing metadata but not for application plaintext. End-to-end TLS plus instance/domain authorization limits a compromised relay to DoS/misrouting attempts that should fail certificate validation. |
| **Security boundary**                        | SC-13 Relay is metadata-trusted, not plaintext-trusted                                                                                                                                                                                 |
| **Attack path**                              | Relay injects or redirects connections to wrong backend.                                                                                                                                                                               |
| **Impact**                                   | Availability loss; possible phishing only if certificate trust is also compromised.                                                                                                                                                    |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                         |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                       |
| **Proof test**                               | Compromised-relay test reroutes domain to wrong instance; TLS/SNI identity validation must fail.                                                                                                                                       |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                           |
| **Decision**                                 | **Redesign**                                                                                                                                                                                                                           |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                    |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                            |

Q29. What happens if a relay credential is stolen?

| **Question**                                 | What happens if a relay credential is stolen?                                                                                                                                                  |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Relay credentials are per instance, short-lived/rotatable and revocable; they authorize only explicitly assigned domain routes. A stolen credential must not grant all user projects/machines. |
| **Security boundary**                        | SC-13 Relay is metadata-trusted, not plaintext-trusted                                                                                                                                         |
| **Attack path**                              | Steal one tunnel credential and enumerate routes.                                                                                                                                              |
| **Impact**                                   | One-instance tunnel abuse.                                                                                                                                                                     |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                 |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                               |
| **Proof test**                               | Use credential from instance A against B/other tenant routes; deny and audit; rotate credential live.                                                                                          |
| **Severity**                                 | **High**                                                                                                                                                                                       |
| **Decision**                                 | **Fix**                                                                                                                                                                                        |
| **Owner**                                    | Security + Platform                                                                                                                                                                            |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                    |

Q30. Can one customer's relay connection reach another customer's tunnel?

| **Question**                                 | Can one customer's relay connection reach another customer's tunnel?                                                                                      |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Relay route table keys are tenant + instance + verified domain, enforced before tunnel forwarding. Connections cannot choose arbitrary customer backends. |
| **Security boundary**                        | SC-13 Relay is metadata-trusted, not plaintext-trusted; SC-14 Domain claim lifecycle                                                                      |
| **Attack path**                              | User A requests User B tunnel identifier/domain.                                                                                                          |
| **Impact**                                   | Cross-tenant traffic exposure.                                                                                                                            |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                            |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                          |
| **Proof test**                               | Multi-tenant relay integration test for route confusion, ID guessing and replay.                                                                          |
| **Severity**                                 | **Critical**                                                                                                                                              |
| **Decision**                                 | **Fix**                                                                                                                                                   |
| **Owner**                                    | Security + Platform                                                                                                                                       |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                               |

Q31. Is Caddy the only Internet-facing component?

| **Question**                                 | Is Caddy the only Internet-facing component?                                                                                                                          |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | For public web ingress, only Caddy (and optional relay/tunnel listener) may bind host public ports. Firewall policy is generated independently of container requests. |
| **Security boundary**                        | SC-12 Only edge can publish ports                                                                                                                                     |
| **Attack path**                              | Workload attempts host port publish to bypass edge.                                                                                                                   |
| **Impact**                                   | Bypass TLS/rate limits/domain policy.                                                                                                                                 |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                        |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                      |
| **Proof test**                               | Runtime request with published host port must be rejected; host socket inventory must show only approved listeners.                                                   |
| **Severity**                                 | **Critical**                                                                                                                                                          |
| **Decision**                                 | **Fix**                                                                                                                                                               |
| **Owner**                                    | Security + Platform                                                                                                                                                   |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                           |

Q32. Can an application expose its own public port?

| **Question**                                 | Can an application expose its own public port?                                                                                                                                                           |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | An application may bind any port inside its own namespace but cannot publish it on the host in normal mode because hostPort/hostNetwork are prohibited and firewall DNAT is controlled only by routemgr. |
| **Security boundary**                        | SC-05 Network segmentation and egress policy; SC-12 Only edge can publish ports                                                                                                                          |
| **Attack path**                              | Malicious app binds 0.0.0.0:4444 and requests public mapping.                                                                                                                                            |
| **Impact**                                   | Direct Internet exposure.                                                                                                                                                                                |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                           |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                         |
| **Proof test**                               | Fixture listens on multiple ports and probes externally; only Caddy-routed declared service is reachable.                                                                                                |
| **Severity**                                 | **Critical**                                                                                                                                                                                             |
| **Decision**                                 | **Fix**                                                                                                                                                                                                  |
| **Owner**                                    | Security + Platform                                                                                                                                                                                      |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                              |

Q33. Where is DDoS protection?

| **Question**                                 | Where is DDoS protection?                                                                                                                                                                                                                    |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | OpenDeploy provides local connection/request/body/rate limits but cannot absorb volumetric DDoS that saturates the user link. Relay deployments may add provider-level filtering; this is an explicit infrastructure limitation, not hidden. |
| **Security boundary**                        | SC-24 DDoS and capacity truth                                                                                                                                                                                                                |
| **Attack path**                              | Flood host/link beyond local capacity.                                                                                                                                                                                                       |
| **Impact**                                   | Network/application outage.                                                                                                                                                                                                                  |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                               |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                             |
| **Proof test**                               | Load tests verify local limits; documentation/acceptance test confirms no false cloud-scale DDoS claim.                                                                                                                                      |
| **Severity**                                 | **High**                                                                                                                                                                                                                                     |
| **Decision**                                 | **Accept with limitation**                                                                                                                                                                                                                   |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                          |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                  |

Q34. Can an attacker claim another user's domain?

| **Question**                                 | Can an attacker claim another user's domain?                                                                                                                           |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | A custom domain becomes attachable only after a fresh, random TXT ownership challenge succeeds. Active claims are globally unique within the instance/relay namespace. |
| **Security boundary**                        | SC-14 Domain claim lifecycle                                                                                                                                           |
| **Attack path**                              | Attacker enters victim hostname after old project deletion.                                                                                                            |
| **Impact**                                   | Domain takeover/phishing.                                                                                                                                              |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                         |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                       |
| **Proof test**                               | Attempt claim without current TXT token and with another project active; deny.                                                                                         |
| **Severity**                                 | **Critical**                                                                                                                                                           |
| **Decision**                                 | **Redesign**                                                                                                                                                           |
| **Owner**                                    | Security + Platform                                                                                                                                                    |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                            |

Q35. What happens to stale DNS records?

| **Question**                                 | What happens to stale DNS records?                                                                                                                                          |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Deleting/detaching creates a tombstone/unassigned claim record. Stale A/CNAME records never auto-map to another project; a future claimant must pass a fresh TXT challenge. |
| **Security boundary**                        | SC-14 Domain claim lifecycle                                                                                                                                                |
| **Attack path**                              | Old DNS points to instance after project is removed; new project reuses hostname.                                                                                           |
| **Impact**                                   | Dangling-domain takeover.                                                                                                                                                   |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                              |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                            |
| **Proof test**                               | Delete project while DNS remains, attempt immediate re-claim, verify no traffic routes until new proof.                                                                     |
| **Severity**                                 | **Critical**                                                                                                                                                                |
| **Decision**                                 | **Redesign**                                                                                                                                                                |
| **Owner**                                    | Security + Platform                                                                                                                                                         |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                 |

Q36. How strong is domain ownership verification?

| **Question**                                 | How strong is domain ownership verification?                                                                                                                                                                                         |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Ownership proof is a high-entropy TXT token bound to instance + claim + hostname with expiry; A/AAAA/CNAME correctness is separately validated for routing. DNS control is a trust root, but stale resolution alone is insufficient. |
| **Security boundary**                        | SC-14 Domain claim lifecycle                                                                                                                                                                                                         |
| **Attack path**                              | Attacker can point A record but cannot set claim TXT, or replays old TXT.                                                                                                                                                            |
| **Impact**                                   | Unauthorized domain binding.                                                                                                                                                                                                         |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                       |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                     |
| **Proof test**                               | Test expired/replayed/wrong-instance/wildcard/apex TXT challenges and authoritative DNS checks.                                                                                                                                      |
| **Severity**                                 | **High**                                                                                                                                                                                                                             |
| **Decision**                                 | **Fix**                                                                                                                                                                                                                              |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                  |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                          |

Q37. What is the blast radius of a compromised application?

| **Question**                                 | What is the blast radius of a compromised application?                                                                                                                                                                                                                                              |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Target blast radius for a fully compromised normal application is its own runtime filesystem, explicitly mounted project volumes, injected project/environment secrets and allowed egress. Cross-project, control-plane and host access are blocked; residual kernel/runtime zero-day risk remains. |
| **Security boundary**                        | SC-01 Trust classes and fail-closed policy; SC-02 Untrusted workload sandbox; SC-04 Filesystem and runtime-socket isolation; SC-05 Network segmentation and egress policy; SC-06 Secret broker and scope enforcement; SC-22 Database and volume isolation                                           |
| **Attack path**                              | Attacker owns app process and attempts lateral movement/host escape.                                                                                                                                                                                                                                |
| **Impact**                                   | Own-project data loss by design; platform-wide loss only if sandbox/kernel/Tier-0 control also fails.                                                                                                                                                                                               |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                                                                      |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                                                                    |
| **Proof test**                               | Red-team compromised-container suite validates boundaries and records residual risks.                                                                                                                                                                                                               |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                                                                                        |
| **Decision**                                 | **Redesign**                                                                                                                                                                                                                                                                                        |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                                                                                 |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                                                                         |

Q38. Are project networks truly isolated?

| **Question**                                 | Are project networks truly isolated?                                                                                                                                                   |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Yes by policy: separate network namespaces/bridges and nftables default-deny inter-project traffic, service discovery and control-plane routes. Exceptions are explicit service links. |
| **Security boundary**                        | SC-05 Network segmentation and egress policy                                                                                                                                           |
| **Attack path**                              | Project A scans private subnets/DNS and connects to B service.                                                                                                                         |
| **Impact**                                   | Cross-project compromise.                                                                                                                                                              |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                         |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                       |
| **Proof test**                               | Network matrix tests A-\>B/B-\>A across TCP/UDP/DNS and restart/reconcile cycles.                                                                                                      |
| **Severity**                                 | **Critical**                                                                                                                                                                           |
| **Decision**                                 | **Fix**                                                                                                                                                                                |
| **Owner**                                    | Security + Platform                                                                                                                                                                    |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                            |

Q39. Are persistent volumes isolated strongly enough?

| **Question**                                 | Are persistent volumes isolated strongly enough?                                                                                                                        |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Volumes have opaque IDs, owner project/environment/service metadata and mount allowlists. Normal users cannot submit arbitrary host paths or another project volume ID. |
| **Security boundary**                        | SC-04 Filesystem and runtime-socket isolation; SC-22 Database and volume isolation                                                                                      |
| **Attack path**                              | Container guesses/mounts peer volume or symlink escapes volume root.                                                                                                    |
| **Impact**                                   | Cross-project persistent data theft/destruction.                                                                                                                        |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                          |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                        |
| **Proof test**                               | Mount authorization, path traversal, symlink race and IDOR tests across projects.                                                                                       |
| **Severity**                                 | **Critical**                                                                                                                                                            |
| **Decision**                                 | **Fix**                                                                                                                                                                 |
| **Owner**                                    | Security + Platform                                                                                                                                                     |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                             |

Q40. Why should databases be considered trusted?

| **Question**                                 | Why should databases be considered trusted?                                                                                                                 |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Database containers are not inherently trusted. They are workloads with project network/storage scope; compromise must not expose other projects or Tier-0. |
| **Security boundary**                        | SC-05 Network segmentation and egress policy; SC-22 Database and volume isolation                                                                           |
| **Attack path**                              | Exploit database service then scan host/other services.                                                                                                     |
| **Impact**                                   | Project data loss; lateral movement if segmentation fails.                                                                                                  |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                              |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                            |
| **Proof test**                               | Compromise fixture DB and run same lateral-movement suite as application containers.                                                                        |
| **Severity**                                 | **High**                                                                                                                                                    |
| **Decision**                                 | **Fix**                                                                                                                                                     |
| **Owner**                                    | Security + Platform                                                                                                                                         |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                 |

Q41. What prevents accidentally publishing a database?

| **Question**                                 | What prevents accidentally publishing a database?                                                                                                                                 |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Managed databases are private by default. Public exposure requires an explicit specialized policy, recent MFA and a warning; generic workload port publishing cannot expose them. |
| **Security boundary**                        | SC-11 Admin authentication and authorization; SC-12 Only edge can publish ports; SC-22 Database and volume isolation                                                              |
| **Attack path**                              | DB service binds 0.0.0.0:5432 and runtime publishes host port.                                                                                                                    |
| **Impact**                                   | Internet-exposed database.                                                                                                                                                        |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                    |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                  |
| **Proof test**                               | Template/API tests reject host publishing and external scan confirms private-only reachability.                                                                                   |
| **Severity**                                 | **Critical**                                                                                                                                                                      |
| **Decision**                                 | **Fix**                                                                                                                                                                           |
| **Owner**                                    | Security + Platform                                                                                                                                                               |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                       |

Q42. What happens if the OpenDeploy update server is compromised?

| **Question**                                 | What happens if the OpenDeploy update server is compromised?                                                                                                  |
|----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | The updater is treated as Tier-0 supply chain. Clients trust threshold-signed TUF-style metadata and pinned root keys, not merely HTTPS or one update server. |
| **Security boundary**                        | SC-18 Hardened updater with TUF model; SC-19 Supply-chain provenance and pinning                                                                              |
| **Attack path**                              | Compromised update origin serves malicious binary/manifest.                                                                                                   |
| **Impact**                                   | Host-level compromise of all workloads.                                                                                                                       |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                              |
| **Proof test**                               | Serve unsigned, wrong-key, rollback, expired and mix-and-match metadata; updater must fail closed.                                                            |
| **Severity**                                 | **Critical**                                                                                                                                                  |
| **Decision**                                 | **Redesign**                                                                                                                                                  |
| **Owner**                                    | Security + Platform                                                                                                                                           |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                   |

Q43. Where are signing keys stored?

| **Question**                                 | Where are signing keys stored?                                                                                                                                                                                             |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Root/targets signing keys are offline or hardware-backed with threshold authorization (for example 2-of-3). Online timestamp/snapshot keys are separate and short-lived; release signing is CI-isolated with review/audit. |
| **Security boundary**                        | SC-18 Hardened updater with TUF model; SC-19 Supply-chain provenance and pinning                                                                                                                                           |
| **Attack path**                              | Developer/CI account compromise obtains single signing credential.                                                                                                                                                         |
| **Impact**                                   | Malicious trusted release.                                                                                                                                                                                                 |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                             |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                           |
| **Proof test**                               | Key-compromise game verifies one key cannot authorize root/targets release and rotation/revocation procedures work.                                                                                                        |
| **Severity**                                 | **Critical**                                                                                                                                                                                                               |
| **Decision**                                 | **Redesign**                                                                                                                                                                                                               |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                        |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                |

Q44. Can OpenDeploy automatically roll back a malicious update?

| **Question**                                 | Can OpenDeploy automatically roll back a malicious update?                                                                                                                                                                                     |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | A/B binary slots allow automatic rollback of a failed candidate update. But a valid update with irreversible schema migration cannot be blindly rolled back; migrations need compatibility flags, pre-update backup and explicit restore path. |
| **Security boundary**                        | SC-16 State integrity and bounded reconciliation; SC-18 Hardened updater with TUF model                                                                                                                                                        |
| **Attack path**                              | Signed buggy/malicious update starts then corrupts state/schema.                                                                                                                                                                               |
| **Impact**                                   | Platform outage/state loss.                                                                                                                                                                                                                    |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                 |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                               |
| **Proof test**                               | Inject update failure before/after migration; verify slot rollback where safe and restore-required gate where not.                                                                                                                             |
| **Severity**                                 | **High**                                                                                                                                                                                                                                       |
| **Decision**                                 | **Fix**                                                                                                                                                                                                                                        |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                            |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                    |

Q45. What happens if an upstream dependency is compromised?

| **Question**                                 | What happens if an upstream dependency is compromised?                                                                                                                                                       |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Pin upstream versions/digests; verify checksums/signatures where available; generate SBOM and provenance; scan dependencies/images; review high-risk changes and rebuild release artifacts in controlled CI. |
| **Security boundary**                        | SC-19 Supply-chain provenance and pinning                                                                                                                                                                    |
| **Attack path**                              | Compromised containerd/BuildKit/Caddy/dependency enters release.                                                                                                                                             |
| **Impact**                                   | Tier-0 or workload compromise.                                                                                                                                                                               |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                               |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                             |
| **Proof test**                               | CI policy fails on unpinned dependency, unexpected digest, missing provenance/SBOM or critical unapproved finding.                                                                                           |
| **Severity**                                 | **Critical**                                                                                                                                                                                                 |
| **Decision**                                 | **Fix**                                                                                                                                                                                                      |
| **Owner**                                    | Security + Platform                                                                                                                                                                                          |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                  |

Q46. Is the build reproducible?

| **Question**                                 | Is the build reproducible?                                                                                                                                                                                                                                                                          |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Perfect bit-for-bit reproducibility is a goal, not a universal guarantee across all language ecosystems. OpenDeploy records exact source SHA, builder/base-image digests, lockfiles and provenance so differences can be explained and policy can require reproducible modes for selected projects. |
| **Security boundary**                        | SC-19 Supply-chain provenance and pinning                                                                                                                                                                                                                                                           |
| **Attack path**                              | Same source resolves mutable base/dependency at different time.                                                                                                                                                                                                                                     |
| **Impact**                                   | Unexplained artifact drift; supply-chain ambiguity.                                                                                                                                                                                                                                                 |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                                                                      |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                                                                    |
| **Proof test**                               | Rebuild reference fixtures twice in clean workers; compare digests and provenance, flag nondeterministic inputs.                                                                                                                                                                                    |
| **Severity**                                 | **Medium**                                                                                                                                                                                                                                                                                          |
| **Decision**                                 | **Clarify/Fix**                                                                                                                                                                                                                                                                                     |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                                                                                 |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                                                                         |

Q47. Can an old deployment overwrite a newer deployment?

| **Question**                                 | Can an old deployment overwrite a newer deployment?                                                                                                                                                                     |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | No. An environment generation is assigned when the deployment request becomes desired. A late Build A may finish, but if its generation is older than desired generation it becomes Superseded and cannot auto-promote. |
| **Security boundary**                        | SC-08 Webhook authenticity, replay, ordering; SC-15 Generation-safe deployment promotion                                                                                                                                |
| **Attack path**                              | A is slow, B completes/promotes, then A finishes.                                                                                                                                                                       |
| **Impact**                                   | Production reverts to old commit.                                                                                                                                                                                       |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                          |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                        |
| **Proof test**                               | Concurrent-build test with forced delays verifies only newest desired generation promotes.                                                                                                                              |
| **Severity**                                 | **Critical**                                                                                                                                                                                                            |
| **Decision**                                 | **Fix**                                                                                                                                                                                                                 |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                     |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                             |

Q48. What happens if two deployments promote simultaneously?

| **Question**                                 | What happens if two deployments promote simultaneously?                                                                                                                                                                       |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Promotion uses a per-environment lock/CAS plus durable promotion_intent journal. Router update is tagged with deployment ID, verified, then DB pointer is committed; reconciliation resolves crashes between the two systems. |
| **Security boundary**                        | SC-15 Generation-safe deployment promotion; SC-16 State integrity and bounded reconciliation                                                                                                                                  |
| **Attack path**                              | Two promotion workers race or crash between router and DB updates.                                                                                                                                                            |
| **Impact**                                   | Route/state split-brain.                                                                                                                                                                                                      |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                              |
| **Proof test**                               | Race/kill tests at every promotion step; final route and DB must converge to one generation.                                                                                                                                  |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                  |
| **Decision**                                 | **Redesign**                                                                                                                                                                                                                  |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                           |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                   |

Q49. Is rollback actually independent of GitHub?

| **Question**                                 | Is rollback actually independent of GitHub?                                                                                                                                                                                                   |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Yes. Rollback uses retained local immutable image/static artifact and metadata, not a source rebuild. GitHub/webhook/DNS APIs are not required to switch an existing local route; public DNS must of course still resolve for Internet users. |
| **Security boundary**                        | SC-15 Generation-safe deployment promotion; SC-16 State integrity and bounded reconciliation                                                                                                                                                  |
| **Attack path**                              | Source provider unavailable/deleted during rollback.                                                                                                                                                                                          |
| **Impact**                                   | Inability to recover from bad release.                                                                                                                                                                                                        |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                              |
| **Proof test**                               | Disable GitHub/network API, then rollback to retained deployment and verify route changes locally.                                                                                                                                            |
| **Severity**                                 | **High**                                                                                                                                                                                                                                      |
| **Decision**                                 | **Accept + verify**                                                                                                                                                                                                                           |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                           |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                   |

Q50. What does “healthy” actually mean?

| **Question**                                 | What does “healthy” actually mean?                                                                                                                                                                                                                     |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Healthy is layered evidence: process started, startup check passed, readiness passes, optional dependency checks/smoke tests pass, and optionally an external synthetic request through the real domain. A single 200 health endpoint is insufficient. |
| **Security boundary**                        | SC-17 Layered health evidence                                                                                                                                                                                                                          |
| **Attack path**                              | App returns 200 from /health while auth/DB/payment path is broken.                                                                                                                                                                                     |
| **Impact**                                   | Bad release promoted.                                                                                                                                                                                                                                  |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                         |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                       |
| **Proof test**                               | Reference app with false /health but failing smoke journey must not promote when smoke gate enabled.                                                                                                                                                   |
| **Severity**                                 | **High**                                                                                                                                                                                                                                               |
| **Decision**                                 | **Fix**                                                                                                                                                                                                                                                |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                                    |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                            |

Q51. Can a malicious application fake its health check?

| **Question**                                 | Can a malicious application fake its health check?                                                                                                                                                  |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Yes, an application controls its own internal health endpoint and can lie. Therefore health is not a trust proof; use user-defined smoke tests and external synthetic checks for higher confidence. |
| **Security boundary**                        | SC-17 Layered health evidence                                                                                                                                                                       |
| **Attack path**                              | Malicious/broken app always returns success.                                                                                                                                                        |
| **Impact**                                   | Promotion of defective app.                                                                                                                                                                         |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                      |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                    |
| **Proof test**                               | Test fake health response versus independent synthetic transaction; document trust limits.                                                                                                          |
| **Severity**                                 | **Medium**                                                                                                                                                                                          |
| **Decision**                                 | **Accept with limitation**                                                                                                                                                                          |
| **Owner**                                    | Security + Platform                                                                                                                                                                                 |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                         |

Q52. What prevents configuration corruption?

| **Question**                                 | What prevents configuration corruption?                                                                                                                                                                                                                          |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | State protection combines SQLite WAL/durable transactions, foreign keys/invariants, transactional migrations, checksummed snapshots and startup integrity checks. If core invariants fail, enter degraded read-only mode rather than destructive reconciliation. |
| **Security boundary**                        | SC-16 State integrity and bounded reconciliation                                                                                                                                                                                                                 |
| **Attack path**                              | Metadata corruption produces wrong desired-state graph.                                                                                                                                                                                                          |
| **Impact**                                   | Wrong containers/routes/volumes changed or deleted.                                                                                                                                                                                                              |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                                   |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                                 |
| **Proof test**                               | Corrupt DB pages/rows/invariants in fixtures; verify detection, read-only mode and recovery from snapshot.                                                                                                                                                       |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                                                     |
| **Decision**                                 | **Fix**                                                                                                                                                                                                                                                          |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                                              |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                                      |

Q53. Can desired state and actual state diverge permanently?

| **Question**                                 | Can desired state and actual state diverge permanently?                                                                                                                                                         |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Reconciliation is generation-aware, idempotent and bounded with exponential backoff and circuit breaker. Persistent divergence becomes Degraded with operator-visible reason instead of an infinite tight loop. |
| **Security boundary**                        | SC-16 State integrity and bounded reconciliation                                                                                                                                                                |
| **Attack path**                              | Runtime repeatedly fails to reach desired state.                                                                                                                                                                |
| **Impact**                                   | Resource exhaustion/log storm/unstable workloads.                                                                                                                                                               |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                  |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                |
| **Proof test**                               | Inject permanent runtime error; verify retry budget, circuit break and explicit recovery action.                                                                                                                |
| **Severity**                                 | **High**                                                                                                                                                                                                        |
| **Decision**                                 | **Fix**                                                                                                                                                                                                         |
| **Owner**                                    | Security + Platform                                                                                                                                                                                             |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                     |

Q54. If OpenDeploy is compromised, what evidence remains?

| **Question**                                 | If OpenDeploy is compromised, what evidence remains?                                                                                                                                                                                                                                     |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Security audit records actor, session/MFA, source address, GitHub delivery/installation, commit, artifact digest, secret metadata changes, domain changes, privileged capability use and platform updates. Off-host/WORM export is required for strong evidence against node compromise. |
| **Security boundary**                        | SC-20 Tamper-evident security audit                                                                                                                                                                                                                                                      |
| **Attack path**                              | Attacker changes deploy/domain/secret/update then erases local logs.                                                                                                                                                                                                                     |
| **Impact**                                   | Loss of incident attribution.                                                                                                                                                                                                                                                            |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                                                           |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                                                         |
| **Proof test**                               | Perform representative privileged operations and compromise simulation; verify immutable remote event sequence can reconstruct timeline.                                                                                                                                                 |
| **Severity**                                 | **High**                                                                                                                                                                                                                                                                                 |
| **Decision**                                 | **Fix**                                                                                                                                                                                                                                                                                  |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                                                                      |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                                                              |

Q55. Are security events separated from application logs?

| **Question**                                 | Are security events separated from application logs?                                                                                                                                                   |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Yes. Application logs are explicitly untrusted and stored separately. Security events are emitted by auditd/control-plane with typed event IDs; strings printed by an app cannot become audit records. |
| **Security boundary**                        | SC-20 Tamper-evident security audit                                                                                                                                                                    |
| **Attack path**                              | App prints ADMIN_LOGIN_SUCCESS/DEPLOYMENT_APPROVED to stdout.                                                                                                                                          |
| **Impact**                                   | Log-forgery confusion during incident response.                                                                                                                                                        |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                         |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                       |
| **Proof test**                               | Fixture forges security-looking lines; UI/export must keep them in workload log stream only.                                                                                                           |
| **Severity**                                 | **High**                                                                                                                                                                                               |
| **Decision**                                 | **Fix**                                                                                                                                                                                                |
| **Owner**                                    | Security + Platform                                                                                                                                                                                    |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                            |

Q56. Are backups themselves a secret-exfiltration target?

| **Question**                                 | Are backups themselves a secret-exfiltration target?                                                                                                                                      |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Backups are high-value secrets. Encrypt before leaving the node using per-backup data keys, wrap keys separately, authenticate metadata, restrict readers and retain versioned manifests. |
| **Security boundary**                        | SC-21 Backup confidentiality and deletion resistance                                                                                                                                      |
| **Attack path**                              | Attacker steals backup object.                                                                                                                                                            |
| **Impact**                                   | Databases, secrets, certificates and config exposed.                                                                                                                                      |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                            |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                          |
| **Proof test**                               | Restore with correct key succeeds; object without wrapping key reveals no plaintext; tamper changes are detected.                                                                         |
| **Severity**                                 | **Critical**                                                                                                                                                                              |
| **Decision**                                 | **Fix**                                                                                                                                                                                   |
| **Owner**                                    | Security + Platform                                                                                                                                                                       |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                               |

Q57. Can a compromised OpenDeploy instance destroy its own backups?

| **Question**                                 | Can a compromised OpenDeploy instance destroy its own backups?                                                                                                                                                                   |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Use off-host storage and, where possible, credentials that can create new versioned/immutable objects but cannot delete/overwrite existing backups. Backup deletion/admin credentials are not stored in normal platform runtime. |
| **Security boundary**                        | SC-21 Backup confidentiality and deletion resistance                                                                                                                                                                             |
| **Attack path**                              | Compromised node uses backup credentials to delete all recovery points.                                                                                                                                                          |
| **Impact**                                   | Ransomware/data destruction with no recovery.                                                                                                                                                                                    |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                   |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                 |
| **Proof test**                               | Compromise platform backup credential and attempt delete/overwrite; provider policy must deny.                                                                                                                                   |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                     |
| **Decision**                                 | **Redesign**                                                                                                                                                                                                                     |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                              |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                      |

Q58. Is the control plane a single point of trust?

| **Question**                                 | Is the control plane a single point of trust?                                                                                                                                                                                                                                                               |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Yes, a single node has a single Tier-0 trust domain. v2 limits direct root paths through service separation but does not claim that a platformd/host-root compromise is isolated to one project. Production documentation explicitly requires node rebuild and credential rotation after Tier-0 compromise. |
| **Security boundary**                        | SC-10 Tier-0 control-plane split; SC-20 Tamper-evident security audit                                                                                                                                                                                                                                       |
| **Attack path**                              | Exploit Tier-0 service on single node.                                                                                                                                                                                                                                                                      |
| **Impact**                                   | All node workloads/credentials potentially affected.                                                                                                                                                                                                                                                        |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                                                                              |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                                                                            |
| **Proof test**                               | Tabletop and automated incident drill validates rebuild, secret rotation and restore procedures.                                                                                                                                                                                                            |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                                                                                                |
| **Decision**                                 | **Accept with explicit limitation**                                                                                                                                                                                                                                                                         |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                                                                                         |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                                                                                 |

Q59. What does “any project” actually mean?

| **Question**                                 | What does “any project” actually mean?                                                                                                                                                                                                                                |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | “Any project” means any source code that can produce a compatible Linux OCI image or static artifact and operate within supported capability policies. It does not mean arbitrary desktop apps, kernels, drivers or workloads requiring unrestricted host privileges. |
| **Security boundary**                        | SC-01 Trust classes and fail-closed policy; SC-23 Special-capability workload policy                                                                                                                                                                                  |
| **Attack path**                              | User imports workload outside Linux OCI/static contract.                                                                                                                                                                                                              |
| **Impact**                                   | Unsupported behavior/security exceptions.                                                                                                                                                                                                                             |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                                        |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                                      |
| **Proof test**                               | Compatibility tests and UI detection produce explicit unsupported/capability-needed result rather than unsafe guessing.                                                                                                                                               |
| **Severity**                                 | **Medium**                                                                                                                                                                                                                                                            |
| **Decision**                                 | **Clarify**                                                                                                                                                                                                                                                           |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                                                   |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                                           |

Q60. What happens when a project requires special host capabilities?

| **Question**                                 | What happens when a project requires special host capabilities?                                                                                                                                                                                                     |
|----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Special host capabilities are denied by default. GPU/USB/FUSE/special devices can be added through explicit audited capability plugins where support exists; host networking/kernel modules/privileged syscalls move the workload into Unsafe mode or are rejected. |
| **Security boundary**                        | SC-23 Special-capability workload policy                                                                                                                                                                                                                            |
| **Attack path**                              | Project requests /dev, host network, FUSE, module load or privileged syscall.                                                                                                                                                                                       |
| **Impact**                                   | Expanded host escape/blast radius.                                                                                                                                                                                                                                  |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                                      |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                                    |
| **Proof test**                               | Capability-policy matrix tests each device/feature and verifies normal-mode rejection plus warnings/audit for approved exceptions.                                                                                                                                  |
| **Severity**                                 | **High**                                                                                                                                                                                                                                                            |
| **Decision**                                 | **Fix**                                                                                                                                                                                                                                                             |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                                                 |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                                         |

Q61. Where exactly is authentication performed?

| **Question**                                 | Where exactly is authentication performed?                                                                                                                                                                                                                                                                              |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Authentication is layer-specific: relay tunnel uses instance mTLS/rotating credentials; domain claim uses DNS TXT proof; public application authentication belongs to the application/optional edge middleware; admin API uses OpenDeploy IAM/MFA. No layer may treat another layer identity as administrator identity. |
| **Security boundary**                        | SC-11 Admin authentication and authorization; SC-13 Relay is metadata-trusted, not plaintext-trusted; SC-14 Domain claim lifecycle                                                                                                                                                                                      |
| **Attack path**                              | Relay/domain/app identity is confused with admin or another trust layer.                                                                                                                                                                                                                                                |
| **Impact**                                   | Authentication bypass or cross-tenant routing.                                                                                                                                                                                                                                                                          |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                                                                                          |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                                                                                        |
| **Proof test**                               | Identity-confusion integration tests replay credentials/tokens across layers; all wrong-context uses fail.                                                                                                                                                                                                              |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                                                                                                            |
| **Decision**                                 | **Redesign**                                                                                                                                                                                                                                                                                                            |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                                                                                                     |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                                                                                             |

Q62. Can the relay impersonate the destination application?

| **Question**                                 | Can the relay impersonate the destination application?                                                                                                                                                                                                                |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | With TLS pass-through/SNI routing, the relay lacks the private key used by local Caddy and cannot transparently impersonate the application to a standards-compliant client. It can still deny service or route to an endpoint that will fail certificate validation. |
| **Security boundary**                        | SC-13 Relay is metadata-trusted, not plaintext-trusted                                                                                                                                                                                                                |
| **Attack path**                              | Compromised relay terminates/modifies traffic or redirects to attacker endpoint.                                                                                                                                                                                      |
| **Impact**                                   | MITM if endpoint key/trust also compromised; otherwise DoS.                                                                                                                                                                                                           |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                                        |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                                      |
| **Proof test**                               | TLS capture and wrong-backend tests verify client rejects relay impersonation and payload is opaque at relay.                                                                                                                                                         |
| **Severity**                                 | **High**                                                                                                                                                                                                                                                              |
| **Decision**                                 | **Fix**                                                                                                                                                                                                                                                               |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                                                   |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                                           |

Q63. What if an application obtains the container runtime socket?

| **Question**                                 | What if an application obtains the container runtime socket?                                                                                                                                         |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | The runtime socket is never mounted into applications. If a regression exposes it, assume Tier-0 compromise potential and trigger critical incident handling; this is a mandatory release-gate test. |
| **Security boundary**                        | SC-04 Filesystem and runtime-socket isolation; SC-10 Tier-0 control-plane split                                                                                                                      |
| **Attack path**                              | App obtains containerd/Docker/runtimed control socket.                                                                                                                                               |
| **Impact**                                   | Arbitrary workload launch/host compromise.                                                                                                                                                           |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                       |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                     |
| **Proof test**                               | Every runtime class checks path, inherited FD and socket connectivity for known control endpoints; must fail.                                                                                        |
| **Severity**                                 | **Critical**                                                                                                                                                                                         |
| **Decision**                                 | **Fix/Test gate**                                                                                                                                                                                    |
| **Owner**                                    | Security + Platform                                                                                                                                                                                  |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                          |

Q64. What if a malicious Dockerfile tries to access the host filesystem?

| **Question**                                 | What if a malicious Dockerfile tries to access the host filesystem?                                                                                                                   |
|----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | A malicious Dockerfile executes only within the selected build boundary. It receives an ephemeral workspace, not host roots/platform paths; untrusted sources use stronger isolation. |
| **Security boundary**                        | SC-02 Untrusted workload sandbox; SC-03 Rootless build boundary; SC-04 Filesystem and runtime-socket isolation                                                                        |
| **Attack path**                              | Dockerfile reads /etc, /var/lib/opendeploy, host mounts or symlink-escapes workspace.                                                                                                 |
| **Impact**                                   | Host/config/secret exposure.                                                                                                                                                          |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                        |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                      |
| **Proof test**                               | Malicious Dockerfile suite attempts bind/path/symlink/proc escapes; host sentinel files must remain unreadable/unmodified.                                                            |
| **Severity**                                 | **Critical**                                                                                                                                                                          |
| **Decision**                                 | **Fix/Test gate**                                                                                                                                                                     |
| **Owner**                                    | Security + Platform                                                                                                                                                                   |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                           |

Q65. What if a PR tries to access production secrets?

| **Question**                                 | What if a PR tries to access production secrets?                                                                              |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | A PR identity cannot request production secret handles, and public-fork/untrusted previews receive no sensitive secret scope. |
| **Security boundary**                        | SC-06 Secret broker and scope enforcement; SC-09 Preview isolation                                                            |
| **Attack path**                              | PR modifies code/config to print production secret.                                                                           |
| **Impact**                                   | Production credential theft.                                                                                                  |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                              |
| **Proof test**                               | Canary production secret exists; preview attempts all API/config references and must never receive it.                        |
| **Severity**                                 | **Critical**                                                                                                                  |
| **Decision**                                 | **Fix/Test gate**                                                                                                             |
| **Owner**                                    | Security + Platform                                                                                                           |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                   |

Q66. What if a PR tries to access the production database?

| **Question**                                 | What if a PR tries to access the production database?                                                      |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Preview network policy has no route to production database networks and no production DB credentials.      |
| **Security boundary**                        | SC-05 Network segmentation and egress policy; SC-09 Preview isolation; SC-22 Database and volume isolation |
| **Attack path**                              | PR scans/connects to production DB address/service name.                                                   |
| **Impact**                                   | Production data compromise.                                                                                |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                             |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                           |
| **Proof test**                               | Preview network scan plus direct DB connection attempts fail while preview-specific DB remains reachable.  |
| **Severity**                                 | **Critical**                                                                                               |
| **Decision**                                 | **Fix/Test gate**                                                                                          |
| **Owner**                                    | Security + Platform                                                                                        |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                |

Q67. What if two projects deliberately try to communicate?

| **Question**                                 | What if two projects deliberately try to communicate?                                                                                                                                   |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Projects are isolated by network namespace and default-deny cross-project policy. Deliberate communication works only through an explicit audited service link or public edge endpoint. |
| **Security boundary**                        | SC-05 Network segmentation and egress policy                                                                                                                                            |
| **Attack path**                              | A scans/connects directly to B private addresses.                                                                                                                                       |
| **Impact**                                   | Lateral movement.                                                                                                                                                                       |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                          |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                        |
| **Proof test**                               | Bidirectional TCP/UDP/DNS scan matrix must show no private cross-project path.                                                                                                          |
| **Severity**                                 | **High**                                                                                                                                                                                |
| **Decision**                                 | **Fix/Test gate**                                                                                                                                                                       |
| **Owner**                                    | Security + Platform                                                                                                                                                                     |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                             |

Q68. What if one project performs a network scan against the host?

| **Question**                                 | What if one project performs a network scan against the host?                                                                                                |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Application egress blocks host management addresses and local LAN/private ranges by default unless an administrator creates an explicit project egress rule. |
| **Security boundary**                        | SC-05 Network segmentation and egress policy                                                                                                                 |
| **Attack path**                              | App scans host gateway and local 192.168/10/172.16 networks.                                                                                                 |
| **Impact**                                   | Attack on host/LAN devices.                                                                                                                                  |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                               |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                             |
| **Proof test**                               | Run nmap/socket fixture against host/LAN/link-local/metadata; packets are dropped/logged by egress policy.                                                   |
| **Severity**                                 | **High**                                                                                                                                                     |
| **Decision**                                 | **Fix/Test gate**                                                                                                                                            |
| **Owner**                                    | Security + Platform                                                                                                                                          |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                  |

Q69. What if a container tries to reach \`localhost\` services?

| **Question**                                 | What if a container tries to reach \`localhost\` services?                                                                                                                                         |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Container localhost is only its sandbox. No host-loopback forwarding, host gateway alias or platform listener is injected; BuildKit rootless networking is configured with host-loopback disabled. |
| **Security boundary**                        | SC-03 Rootless build boundary; SC-05 Network segmentation and egress policy                                                                                                                        |
| **Attack path**                              | Workload connects to localhost/host gateway to reach host daemon.                                                                                                                                  |
| **Impact**                                   | Tier-0 access.                                                                                                                                                                                     |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                     |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                   |
| **Proof test**                               | Probe 127/8, ::1 and known host aliases/gateways from build/app; only sandbox-local services respond.                                                                                              |
| **Severity**                                 | **High**                                                                                                                                                                                           |
| **Decision**                                 | **Fix/Test gate**                                                                                                                                                                                  |
| **Owner**                                    | Security + Platform                                                                                                                                                                                |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                        |

Q70. What if a malicious application binds a public port directly?

| **Question**                                 | What if a malicious application binds a public port directly?                                                                                                   |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Binding a port inside a container does not publish it on host. Normal runtime rejects hostPort/hostNetwork and routemgr owns the only DNAT/public edge mapping. |
| **Security boundary**                        | SC-12 Only edge can publish ports                                                                                                                               |
| **Attack path**                              | Malicious app binds many ports and asks runtime to publish.                                                                                                     |
| **Impact**                                   | Edge bypass.                                                                                                                                                    |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                  |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                |
| **Proof test**                               | External scan before/after malicious deployment shows no new host listeners/public ports.                                                                       |
| **Severity**                                 | **Critical**                                                                                                                                                    |
| **Decision**                                 | **Fix/Test gate**                                                                                                                                               |
| **Owner**                                    | Security + Platform                                                                                                                                             |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                     |

Q71. What if an attacker gets an OpenDeploy admin session?

| **Question**                                 | What if an attacker gets an OpenDeploy admin session?                                                                                                                                                                                                                                        |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | A stolen admin session remains severe. Limit damage with short/rotating sessions, MFA-bound authentication, RBAC, sensitive-action re-auth, session/device revocation, IP/risk logging and no generic host shell. Credentials/secrets touched during the session may still require rotation. |
| **Security boundary**                        | SC-10 Tier-0 control-plane split; SC-11 Admin authentication and authorization; SC-20 Tamper-evident security audit                                                                                                                                                                          |
| **Attack path**                              | Attacker steals browser session and performs privileged actions.                                                                                                                                                                                                                             |
| **Impact**                                   | Project/Tier-0 changes within role.                                                                                                                                                                                                                                                          |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                                                               |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                                                             |
| **Proof test**                               | Replay stolen session after revoke/re-auth threshold; verify sensitive ops require fresh proof and incident audit is complete.                                                                                                                                                               |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                                                                                 |
| **Decision**                                 | **Redesign/Test gate**                                                                                                                                                                                                                                                                       |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                                                                          |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                                                                  |

Q72. What if a GitHub webhook is replayed?

| **Question**                                 | What if a GitHub webhook is replayed?                                                                                                                       |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Replay is blocked by delivery-ID dedupe, and even a replay outside the dedupe retention cannot auto-promote an older generation than current desired state. |
| **Security boundary**                        | SC-08 Webhook authenticity, replay, ordering; SC-15 Generation-safe deployment promotion                                                                    |
| **Attack path**                              | Replay a previously valid signed push webhook.                                                                                                              |
| **Impact**                                   | Stale deployment or resource abuse.                                                                                                                         |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                              |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                            |
| **Proof test**                               | Replay within/after dedupe window; no stale promotion and duplicate job is suppressed or marked superseded.                                                 |
| **Severity**                                 | **Critical**                                                                                                                                                |
| **Decision**                                 | **Fix/Test gate**                                                                                                                                           |
| **Owner**                                    | Security + Platform                                                                                                                                         |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                 |

Q73. What if GitHub sends events out of order?

| **Question**                                 | What if GitHub sends events out of order?                                                                                               |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Out-of-order events are normalized against repository/ref head and desired_generation. Completion order never defines production order. |
| **Security boundary**                        | SC-08 Webhook authenticity, replay, ordering; SC-15 Generation-safe deployment promotion                                                |
| **Attack path**                              | Webhook B arrives before A, or A arrives late after B.                                                                                  |
| **Impact**                                   | Old commit production.                                                                                                                  |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                          |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                        |
| **Proof test**                               | Permute webhook order and build completion order; final production must equal current desired generation.                               |
| **Severity**                                 | **Critical**                                                                                                                            |
| **Decision**                                 | **Fix/Test gate**                                                                                                                       |
| **Owner**                                    | Security + Platform                                                                                                                     |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                             |

Q74. What if an attacker controls a DNS record?

| **Question**                                 | What if an attacker controls a DNS record?                                                                                                                                                                                                                     |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | If an attacker legitimately controls authoritative DNS, they can satisfy domain ownership and redirect that domain; DNS is an external trust root. OpenDeploy limits this to domain routing and does not grant platform/admin/secret authority from DNS proof. |
| **Security boundary**                        | SC-14 Domain claim lifecycle                                                                                                                                                                                                                                   |
| **Attack path**                              | Attacker compromises registrar/DNS and sets TXT/A records.                                                                                                                                                                                                     |
| **Impact**                                   | Domain/application traffic takeover; not platform IAM takeover.                                                                                                                                                                                                |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                                 |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                               |
| **Proof test**                               | DNS-control test proves domain claim succeeds but admin/project secrets and unrelated domains remain inaccessible.                                                                                                                                             |
| **Severity**                                 | **High**                                                                                                                                                                                                                                                       |
| **Decision**                                 | **Accept trust-root limitation**                                                                                                                                                                                                                               |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                                            |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                                    |

Q75. What if a domain is deleted and immediately re-claimed?

| **Question**                                 | What if a domain is deleted and immediately re-claimed?                                                                                                |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Deleted/detached domain claims enter tombstone state and are never automatically assigned by stale DNS. New attachment requires a new nonce/TXT proof. |
| **Security boundary**                        | SC-14 Domain claim lifecycle                                                                                                                           |
| **Attack path**                              | Immediately re-create project with same hostname while stale DNS remains.                                                                              |
| **Impact**                                   | Dangling-domain takeover.                                                                                                                              |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                         |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                       |
| **Proof test**                               | Automated delete/reclaim race verifies no route until fresh ownership proof completes.                                                                 |
| **Severity**                                 | **Critical**                                                                                                                                           |
| **Decision**                                 | **Fix/Test gate**                                                                                                                                      |
| **Owner**                                    | Security + Platform                                                                                                                                    |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                            |

Q76. What if the relay is compromised?

| **Question**                                 | What if the relay is compromised?                                                                                                                                                                                                              |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Relay compromise can reveal metadata, disrupt/route connections and potentially target tunnel availability, but end-to-end application TLS and tenant route authorization should prevent plaintext inspection and cross-tenant backend access. |
| **Security boundary**                        | SC-13 Relay is metadata-trusted, not plaintext-trusted                                                                                                                                                                                         |
| **Attack path**                              | Take control of relay process/database.                                                                                                                                                                                                        |
| **Impact**                                   | Metadata disclosure and DoS; cross-tenant/plaintext if controls fail.                                                                                                                                                                          |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                 |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                               |
| **Proof test**                               | Red-team relay with route-table tampering, packet capture and tenant confusion tests; client TLS and instance auth must contain it.                                                                                                            |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                                   |
| **Decision**                                 | **Redesign/Test gate**                                                                                                                                                                                                                         |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                            |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                    |

Q77. What if a relay credential is stolen?

| **Question**                                 | What if a relay credential is stolen?                                                                                                          |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | A tunnel credential is scoped to one instance and its authorized routes, expires/rotates, and can be revoked without changing project secrets. |
| **Security boundary**                        | SC-13 Relay is metadata-trusted, not plaintext-trusted                                                                                         |
| **Attack path**                              | Steal instance A credential and connect as B or enumerate all user routes.                                                                     |
| **Impact**                                   | Limited tunnel impersonation if not scoped.                                                                                                    |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                 |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                               |
| **Proof test**                               | Credential replay against other instance/tenant/domain is denied; revoke/rotate live with no stale authorization.                              |
| **Severity**                                 | **High**                                                                                                                                       |
| **Decision**                                 | **Fix/Test gate**                                                                                                                              |
| **Owner**                                    | Security + Platform                                                                                                                            |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                    |

Q78. What if the update signing infrastructure is compromised?

| **Question**                                 | What if the update signing infrastructure is compromised?                                                                                                                                                                                       |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Compromise of one online signing key must not authorize a release. Threshold offline root/targets signing, role separation, expiry and root-key rotation provide recovery; total root-threshold compromise requires out-of-band trust recovery. |
| **Security boundary**                        | SC-18 Hardened updater with TUF model; SC-19 Supply-chain provenance and pinning                                                                                                                                                                |
| **Attack path**                              | Attacker obtains CI/update-server key and signs malware.                                                                                                                                                                                        |
| **Impact**                                   | Host-level supply-chain compromise.                                                                                                                                                                                                             |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                  |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                |
| **Proof test**                               | Exercise one-key compromise, key revocation and root rotation; updater rejects release lacking threshold trust.                                                                                                                                 |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                                    |
| **Decision**                                 | **Redesign/Test gate**                                                                                                                                                                                                                          |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                             |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                     |

Q79. What if a legitimate signed update is malicious due to supply-chain compromise?

| **Question**                                 | What if a legitimate signed update is malicious due to supply-chain compromise?                                                                                                                                                                         |
|----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Cryptographic validity cannot prove benevolence. Reduce malicious-insider/supply-chain risk with multi-party release approval, isolated reproducible/provenance-producing CI, SBOM/scans, staged canary rollout, transparency and fast revoke/rollback. |
| **Security boundary**                        | SC-18 Hardened updater with TUF model; SC-19 Supply-chain provenance and pinning                                                                                                                                                                        |
| **Attack path**                              | Authorized threshold release contains malicious logic.                                                                                                                                                                                                  |
| **Impact**                                   | Fleet/node compromise despite valid signature.                                                                                                                                                                                                          |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                                          |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                                        |
| **Proof test**                               | Canary fault injection and signed-bad-release tabletop verify staged stop, metadata revoke and recovery path.                                                                                                                                           |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                                            |
| **Decision**                                 | **Fix/Test gate**                                                                                                                                                                                                                                       |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                                     |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                                             |

Q80. What if the control-plane database contains inconsistent desired state?

| **Question**                                 | What if the control-plane database contains inconsistent desired state?                                                                                                                                                                   |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Current architecture (v2.0)**              | Before acting, platformd validates schema/version/invariants and runs integrity checks. Ambiguous/corrupt desired state triggers degraded read-only mode; reconciliation will not delete/reattach routes/volumes until repaired/restored. |
| **Security boundary**                        | SC-16 State integrity and bounded reconciliation                                                                                                                                                                                          |
| **Attack path**                              | DB contains inconsistent project/volume/domain/deployment relationships.                                                                                                                                                                  |
| **Impact**                                   | Destructive incorrect reconciliation.                                                                                                                                                                                                     |
| **Existing mitigation from v1.0**            | v1 has partial controls but does not fully prove the boundary.                                                                                                                                                                            |
| **Missing mitigation / implementation work** | v2 requires an enforceable control plus a negative test before this is resolved.                                                                                                                                                          |
| **Proof test**                               | Fault-inject inconsistent rows/checksum corruption; verify no destructive action and deterministic restore/recovery report.                                                                                                               |
| **Severity**                                 | **Critical**                                                                                                                                                                                                                              |
| **Decision**                                 | **Fix/Test gate**                                                                                                                                                                                                                         |
| **Owner**                                    | Security + Platform                                                                                                                                                                                                                       |
| **Resolution status**                        | SPECIFIED - NOT RESOLVED until implementation exists and proof test passes.                                                                                                                                                               |

## 29.1 Highest-Priority Closure Gate

The supplied red-team review identifies 15 questions that must be answered first. v2.0 treats them as release-blocking capabilities: a written mitigation is insufficient until the negative proof test passes on every supported host profile where the capability is enabled.

| **Q** | **Highest-priority risk**                                       | **Required controls**                    | **Release proof**                                                                                                                   |
|-------|-----------------------------------------------------------------|------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| Q1    | What exactly is the security boundary of OpenDeploy?            | SC-01; SC-02; SC-04; SC-05; SC-10        | Run escape, mount, socket, secret and cross-network negative tests from a fully compromised Project A.                              |
| Q2    | Is the container really considered a security boundary?         | SC-01; SC-02                             | Execute known escape-regression and adversarial syscall suites against runc and untrusted sandbox profiles.                         |
| Q9    | Can a malicious application read another application's secrets? | SC-06                                    | Property/integration tests attempt cross-tenant secret ID access and verify deny + audit.                                           |
| Q7    | Can BuildKit access containerd?                                 | SC-03; SC-04; SC-10                      | Assert socket absent at filesystem and namespace level; connection and inherited-FD tests fail.                                     |
| Q19   | Can preview environments access production secrets?             | SC-06; SC-09                             | Attempt direct, guessed-ID and config-reference access from preview; all denied and audited.                                        |
| Q18   | Can preview environments access production databases?           | SC-05; SC-09; SC-22                      | Preview fixture scans/calls production DB; firewall and service identity deny it.                                                   |
| Q26   | Is there MFA?                                                   | SC-11; SC-20                             | Automated auth tests for MFA enforcement, throttling, rotation, revocation and stale-session denial.                                |
| Q31   | Is Caddy the only Internet-facing component?                    | SC-12                                    | Runtime request with published host port must be rejected; host socket inventory must show only approved listeners.                 |
| Q27   | What does the relay actually know?                              | SC-13                                    | Packet capture at relay verifies payload remains TLS ciphertext and local Caddy owns certificate key.                               |
| Q29   | What happens if a relay credential is stolen?                   | SC-13                                    | Use credential from instance A against B/other tenant routes; deny and audit; rotate credential live.                               |
| Q34   | Can an attacker claim another user's domain?                    | SC-14                                    | Attempt claim without current TXT token and with another project active; deny.                                                      |
| Q16   | Can an attacker replay an old valid webhook?                    | SC-08; SC-15                             | Replay and reorder signed webhook fixtures; only current generation can auto-promote.                                               |
| Q42   | What happens if the OpenDeploy update server is compromised?    | SC-18; SC-19                             | Serve unsigned, wrong-key, rollback, expired and mix-and-match metadata; updater must fail closed.                                  |
| Q21   | What happens if the OpenDeploy control plane is compromised?    | SC-10; SC-20                             | Compromise simulation verifies platformd lacks raw host shell/socket, then run credential-rotation and node-rebuild incident drill. |
| Q37   | What is the blast radius of a compromised application?          | SC-01; SC-02; SC-04; SC-05; SC-06; SC-22 | Red-team compromised-container suite validates boundaries and records residual risks.                                               |

| **Closure rule** These questions stay SPECIFIED - NOT RESOLVED until implementation exists, CI/lab negative tests pass, and the release gate blocks regression. Any host profile that cannot enforce the required control must disable the affected capability rather than silently weaken isolation. |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

# 30. Mandatory Security and Chaos Test Matrix

| **Test** | **Scenario**                             | **Covers**                            | **Pass condition**                                                                                                              |
|----------|------------------------------------------|---------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| ST-01    | Malicious build filesystem/socket escape | Q4, Q6-Q8, Q63-Q64                    | Malicious Dockerfile/build hooks cannot read host/platform sentinel files, access runtime/control sockets, or escape workspace. |
| ST-02    | Build/preview egress isolation           | Q5, Q18, Q20, Q66-Q69                 | No path to host/LAN/link-local/metadata/other projects; only approved external dependency targets.                              |
| ST-03    | Secret boundary                          | Q9-Q12, Q19, Q65                      | Cross-project/prod-preview secret requests fail; untrusted build receives no prod secret; exact leak canaries are detected.     |
| ST-04    | Runtime/public port boundary             | Q1-Q3, Q31-Q32, Q37-Q41, Q63, Q67-Q70 | No peer/host/runtime-socket access; no direct host listener; database remains private.                                          |
| ST-05    | GitHub authenticity/order                | Q13-Q16, Q47, Q72-Q73                 | Forged/replayed/out-of-order events cannot authorize stale production; revoked access stops new source builds.                  |
| ST-06    | Admin/RBAC/session                       | Q21-Q26, Q54-Q55, Q71                 | Role matrix/IDOR tests, MFA/re-auth, wildcard-bind refusal, session revoke and audit separation pass.                           |
| ST-07    | Relay isolation                          | Q27-Q30, Q61-Q62, Q76-Q77             | Relay cannot see HTTPS plaintext, cross tenant routes or use one instance credential for another.                               |
| ST-08    | Domain lifecycle                         | Q34-Q36, Q74-Q75                      | Fresh TXT proof required, replay/expiry rejected, stale DNS/tombstone cannot rebind domain.                                     |
| ST-09    | Promotion/state crash consistency        | Q47-Q53, Q80                          | Kill/race at every state transition; route + DB converge; corruption enters degraded read-only mode.                            |
| ST-10    | Update/supply-chain compromise           | Q42-Q46, Q78-Q79                      | Wrong/expired/rollback/single-key metadata rejected; provenance/SBOM gates; staged bad release can be halted/revoked.           |
| ST-11    | Backup compromise/restore                | Q56-Q57                               | Backup plaintext unavailable without key; runtime credential cannot delete protected copies; clean-node restore succeeds.       |
| ST-12    | Tier-0 incident drill                    | Q21, Q58, Q71, Q78-Q80                | Preserve remote audit, isolate node, rotate credentials, rebuild and restore within documented runbook.                         |

## 30.1 Release gate rule

| **No paper-only closure** An adversarial question is not marked resolved simply because this document describes a mitigation. The associated implementation must exist, its negative test must run on every applicable release, and failures must block release or explicitly block the affected capability/host profile. |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

# 31. Example Project Configuration

Auto-detection should work without this file. opendeploy.yaml makes security, build and release decisions explicit and reviewable.

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th>version: 2<br />
project: example-api<br />
<br />
source:<br />
production_branch: main<br />
trust: trusted # trusted | untrusted | privileged<br />
<br />
build:<br />
strategy: auto # auto | buildpacks | nixpacks | dockerfile | static<br />
root: .<br />
network_policy: dependency # dependency | restricted | offline<br />
timeout: 20m<br />
<br />
runtime:<br />
type: web # web | worker | cron | static<br />
port: 8080<br />
sandbox: auto # auto | runc | gvisor | vm<br />
read_only_root: true<br />
capabilities: [] # special capabilities require admin policy<br />
<br />
health:<br />
startup:<br />
path: /health/startup<br />
grace: 45s<br />
readiness:<br />
path: /health/ready<br />
smoke:<br />
- name: homepage<br />
request: GET /<br />
expect_status: 200<br />
<br />
resources:<br />
memory: 512Mi<br />
cpu: 1.0<br />
pids: 256<br />
<br />
egress:<br />
internet: true<br />
allow_private_networks: false<br />
allow_hosts: []<br />
<br />
release:<br />
zero_downtime: true<br />
keep_deployments: 5<br />
auto_promote: true<br />
<br />
previews:<br />
enabled: true<br />
public_forks: false<br />
secrets_scope: preview<br />
database: ephemeral<br />
max_active: 3<br />
<br />
volumes:<br />
- name: uploads<br />
mount: /app/uploads<br />
backup: daily</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

# 32. Suggested Source Repository Layout

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th>/cmd<br />
/opendeploy-hostd # native host service<br />
/platformd # project/Git/deployment/API orchestrator<br />
/builderd # build worker manager<br />
/artifactd # OCI/static artifact validator/importer<br />
/runtimed # containerd/runsc runtime broker<br />
/secretd # encrypted scoped secret service<br />
/routemgr # Caddy/domain/promotion route manager<br />
/egressd # outbound policy/firewall manager<br />
/auditd # typed tamper-evident security audit<br />
/relay-agent<br />
/opendeployctl<br />
/internal<br />
/auth /rbac /git /projects /deploy /state /domains<br />
/build /runtime /sandbox /network /secrets /storage<br />
/backup /update /audit /platform<br />
/web<br />
/guest # managed Linux data plane rootfs/kernel definitions<br />
/builders # pinned buildpack/Nixpacks metadata and adapters<br />
/security # policies, profiles, threat model, test fixtures<br />
/relay-server<br />
/packaging<br />
/linux /windows /macos<br />
/tests<br />
/unit /integration /e2e /adversarial /chaos /upgrade /restore<br />
/docs</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

# 33. Research References

Architecture decisions were cross-checked against current upstream documentation. URLs below are implementation references, not an assertion that upstream defaults automatically satisfy OpenDeploy policy. Accessed 20 September 2026.

**\[R1\] GitHub Docs - Choosing permissions for a GitHub App.** https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app

**\[R2\] GitHub Docs - Validating webhook deliveries.** https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries

**\[R3\] GitHub Docs - Generating an installation access token for a GitHub App.** https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app

**\[R4\] BuildKit - Project security boundary.** https://github.com/moby/buildkit/blob/master/PROJECT.md

**\[R5\] BuildKit - Rootless mode.** https://github.com/moby/buildkit/blob/master/docs/rootless.md

**\[R6\] BuildKit Dockerfile reference - secrets and insecure entitlements.** https://github.com/moby/buildkit/blob/master/frontend/dockerfile/docs/reference.md

**\[R7\] gVisor - Introduction to security.** https://gvisor.dev/docs/architecture_guide/intro/

**\[R8\] gVisor - Security model.** https://gvisor.dev/docs/architecture_guide/security/

**\[R9\] Kata Containers.** https://katacontainers.io/

**\[R10\] Firecracker.** https://firecracker-microvm.github.io/

**\[R11\] OCI Runtime Specification.** https://specs.opencontainers.org/runtime-spec/

**\[R12\] Caddy API.** https://caddyserver.com/docs/api

**\[R13\] Caddy Automatic HTTPS.** https://caddyserver.com/docs/automatic-https

**\[R14\] The Update Framework - Metadata.** https://theupdateframework.io/docs/metadata/

**\[R15\] The Update Framework - Security.** https://theupdateframework.io/security/

**\[R16\] Sigstore Cosign - Verify.** https://docs.sigstore.dev/cosign/verifying/verify/

**\[R17\] SLSA - Build track.** https://slsa.dev/spec/v1.0/levels

**\[R18\] Microsoft Learn - Build a custom Linux distro for WSL.** https://learn.microsoft.com/en-us/windows/wsl/build-custom-distro

**\[R19\] Apple Developer - Running Linux in a Virtual Machine.** https://developer.apple.com/documentation/virtualization/running-linux-in-a-virtual-machine

**\[R20\] Coolify Docs - Preview Deployments.** https://coolify.io/docs/applications/deployments/preview-deployments

**\[R21\] Dokploy Docs - Preview Deployments.** https://docs.dokploy.com/docs/core/applications/preview-deployments

**\[R22\] CapRover - Getting Started.** https://caprover.com/docs/get-started.html

**\[R23\] Dokku - Dockerfile deployment.** https://dokku.com/docs/deployment/builders/dockerfiles/

# 34. Final Architecture Statement

| **OpenDeploy v2.0** Build OpenDeploy as a local-first, cross-platform control plane that converts source into immutable Linux OCI/static artifacts; runs each project behind explicit filesystem, network, secret and edge boundaries; treats hostile source with a stronger sandbox; makes deployment ordering generation-safe; keeps relay plaintext-blind; verifies domain ownership; and treats the updater/control plane as Tier-0 supply chain. The product succeeds when Git -\> Deploy -\> HTTPS remains simple for the user while compromise of one ordinary project does not automatically compromise every higher layer. |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

This specification is intentionally conservative about unresolved risk. A single-node host remains a single host trust/availability domain; authoritative DNS remains an external trust root; a fully authorized application can misuse the secrets it is given; and cryptographically valid software can still be malicious if trusted signers are compromised or colluding. Production-readiness therefore depends on both architecture and continuously passing proof tests.
