# OpenDeploy

**Git-to-production hosting on your own hardware.**

Connect GitHub, import a repository, and OpenDeploy detects, builds and deploys it with HTTPS and custom domains. Every push auto-deploys. It runs on Linux, and on Windows and macOS through a managed Linux guest.

OpenDeploy is built on the assumption that the code it runs may be hostile.

| Area | What OpenDeploy does |
|---|---|
| **Trust classes** | Every project is Trusted, Untrusted or Privileged. Untrusted code (and every fork preview) builds and runs under gVisor. If the sandbox isn't available, it fails closed. |
| **Split control plane** | Separate services under separate Unix users talk over peer-authenticated sockets. The only root component, hostd, exposes a closed set of typed operations and nothing that runs a command. |
| **Builds** | Rootless BuildKit with no entitlements, no runtime sockets and no host files. Egress is policy-filtered. |
| **Network** | Per-environment namespaces with nftables default-deny between projects, to the host, and to private/metadata ranges. Only the edge publishes ports. |
| **Secrets** | A dedicated broker with envelope encryption, file injection, and no production-to-preview inheritance. |
| **Deploys** | Generation-safe promotion: a late webhook can never overwrite a newer deploy. Crash-safe promotion journal, layered health checks, and instant rollback without GitHub. |
| **Domains** | A fresh TXT proof checked against authoritative DNS, plus tombstones, so stale DNS can't be hijacked. |
| **Relay** (optional) | Routes by SNI only. It never holds certificates and never sees plaintext. |
| **Admin** | Loopback by default. WebAuthn/TOTP MFA is mandatory for owners and admins. Sensitive actions require re-auth. |
| **Audit** | A tamper-evident, hash-chained log with signed checkpoints and off-host forwarding. |
| **Supply chain** | TUF-verified updates into A/B slots with automatic rollback. Releases are signed with SBOMs and SLSA provenance. |
| **Backups** | Encrypted client-side, with signed manifests, object-lock storage and clean-node restore. |

## Documentation

| Document | Contents |
|---|---|
| [Production readiness](docs/production-readiness.md) | What is proven and how, what the readiness pass fixed, what remains before GA |
| [Install](docs/install.md) | Linux packages, the Windows MSI, the macOS pkg, first login |
| [Configuration](docs/configuration.md) | Every `node.yaml` key |
| [Operations](docs/operations.md) | Deployments, backups, updates, domains, diagnostics |
| [Runbooks](docs/runbooks.md) | Compromise response, degraded mode, restore, lost MFA |
| [Relay](docs/relay.md) | Running and enrolling an OpenDeploy relay |
| [Security register](security/register.md) | Every threat question (Q1–Q80) and control (SC-01–SC-24), with the test that proves it |
| [Threat model](security/threat-model.md) | |
| [Product requirements](docs/PRD.md) | |

## Development

**Requirements:** Go (see `go.mod`) and Node 22.

```sh
cd web && npm ci && npm run build && cd ..       # dashboard (embedded into platformd)
make build                                        # all binaries into bin/
go test ./...                                     # unit + integration
bin/opendeployctl dev                             # single-process dev node: dashboard :8080, apps on *.localhost:8000 (Docker)
```

| Suite | Command |
|---|---|
| E2E deploys | `sudo go test -tags e2e ./tests/e2e/` (needs Docker and Caddy) |
| Adversarial | `sudo go test -tags adversarial ./tests/adversarial/` (needs gVisor and nftables) |
| Packaging | `.github/workflows/package.yml`, which installs the deb, boots the guest images and installs the MSI/pkg |

Releases are cut by pushing a `v*` tag. The release workflow runs every suite above on the tagged commit, and publishes only if all of them pass.
