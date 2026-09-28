# OpenDeploy Threat Model (summary)

This is the working threat model the implementation enforces. The full
specification lives in [`docs/PRD.md`](../docs/PRD.md) §3 and §28–§30.

## Adversarial assumption
Every one of the following is treated as potentially malicious: the Git repository, its
Dockerfile, dependencies and build hooks, pull requests, the running application, its database
contents, webhook payloads, HTTP requests, domain configuration, admin sessions, relay
connections, third-party packages and update artifacts.

## Trust classes (`internal/trust`)
| Class | Build | Runtime | Secrets |
|---|---|---|---|
| Trusted | rootless BuildKit (OCI worker) | runc (hardened) or gVisor by policy | own environment scope |
| Untrusted | gVisor / VM sandbox | gVisor / VM | never production secrets; builds get none |
| Privileged | rootless BuildKit | runc + explicitly granted capability | own environment scope; MFA-gated grant |

`trust.Decide` is the single decision point. It is pure and fails closed:
- missing sandbox, missing network-policy enforcement or missing rootless build → error, never downgrade;
- a repository may lower but never raise its own trust;
- fork pull requests are always Untrusted and require `allow_public_forks`;
- capabilities need an administrator grant *and* host support; privileged previews are rejected.

## Tier-0 service split (`internal/identity`, `internal/ipc`)
Each service runs as its own Unix user (`od-<service>`) and exposes typed IPC operations over a
Unix socket. The server maps the kernel `SO_PEERCRED` UID to a service identity and checks it against
each operation's allowlist. Request bodies reject unknown fields. No operation takes a
command, script or arbitrary path; `internal/hostops` is the closed inventory of privileged
host operations.

## State integrity (`internal/state`, `internal/store`)
SQLite WAL + `synchronous=FULL` + foreign keys, a single serialized writer, checksummed contiguous
migrations, startup integrity and invariant checks, and checksummed snapshots. Any ambiguity that
could delete, reattach or misroute resources enters **degraded read-only mode**.

## Audit (`internal/audit`, `cmd/auditd`)
Typed events are accepted only from control-plane identities. The recorded `service` is
the kernel-verified caller. Events form a SHA-256 hash chain with append-only triggers.
Checkpoints are signed with Ed25519, and optional off-host NDJSON streaming is available.
Tampering, truncation or reordering is detected on startup and puts auditd into degraded mode.

## Residual risks (explicitly not solved)
- Kernel, sandbox or VMM zero-days can violate isolation boundaries.
- A compromised platformd is a node-wide incident: rebuild the node and rotate credentials.
- The relay sees routing metadata (SNI, IPs, timing, byte counts).
- Whoever controls authoritative DNS can legitimately prove domain control.
- A malicious release signed by an authorized threshold of signers remains possible.
- A single node's access link cannot absorb volumetric DDoS.
