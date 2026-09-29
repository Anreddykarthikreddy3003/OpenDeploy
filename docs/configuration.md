# Node configuration reference

Every OpenDeploy service reads **`/etc/opendeploy/node.yaml`**. The installer writes a commented starting point (`packaging/linux/etc/node.yaml`).

**Parsing is strict.** Unknown keys and invalid values stop the services from starting. That is deliberate: a typo in a security setting must never be ignored silently.

**After editing, restart:**
```sh
sudo systemctl restart opendeploy.target
```
Then check the host with `opendeployctl doctor`.

Defaults are shown in parentheses.

## Top level

| Key | Meaning |
|---|---|
| `profile` (`standard`) | `tiny` \| `standard` \| `performance`. Sets build concurrency (1/2/4). `tiny` also disables Untrusted workloads. |
| `data_dir` (`/var/lib/opendeploy`) | All node state. Each service owns a private subdirectory. |
| `run_dir` (`/run/opendeploy`) | Service sockets. |
| `dev_mode` (`false`) | One-process development node. It is refused unless `OPENDEPLOY_INSECURE_DEV=1` is also set. Never use it in production. |

## `api`: dashboard and API

| Key | Meaning |
|---|---|
| `listen` (`127.0.0.1:7070`; the package uses `127.0.0.1:8080`) | Admin listener. Any non-loopback address is refused unless remote administration is configured (below). |
| `public_url` | The external URL of the dashboard. Security keys (WebAuthn) are bound to this origin. |
| `trusted_proxies` | CIDRs whose `X-Forwarded-For` is honoured (rate limiting, audit source IP). |

### Remote administration

Loopback is the default. Reach the dashboard through an SSH tunnel:
```sh
ssh -L 8080:127.0.0.1:8080 node
```

To serve the dashboard on a network interface you must set **all** of these under `api.remote_admin`:

| Key | Meaning |
|---|---|
| `enabled: true` | Turns remote administration on. |
| `acknowledged_risk: true` | Explicit acknowledgement that the admin API will be reachable over the network. |
| `allowed_cidrs` | Source networks allowed to connect. |
| `tls_cert`, `tls_key` | The admin API is served only over TLS. |

MFA is mandatory for owners and admins either way.

## `ingress`: how apps are published

| Key | Meaning |
|---|---|
| `mode` (`lan`) | `lan`: plain HTTP on the local network (desktop nodes use `localhost` names). `direct`: a public IP with ACME certificates. `relay`: no inbound ports, traffic arrives through an OpenDeploy relay (see `docs/relay.md`). |
| `base_domain` | Generated URLs are `<project>.<base_domain>`. Point a wildcard DNS record at the node. |
| `acme_email`, `acme_ca` | ACME account email and CA URL (default Let's Encrypt). |
| `public_ipv4`, `public_ipv6` | Used to check that a custom domain's DNS routes to this node before it is attached. |
| `http_port` (80), `https_port` (443) | Edge ports. |
| `caddy_admin_socket` | Caddy's admin API socket. It is never exposed over TCP. |
| `dns_resolver` (`1.1.1.1:53`) | Resolver used to locate a domain's authoritative servers. TXT proofs are checked against those servers, not caches. |
| `limits.max_body_bytes` (100 MiB), `limits.requests_per_second` (200), `limits.max_conns_per_host` (1024) | Edge limits per host (SC-24). |
| `relay.*` | `server_addr`, `server_name`, `tenant_id`, `instance_id`, `public_suffix`, `enroll_token_file`, and optionally `ca_file`/`cert_file`/`key_file`. See `docs/relay.md`. |

## `runtime`

| Key | Meaning |
|---|---|
| `backend` (`containerd`) | `containerd` for production. `docker` is an adapter for development and CI. |
| `containerd_socket`, `containerd_namespace` (`opendeploy`) | Where runtimed reaches containerd. |
| `containerd_snapshotter` | Overrides containerd's default (overlayfs), e.g. `btrfs`, `zfs`, or `native` for nested/unusual filesystems. |
| `runc_handler`, `runsc_handler`, `vm_handler` | Runtime handlers for the Trusted, Untrusted and VM classes. Untrusted workloads fail closed when `runsc` is not installed. |
| `volumes_dir` | Persistent volumes. They are addressed by opaque ID, never by host path. |

## `build`

| Key | Meaning |
|---|---|
| `executor` (`buildkit`) | Rootless buildkitd via `buildctl`, or `docker` with the docker runtime backend. |
| `buildkit_addr` | Socket of the rootless buildkitd (`opendeploy-buildkitd.service`). |
| `untrusted_buildkit_addr`, `untrusted_runtime`, `untrusted_image`, `untrusted_network` | The sandboxed builder for Untrusted builds (gVisor). Without one, Untrusted builds fail closed. |
| `max_concurrent` | Parallel builds. The default comes from the profile. |
| `ca_bundle` | Extra PEM CA bundle for TLS-inspecting networks. See below. |

### Networks with TLS inspection

Install with:
```sh
sudo install.sh --ca-bundle corp-ca.pem
```
Or copy PEM files into `/etc/opendeploy/ca.d/` yourself.

- **Every service** trusts `/etc/ssl/certs` plus `/etc/opendeploy/ca.d` through `SSL_CERT_DIR`. That covers base-image pulls by rootless BuildKit, GitHub API calls, update checks and relay connections.
- **Build steps** receive the merged bundle as the BuildKit secret `opendeploy-ca`.
  - Generated Dockerfiles mount it into every `RUN` step and point `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `PIP_CERT`, `REQUESTS_CA_BUNDLE` and the like at it for that step only. It is never written into an image layer.
  - Your own Dockerfiles opt in per step:
    ```dockerfile
    RUN --mount=type=secret,id=opendeploy-ca,target=/run/secrets/opendeploy-ca \
        SSL_CERT_FILE=/run/secrets/opendeploy-ca npm ci
    ```

## `egress`

| Key | Meaning |
|---|---|
| `enforce` (`false`; the package uses `true`) | Applies per-environment nftables policy. It denies cross-project traffic, the host, RFC1918, link-local and cloud metadata. |
| `proxy_listen` (`0.0.0.0:3128`) | The build/preview egress proxy. It enforces the same deny ranges (SSRF-safe). The host firewall keeps it unreachable from outside. |
| `allowed_hosts` | Destinations reachable from restricted builds (e.g. registries). |
| `dns` | Resolvers handed to workloads. |

## `github`

| Key | Meaning |
|---|---|
| `app_id`, `app_slug` | The GitHub App identity. |
| `private_key_file`, `webhook_secret_file` | App credentials. Files must be mode 0600 or stricter. |
| `client_id`, `client_secret_file` | For "Sign in with GitHub" repository selection in the dashboard. |
| `api_url` | For GitHub Enterprise Server. |

The App requests only: Contents read, Pull requests read, Metadata read, and Checks write if check runs are enabled.

## `secrets`

| Key | Meaning |
|---|---|
| `kek_file` | secretd's key-encryption key. It is created on first start with mode 0600, owned by `od-secretd`. It is included in backups only in wrapped form. |

## `backup`

| Key | Meaning |
|---|---|
| `enabled`, `schedule` (`@daily`) | Scheduled backups. A backup can also run from the dashboard (Platform → Backups) at any time. |
| `endpoint`, `bucket`, `region`, `prefix` (`opendeploy/`), `use_ssl` | S3-compatible target. Without `endpoint`, backups go to `local_dir`. |
| `access_key_file`, `secret_key_file` | Use credentials **without** DeleteObject permission. |
| `object_lock`, `retain_days` (30) | Write with S3 Object Lock retention (compliance mode). |
| `master_key_file` | Wraps each backup's data key. Export it from the dashboard and store it off-host; restore needs it. |
| `include_artifacts` (`true`) | Keep rollback artifacts in backups. |
| `signer_public_key` | Pin the manifest signing key expected at restore time. |

## `update`

| Key | Meaning |
|---|---|
| `repository_url` | TUF repository (metadata and targets). Empty disables update checks. |
| `trusted_root` | The pinned TUF root (`/etc/opendeploy/tuf-root.json`). |
| `channel` (`stable`) | Release channel. |
| `slots_dir` (`/opt/opendeploy/slots`) | A/B release slots. |

Nodes check for updates on a schedule and show what is available. Only the owner can apply one, from Platform → Updates, and doing so requires re-authentication.

## `audit`

`forward` is a list of `{name, url, token_file}`. Each entry streams the hash-chained audit log to an off-host HTTPS collector, e.g. SIEM or WORM storage.

## `artifact`

| Key | Meaning |
|---|---|
| `registry_listen` (`127.0.0.1:5010`) | The node-local OCI registry that runtimed pulls from. |
| `max_image_bytes` (10 GiB) | Size limit for a single image artifact. |

## `identity`

`users` overrides the Unix user of a service identity, e.g. `{platformd: od-platformd}`. Only needed when the users created by the package are renamed.
