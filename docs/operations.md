# Operating OpenDeploy

This guide covers day-to-day operation of a node. For incident response, see `docs/runbooks.md`. For every configuration key, see `docs/configuration.md`.

## Health at a glance

**Dashboard → Platform → Status** shows:
- the version and ingress mode;
- the edge route count;
- isolation capabilities (gVisor, rootless builds, network policy);
- relay tunnel state;
- audit chain integrity.

**On the host:**
```sh
opendeployctl doctor                      # capabilities and prerequisites
systemctl status 'opendeploy-*'           # one unit per service
journalctl -u opendeploy-platformd -f     # control plane log (JSON)
```

**Degraded read-only mode.** When a state invariant is violated, or the database fails its integrity check, platformd refuses changes. Running apps keep serving. Follow runbook R2.

## Deployments

| Task | How |
|---|---|
| Roll back | Open a previous deployment and choose **Roll back to this**, or run `opendeployctl rollback <deployment-id>`. A rollback reuses the retained artifact (no rebuild, no GitHub access) and becomes a new generation. |
| Stale events | A late or replayed webhook can never overwrite a newer deployment: only the environment's current generation may promote. |
| Build logs | `opendeployctl logs <deployment-id> -f` |
| Runtime logs | `opendeployctl runtime-logs <project>` |

## Backups

1. Configure a target under `backup:` in `node.yaml`. Use S3 with Object Lock, and credentials that can write but not delete.
   - Create the bucket with Object Lock enabled (which also enables versioning) and set `object_lock: true` and `retain_days`. Objects are written in compliance mode: nobody, including the storage administrator, can delete them before the retention date.
   - Give the node a policy with only `s3:PutObject`, `s3:GetObject`, `s3:PutObjectRetention`, `s3:GetObjectRetention` and `s3:ListBucket`. `tests/s3/minio.sh` shows a working policy; CI runs the backup and restore drill against it.
   - Uploads carry `Content-MD5`, `x-amz-checksum-sha256` and a signed payload hash, so the store rejects a corrupted upload.
2. Export the **master key** from **Platform → Backups → Disaster recovery key** and store it off the node, e.g. in a password manager or sealed envelope. Without it no backup can be decrypted. With it, every backup can.
3. Note the **signer public key** shown on the same page. Restores verify manifests against it.
4. Backups run on schedule, or with **Back up now**. Each backup contains:
   - the platform database;
   - the audit chain;
   - secrets, sealed a second time;
   - volumes;
   - optionally, rollback artifacts.

   Every part is encrypted with a fresh data key and the manifest is signed.

**Test restores regularly** on a spare machine (runbook R5). A backup that has never been restored is a hope, not a backup.

## Updates

**Platform → Updates** shows the installed version and the newest verified release on your channel.
- Updates are TUF-verified: signed, fresh metadata, no rollback attacks, and halted or revoked releases are refused.
- **Apply** (owner, re-auth):
  1. stages the release into the inactive A/B slot;
  2. takes a backup first if the release migrates the database schema;
  3. switches over and waits for the readiness gate.

  If the new release is unhealthy, the node switches back automatically. The exception is after a schema migration: the old binary might not understand the new schema, so the update reports that operator action is needed. Follow runbook R4.
- Package-manager upgrades (`apt`/`dnf`) also land in the inactive slot and never downgrade a newer release applied by the updater.

**Release engineering** (maintainers):
```sh
opendeploy-release publish --channel stable --version X ...   # sign and publish a release
opendeploy-release halt --channel stable                      # stop nodes staging the current release
opendeploy-release revoke --channel stable --version X        # refuse X everywhere (nodes flag it if installed)
```
`tuf-timestamp.yml` re-signs freshness daily. Root keys stay offline.

## Custom domains

1. Add the domain to the project.
2. Publish the shown TXT record at `_opendeploy-challenge.<host>`.
3. Point the host at the node (or the relay).
4. Choose **Verify**.

The proof is checked against the domain's authoritative servers. A detached domain leaves a tombstone, and re-attaching it requires a new proof. Stale DNS can never silently attach a domain to another project.

## Relay

See `docs/relay.md` for enrolment, credential rotation and revocation. A relay routes by SNI/Host only: it never holds your certificates and cannot read traffic.

## Diagnostics and support

**Platform → Status → Diagnostics → Download support bundle** (owner, re-auth, audited) collects:
- host capabilities and update state;
- `node.yaml`;
- service status;
- the last 300 log lines of each service.

Tokens, keys and passwords are redacted before the archive leaves hostd.

## Capacity and DDoS

The edge enforces per-host limits (`ingress.limits`): request body size, requests per second and concurrent connections. Workloads have CPU, memory and PID limits.

These protect a node from misbehaving clients and noisy neighbours. **They do not absorb volumetric attacks**: a single machine or home uplink can be saturated upstream of anything the node does. Public, high-value deployments should sit behind a relay or provider with DDoS protection (PRD SC-24).

## Security checklist for a new node

- [ ] The dashboard is on loopback, or remote admin is enabled with TLS, `allowed_cidrs` and acknowledgement.
- [ ] The owner has enrolled a security key, plus a second one or recovery codes stored safely.
- [ ] gVisor is installed (`opendeployctl doctor`) if you will run Untrusted projects or fork previews.
- [ ] Backups are configured with object lock; the master key is exported and stored off-host; a restore has been tested.
- [ ] Audit forwarding (`audit.forward`) points at a collector you trust.
- [ ] The update repository and trusted root are configured, and the channel is chosen.
