# Incident runbooks

These are short, ordered procedures. **Run them against a test node before you need them.**

The ST-12 drill (R1) is automated in `tests/integration/stack_test.go` ("ST-12 incident drill"):
- credential revocation,
- KEK rotation,
- secrets still readable afterwards.

The restore half is covered by `tests/integration/backup_test.go` (ST-11).

**Conventions**

| Term | Meaning |
|---|---|
| "Dashboard" | `http://127.0.0.1:8080` through your SSH tunnel. |
| "The node" | The Linux host, or the guest on Windows/macOS. |
| Sensitive actions | Ask you to re-authenticate. Keep your security key at hand. |

---

## R1: Suspected compromise of the node or control plane (ST-12)

**Goal:** preserve evidence, cut the attacker off, rotate everything the node could have exposed, and rebuild onto a clean machine.

### 1. Preserve evidence first
- The off-host audit copy (`audit.forward`) is your source of truth. Export the collector's copy for the incident window before anything else.
- Dashboard → Platform → Status → **Audit chain** must read *intact*. If it reads *BROKEN*, note the event number: everything after it is untrustworthy.
- Download a **support bundle** (Platform → Status → Diagnostics) and store it with the incident record.

### 2. Cut off access
- Platform → Status → Incident response → **Revoke all sessions and tokens**. This signs out everyone except you and invalidates every API token.
- Check Platform → Users for accounts or role changes you don't recognise.

### 3. Isolate the node if the host itself is suspect
- Take it off the network, keeping the disk for forensics.
- Relay mode: on the relay server, run `relay-server revoke --instance <id>`.
- Do **not** reuse the host.

### 4. Rotate credentials

| Credential | Action |
|---|---|
| Secrets KEK | Incident response → **Rotate secrets key**. It re-wraps every secret; the old key is destroyed. |
| Application secrets | Rotate at their source (database passwords, API keys) and update them in OpenDeploy. A KEK rotation protects stored ciphertext, not values a compromised process may already have read. |
| GitHub App | In GitHub → Settings → Developer settings → your App: generate a new private key and revoke the old one; set a new webhook secret. Update `github.private_key_file` and `github.webhook_secret_file`, then restart. |
| Relay credentials | Re-enrol with `relay-server enroll`; credentials are short-lived, so the old ones expire anyway. |
| Backup storage | New access keys. The old credentials must not have had delete rights; confirm objects are still under object lock. |
| Update keys (maintainers only) | If TUF online keys were exposed, rotate them with a root-signed metadata update (`tools/opendeploy-release`) and halt the channel meanwhile. |

### 5. Rebuild
Install OpenDeploy on a **clean** machine (`docs/install.md`), then restore the newest backup taken **before** the compromise window (R5). After the restore:
- redo steps 2 and 4 on the new node;
- re-verify custom domains;
- confirm the audit chain is intact.

### 6. Record
Write up the timeline from the off-host audit log. Confirm that the new node's audit forwarding works.

---

## R2: Degraded read-only mode

The dashboard shows "Degraded read-only mode". platformd found a violated invariant or a failed integrity check and stopped accepting changes. Running apps keep serving.

1. Read the reason on Platform → Status, and `journalctl -u opendeploy-platformd`.
2. Disk full or I/O errors: fix the host, then run `systemctl restart opendeploy-platformd`. The integrity check reruns at start.
3. Corruption: platformd keeps checksummed snapshots under `/var/lib/opendeploy/platformd/snapshots`. Stop the platform, move the damaged `platform.db*` aside, and restore the newest snapshot, or the newest backup (R5):
   ```sh
   systemctl stop opendeploy-platformd
   ```
4. After the restart, the reconciler converges routes and workloads to the desired state. Deployments stuck mid-promotion are resolved from the promotion journal.

---

## R3: A user lost their second factor

| Who | What to do |
|---|---|
| Another user | The owner opens Platform → Users → **Reset MFA** for that user. The user enrols again at next login. |
| The owner | Sign in with a **recovery code** (saved at enrolment) or a second security key. Without either, recovery requires restoring the node from backup, so keep recovery codes safe and enrol two keys. |

---

## R4: An update failed

| Case | What happens / what to do |
|---|---|
| Rolled back automatically | Platform → Updates shows `rolled_back`: the new release failed its readiness gate and the previous slot is active again. Nothing else to do; report the version. |
| "Operator action needed" | The failed release had migrated the database schema, so automatic rollback is unsafe. A backup was taken **before** the migration. Restore it onto this node (R5 with `--force`) while services are stopped; the previous release is still in the other slot. |
| Halted or revoked | Nodes refuse to stage that release; no action is needed. |

---

## R5: Restore from backup (also the regular restore drill)

1. Install OpenDeploy on the target machine **without starting it**:
   ```sh
   install.sh --no-start
   ```
   Or stop it:
   ```sh
   systemctl stop opendeploy.target
   ```
2. Put the backup target settings in `/etc/opendeploy/node.yaml`: the same `backup:` block, and `signer_public_key` from the old node.
3. List backups, then restore:
   ```sh
   sudo opendeployctl restore --list
   sudo opendeployctl restore --id <id|latest> --master-key /path/to/master.key --signer <base64 key>
   ```
   Use `--from DIR` for a local copy; `--force` overwrites existing state.
4. Start the node:
   ```sh
   systemctl start opendeploy.target
   ```
   Workloads start from the restored artifacts. No rebuild or GitHub access is needed.
5. Re-point DNS or the relay at the new node, then verify custom domains.

A restore refuses manifests not signed by the pinned key, and fails on any tampered or truncated chunk.

---

## R6: A secret leaked (build log, repository, screenshot)

1. Rotate the value at its source.
2. Update it in OpenDeploy: Project → Environment variables. Mark it sensitive.
3. Redeploy the affected environments.
4. If it leaked in a build log: the build reported a leak warning (values seen in output are masked), and the log is kept for audit. Check who could read it (project viewers and above).

---

## R7: A relay credential was stolen

On the relay server:
```sh
relay-server revoke --instance <id>
relay-server enroll --tenant <tenant> --instance <id>
```
Hand the new enrol token to the node (`ingress.relay.enroll_token_file`) and restart `opendeploy-relay-agent`.

A stolen credential can only register this instance's own routes, and only for domains the node has verified. The relay never sees plaintext.
