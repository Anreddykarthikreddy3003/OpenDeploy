# Installing OpenDeploy

OpenDeploy always runs its data plane on Linux:
- On a **Linux server** it runs natively.
- On **Windows** and **macOS** it runs the same Linux node inside a managed guest: a WSL2 distribution or a Virtualization.framework VM. The installer sets this up; you never manage the guest directly.

After any install, open the dashboard and create the owner account with the one-time **bootstrap token** (see each platform below for where to find it). The owner must enrol a second factor, either a security key or TOTP, before using the API.

## Linux (Debian/Ubuntu, Fedora/RHEL)

**Requirements**
- systemd and cgroup v2.
- nftables, uidmap (`newuidmap`), containerd, curl.
- For builds: [Caddy](https://caddyserver.com/docs/install) 2.8 or newer, [BuildKit](https://github.com/moby/buildkit/releases) (`buildkitd`, `buildctl`, `buildkit-runc`) and [RootlessKit](https://github.com/rootless-containers/rootlesskit/releases), installed into `/usr/bin`.
- Optional but recommended: [gVisor](https://gvisor.dev/docs/user_guide/install/) (`runsc` and `containerd-shim-runsc-v1`). Untrusted projects and fork previews are refused (fail closed) until it is installed.

**Install**
```sh
sudo apt install ./opendeploy_<version>_linux-amd64.deb       # or: sudo dnf install ./opendeploy_<version>_linux-amd64.rpm
```

The package runs `/usr/lib/opendeploy/release/packaging/linux/install.sh`, which:
- creates one system user per service and the state directories;
- installs the release into A/B slots under `/opt/opendeploy`;
- writes `/etc/opendeploy/node.yaml` on first install;
- installs the hardened systemd units and starts `opendeploy.target`.

To install from a release tarball instead:
```sh
tar -xzf opendeploy_<version>_linux-amd64.tar.gz -C /tmp/od
sudo /tmp/od/packaging/linux/install.sh --domain apps.example.com --email you@example.com
```

**Installer options**

| Option | Meaning |
|---|---|
| `--domain D` | Base domain for generated app URLs (wildcard DNS `*.D` → this host). |
| `--email E` | ACME account email. |
| `--mode lan\|direct\|relay` | Ingress mode (see `docs/configuration.md`). |
| `--ca-bundle F` | Trust a corporate TLS-inspection CA everywhere, including build steps. |
| `--no-start` | Install without starting services. |
| `--force` | Stage the release even if the same version is installed. |

**First login**
```sh
ssh -L 8080:127.0.0.1:8080 your-server           # the dashboard listens on loopback only
sudo opendeployctl admin bootstrap-token        # on the server
```
Open http://127.0.0.1:8080 and create the owner account with the token. The token is deleted as soon as the owner exists.

**Check the host**
```sh
opendeployctl doctor
systemctl status 'opendeploy-*'
```

**Upgrade:** use `apt`/`dnf` upgrade, or apply updates from Platform → Updates (TUF-verified, A/B with automatic rollback). A package upgrade never downgrades a newer release that the updater already applied.

**Remove**
```sh
sudo apt remove opendeploy
```
This stops the services. Node data in `/var/lib/opendeploy` and `/etc/opendeploy` is kept. Delete it by hand after taking a backup if you want it gone.

## Windows 10/11

**Requirements**
- 64-bit Windows 10 22H2 or Windows 11 with WSL 2. If WSL isn't installed, run this as administrator and reboot:
  ```
  wsl --install --no-distribution
  ```
- Virtualization enabled in firmware.

**Install:** run `OpenDeploy-<version>-x64.msi` as an administrator. The installer:
- copies `opendeploy-desktop.exe` and `opendeployctl.exe` to `C:\Program Files\OpenDeploy\bin` (added to the system PATH), and the OpenDeploy WSL image to `C:\Program Files\OpenDeploy\guest`;
- creates the local service account `opendeploy-svc`: a standard user (not an administrator), hidden from the sign-in screen, with a random password that is never stored. It can only run as a service: it has the "log on as a service" right and is denied interactive, Remote Desktop, network and batch logon;
- registers and starts the **OpenDeploy** Windows service (automatic, delayed start). It starts at boot without anyone logging in.

**Data folder:** the node's data (its WSL disk, status and logs) goes in `C:\ProgramData\OpenDeploy` unless you choose another folder at the first install, from an administrator prompt:
```
msiexec /i OpenDeploy-<version>-x64.msi DATADIR=A:\OpenDeploy
```
- The folder must be a full path on a local NTFS (or ReFS) drive, and new or empty. A drive root (`A:\`), a network path, and the Windows, Program Files and user profile folders are refused. The installer marks the folder with a `.opendeploy-data` file.
- You choose it once. Upgrades, repairs, `status` and `uninstall` use the folder the service was installed with; you don't pass it again. The folder is also recorded in the registry (`HKLM\SOFTWARE\OpenDeploy`, value `DataDir`), so a reinstall after an uninstall that kept the data finds it.
- The data can't be moved. Installing with a different `DATADIR`, or `opendeploy-desktop install --data <other folder>`, is refused. To move a node, delete it with `opendeploy-desktop uninstall --purge` (this deletes all of its data) and install again.
- The program files go to `C:\Program Files\OpenDeploy`. Add `INSTALLFOLDER=D:\Apps\OpenDeploy` to put them elsewhere.

**First start** imports the WSL distribution into the `wsl` folder inside the data folder and boots the node, which takes a few minutes. Follow it from an elevated prompt:
```
opendeploy-desktop status
```
The first line is the data folder, for example `Data folder: A:\OpenDeploy`. Once it reports `running`, the command prints the bootstrap token. Then open http://127.0.0.1:8080. Apps are served at `http://<project>.localhost`.

**Isolation:** the distribution has Windows interop, drive automounts and PATH sharing disabled, so workloads cannot reach Windows through WSL. Node data lives in the distribution's virtual disk in the data folder, which only SYSTEM, Administrators and the service account can access.

**Uninstall:** use Apps & features. This removes the service and keeps the node data; installing again picks it up. To delete everything, first run this as administrator:
```
opendeploy-desktop uninstall --purge
```
It deletes the service account (and its logon rights) and the data folder the node was installed with. It deletes the folder only if it holds the `.opendeploy-data` marker (or is the default `C:\ProgramData\OpenDeploy`); otherwise it stops and changes nothing.

## macOS 13+ (Apple silicon and Intel)

**Install:** open `OpenDeploy-<version>.pkg`. It installs to `/Library/OpenDeploy` and registers a launchd daemon that boots the OpenDeploy Linux VM at startup. The VM uses Apple's Virtualization.framework with NAT networking.

The dashboard (127.0.0.1:8080) and the app edge (ports 80 and 443 on loopback) reach the VM over virtio-vsock; the VM listens on no host network port.

**First start** creates the VM disk (sparse, 64 GiB by default) in `/Library/Application Support/OpenDeploy`:
```sh
sudo opendeploy-desktop status        # prints the bootstrap token once the node is running
```

**Resources:** reinstall the service with different values:
```sh
sudo opendeploy-desktop install --cpus 6 --memory 8192
```
`--disk` applies only to a new VM disk.

**Uninstall**
```sh
sudo /Library/OpenDeploy/uninstall.sh            # keeps the VM disk
sudo /Library/OpenDeploy/uninstall.sh --purge    # deletes the VM and all node data
```

## Next steps
- Connect GitHub under Platform → GitHub (create the App from the manifest).
  On Windows and macOS, and on any node whose `api.public_url` GitHub cannot reach (loopback, a private or `.local` address), the App is created without a webhook. Private repositories still import and build, but pushes do not deploy automatically: deploy from the dashboard or with `opendeployctl deploy <project>`. For push-to-deploy, expose the node through a relay (`docs/relay.md`) and use its public URL.
- Import a repository, or deploy a local directory:
  ```sh
  opendeployctl upload myapp ./
  ```
- Configure backups (`docs/operations.md#backups`) and export the backup master key.
