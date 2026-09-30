# OpenDeploy: notes for Claude Code

OpenDeploy is a local-first, security-hardened deployment platform. The
specification is [docs/PRD.md](docs/PRD.md); what is proven, and what is
still pending, is in
[docs/production-readiness.md](docs/production-readiness.md).

## Layout
- Code:
  - `cmd/`: one binary per service (platformd, builderd, runtimed, …), plus
    `opendeployctl` (CLI) and `opendeploy-desktop` (Windows/macOS host
    supervisor).
  - `internal/`: the services' code; `internal/desktop` is the WSL2 and
    Virtualization.framework host.
  - `web/`: the React dashboard (`npm ci && npm run build`).
- Packaging:
  - `packaging/linux`: deb/rpm payload, `install.sh`, systemd units.
  - `packaging/windows/opendeploy.wxs`: the MSI (WiX 5).
  - `packaging/macos`: the pkg.
  - `guest/`: builds the WSL2 and VM guest images from the node deb (Linux
    and Docker only).
- `tests/`: integration, e2e (build tag `e2e`), adversarial (`adversarial`),
  package (`pkginstall`), soak (`soak`), and `tests/s3/minio.sh`.
- `scripts/release-gate.sh`: every release check, runnable on a Linux host
  (`sudo scripts/release-gate.sh`).
- `docs/physical-test-plan.md`: the test on a real Windows or Mac machine.

## Rules
- Never skip, disable or loosen a test or a security control to get a
  pass. `OPENDEPLOY_REQUIRE_CAPS=1` turns capability skips into failures
  (`internal/testcap`).
- Every bug fix comes with a regression test that fails on the old code.
- Before committing, both must be clean:
  - `gofmt -l .` prints nothing;
  - `go vet ./...` (and `go vet -tags <tag> ./tests/...` for the tagged
    suites).

  Then run the tests for what changed. `go test ./...` runs on Linux; on
  Windows, run `go test ./internal/desktop/... ./cmd/...`.
- Shell scripts, units and guest files must keep LF line endings
  (`.gitattributes`).
- Never commit secrets: tokens, passwords, TOTP secrets, keys or recovery
  codes.
