# Prompt for Claude Code on a physical test machine

Use this to run [physical-test-plan.md](physical-test-plan.md) on a real
Windows or Mac computer. It works with Claude Code in the terminal or in
the VS Code extension.

**Before you paste it**
1. Install Git and Claude Code, then clone the repository and switch to
   `main`:
   ```
   git clone https://github.com/Anreddykarthikreddy3003/OpenDeploy.git C:\src\OpenDeploy
   cd C:\src\OpenDeploy
   git checkout main
   ```
   On a Mac, clone into `~/src/OpenDeploy` instead.
2. **On Windows**, open the terminal (or VS Code) **as administrator** and
   start Claude Code in that folder. Installing the MSI and managing the
   Windows service and WSL need elevation.
3. **Keep permission prompts on** (do not use a bypass mode). You then see
   and approve every command that runs as administrator.
4. Plan on a few hours, spread over more than one sitting. Some steps need
   you:
   - approving UAC prompts;
   - scanning a TOTP code with your phone;
   - rebooting and sleeping the machine;
   - switching networks.

   If the session is interrupted, start Claude Code again and say:
   "Continue the physical test from the report in `docs/test-reports/`."

**The prompt** (copy everything inside the box):

```text
You are testing OpenDeploy on this physical computer, as its release test on real hardware. This repository is OpenDeploy: a local-first, security-hardened deployment platform (Go services, React dashboard). On Windows the node runs in a managed WSL2 distro installed by an MSI; on macOS it runs in a Virtualization.framework VM installed by a pkg. The Linux node already passes the full release gate in the cloud. What has never been tested is real Windows/macOS hardware, which is your job.

Read these first, fully: docs/physical-test-plan.md (your instructions; follow it exactly), docs/production-readiness.md, README.md, docs/install.md, CLAUDE.md. Then work through the plan in order:

1. Part A: review the documents against the code (at least 10 claims, cited to file:line). Fix wrong docs.
2. This machine: detect whether it is Windows or macOS and follow Part B or Part C. Record the machine details and check the prerequisites. Tell me exactly what to install if something is missing, and give me the commands. Install things yourself only after I approve.
3. Build everything from this checkout, following the plan (B1/B2 or C2). On Windows, also run `sudo scripts/release-gate.sh` inside the Ubuntu-24.04 builder distro and record its summary.
4. Run every test case (W-01…W-20 or M-01…M-20) in order. Record PASS / FAIL / BLOCKED / N/A with real evidence for each: the command and its output, or what I saw on screen. Never mark PASS without having observed the pass criterion. Tell me clearly whenever I must act (UAC, TOTP code, reboot, sleep, network switch, checking from another device), and wait for me.
5. For every FAIL: reproduce it, find the root cause in the code, and add a regression test that fails before the fix. Fix it, run the checks in "Fixing a failure", rebuild, reinstall, and re-run the affected cases. Never skip, disable or loosen a test, a check or a security control to get a pass. If a fix would change a security control, an API or on-disk data, or the root cause is unclear, stop and ask me first.
6. Write the report in docs/test-reports/ using the plan's template. Update the "Physical desktops" item in docs/production-readiness.md with the date, the verdict and a link to the report. Finish with an honest verdict: what is production-ready, what failed, what is still pending (signing, pen test, beta, etc.), and what you could not test and why.

Rules:
- Ask me before anything destructive or outward-facing: `uninstall --purge`, deleting data, firewall/BIOS changes, exposing a port, and git push.
- Never put secrets in files, commits or the report: bootstrap tokens, passwords, TOTP secrets, recovery codes, API tokens, master keys, user names or IP addresses. Write <redacted>.
- Keep a running log in the report file as you go, and commit it at the end of each part. If the session is interrupted, the next session continues from it.
- Git: work on `main`. Before each push, run `git pull --rebase origin main`, then `gofmt -l .` (must print nothing), `go vet ./...` and the relevant tests. Commit fixes one per commit, naming the test ID in the message. Push to `origin main` only after I say yes.

Start now with Part A, and give me a short status line after each part.
```
