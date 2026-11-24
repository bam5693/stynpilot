# S3: sandboxed command runner (design + status)

Goal: the AIs can build, test and inspect projects on the Ryzen without the owner copying commands, while the
GREEN / YELLOW / BLACK policy holds. Free-form commands never run as the owner or root.

## Tiers
- T2 recipe (GREEN): a named command family with validated arguments, inside an enrolled workspace (`runner.RECIPES`).
- T3 one-off command (YELLOW): the exact argv is shown and approved on the phone; same sandbox.
- T4 root: only named installer actions; an arbitrary root command is BLACK.
- Enrolling a workspace is YELLOW (once per folder).

## S3a (this commit): policy core, no process is started
`src/stynpilot/runner.py`: workspace rules (canonical path, inside home, not hidden, no links, no credential-named
folders, owner-owned, not world-writable), recipes with per-argument validation (no shell, no expansion, absolute
binaries, fixed environment, path arguments must stay inside the workspace after symlink resolution), and the
`systemd-run` argv for the locked-down transient unit (user `stynpilot-run`, ProtectSystem=strict, ProtectHome=tmpfs +
bind of the one workspace, private tmp/devices/network, no capabilities, syscall filter, resource limits, installer and
state paths inaccessible). Tests: `tests/test_runner_core.py` (hostile folders, hostile arguments, fuzz, unit smuggling).

## Open points that only the real machine can settle (S3b self-test job)
1. Unit properties behave as documented under the Ryzen's systemd (ProtectHome=tmpfs + BindPaths, InaccessiblePaths).
2. Output route: `--pipe --wait` from the root installer vs. a root-owned output file (ProtectSystem=strict).
3. The run user must WRITE files the OWNER owns. Plan: an ACL granted at enrolment (`setfacl -R -m u:stynpilot-run:rwX`
   plus default ACLs for run user AND owner so new files stay editable by the owner); removed when the workspace is
   un-enrolled. Needs the `acl` tools and ACL support on the file system; the self-test checks both. Running the sandbox as
   the owner's uid instead was rejected: it could signal the owner's own processes and reach the owner's runtime dir.
4. Crash/restart recovery of running jobs (installer restarts during a job).

## Next steps
S3b root-door job kinds (create runner user, enroll workspace, run, status, cancel, selftest) with approval and a job
table; S3c MCP tools (workspace request, file edits inside workspaces, job run/status/output/cancel); S3d one-off command.

## dev9: fixes from ChatGPT's independent review of dev8 (a020d9f)

Same architecture, same capabilities; nothing new added. dev8 was never installed: dev9 replaces it as the dev7 upgrade target.

**Blocker 1, home-folder safety.** `ProtectHome=yes` is back on the installer: root never looks into the home. A helper
(`projects_helper.py`) runs AS THE OWNER (transient unit: read-only system, writes only to the projects folder, no capabilities, no
network) and does every path operation: folders are opened with `O_NOFOLLOW` from the previous descriptor, files are re-verified on the
descriptor (regular, one link, same device and inode) and ACLs are set on `/proc/self/fd/N`, never on a name. A link swapped in
mid-walk is skipped. A symlinked projects folder or home is refused, not canonicalised. Enrol, unenrol and job start share one lock;
unenrol removes the row first, then the access.

**Blocker 2, credentials.** Credential-named files and folders (and `.stynpilot-trash`) are found at EVERY job start and hidden with
`InaccessiblePaths=-<path>`, whatever their mode (0600/0644/0666) and whether they existed at enrolment. A protected name that cannot be
expressed safely stops the job (fail closed). The self-test plants world-readable canaries and requires the probe to be refused.

**Blocker 3, disk.** `LimitFSIZE=512M` per file, a 256 MiB memory-backed `/tmp`, an 8 MiB `/run`, a start refusal below 4 GiB free, and a
root-side watchdog (every 2 s, owner-side measurement; cannot measure means stop) that kills a job under 2 GiB free (state `disk_limit`).

**Should-fix.** Host UNIX sockets: `/run` is a private tmpfs and the probe tries to connect to every host socket it can find.
`InaccessiblePaths` entries carry `-`. After each job the run user re-opens the ACL mask (`m::rwx`) so the owner keeps access to its
0600 files. The self-test now REQUIRES the cgroup limits, `RLIMIT_FSIZE` and the `/tmp` size to be seen when the backend is systemd.
Setup schedules one owner-service restart when it creates the projects folder (dev7's upgrade worker cannot create it first).

**Honest limits.** Not exercisable without systemd: the unit properties (proven only by the live self-test on the Ryzen). The disk
bound is: per-file cap + tmpfs caps + a 2 s watchdog with a 2 GiB margin; a writer faster than ~1 GB/s on a nearly full disk could still
race it, and there is no per-workspace byte quota. `IOWriteBandwidthMax` is not set (needs the block device).

## dev8: the combined S3 release (S3b-2 + live self-test + S3c)

What an assistant can do after the owner's two phone approvals (setup once; authorize a project):
request setup and workspace authorization; verify the live sandbox (`runner_status`, `runner_selftest`); create, read, edit, move and
trash files in `~/StyNpilot-Projects/<name>`; run fixed recipes; watch, page the output of, and cancel jobs.

**Approvals (YELLOW, phone):** `runner` request kind with actions `setup`, `enroll`, `unenroll`. Same one-time proof as installs and
upgrades. `setup` creates the `stynpilot-run` account, the `~/StyNpilot-Projects` folder (owner-owned, 0700) and runs the self-test.
**GREEN, no approval:** status, self-test, run/jobs/output/cancel (installer socket, owner uid only), file tools (owner service).

**Gate:** `run` is refused (`sandbox_self_test_required`) until the live self-test passed for this exact StyNpilot version. An upgrade
closes the gate; `runner_selftest` (GREEN) reopens it. The probe runs inside the real sandbox and checks: identity (not root/owner, no
groups), no capabilities and NoNewPrivs, hidden paths unreadable, owner home invisible, network isolated (a listener on the host
loopback is unreachable, so is 1.1.1.1), writes outside the workspace refused, workspace writable, and the OWNER can edit files the
sandbox account creates. Limits (pids/memory in the cgroup) are checked when the kernel shows them, otherwise reported `unverified`.

**Deliberate decisions to review**
1. Workspaces are only direct children of `~/StyNpilot-Projects`. This keeps the owner unit's write access to one named folder
   (`ReadWritePaths=-%h/StyNpilot-Projects`) instead of the whole home.
2. `ProtectHome=yes` was removed from the installer unit (it must see/ACL files in the home). Code restricts every use to the folder above.
3. git recipes pass `-c safe.directory=<authorized folder>`: found by a real test (git refuses owner-owned repos run by another account).
4. Free-form commands never run. Recipes only. No network in jobs. No root.

**Known limits (tracked)**
- A tool that creates a file with mode 0600 inside the sandbox leaves an ACL mask that can lock the owner out of that file. Not repaired yet.
- Workspace size is not capped beyond per-write 1 MiB / enrol 50,000 entries.
- Selftest `limits` may show `unverified` on kernels that hide the cgroup files.
- If the projects folder is first created by `setup` (fresh install, not an upgrade) the owner service sees it writable only after its next
  restart; `runner_status.file_editing_ready` says so.
- The systemd unit properties themselves cannot be exercised in the build sandbox (no systemd); the self-test is how they are proven on the Ryzen.
