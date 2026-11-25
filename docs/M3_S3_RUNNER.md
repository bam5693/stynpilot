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

## dev14: root cause of the live `limit_io` failure (found by dev13's diagnostics on the Ryzen)

Live dev13 self-test: 17 of 18 checks passed; only `limit_io` failed, with expected `259:0:wbps=67108864` and actual `259:0:wbps=64000000`. systemd reads the `64M` suffix of
`IOWriteBandwidthMax` as decimal (64,000,000), while StyNpilot compared against 64 MiB. The real limit was slightly MORE restrictive than expected, so this was a unit mismatch, not a weakness.

- One exact byte value, `runner.IO_WRITE_BPS = 64 * 1024 * 1024`, is written to the unit as a plain number (no suffix), checked by the self-test, and used by the disk-reserve calculation.
- Regression tests: the unit has no suffix; the self-test and reserve use the same constant; the decimal value is rejected by the comparison.
- Diagnostic filter: a `/` is allowed only between a digit and a digit or `-` (soft/hard limits such as `536870912/536870912` or `-1/-1`); paths and words with a slash are still dropped.
- Nothing else changed: no confinement, permission, gate or rollback change.

## dev13: ChatGPT's review of dev12 (dae11c0): diagnostics must reach the assistants

dev12 was never installed; dev13 replaces it. Reporting only: no limit, gate rule or confinement changed.

- *Oversight fixed:* `Executor._safe_selftest` rebuilt the self-test answer from a fixed list of fields and dropped `diagnostics`, so neither `runner_status` nor `runner_selftest`
  showed expected/actual values. It now passes them through `clean_diagnostics` (known check names only, short safe tokens, at most 24), which also re-validates whatever the state file holds.
- *Unverified under systemd:* a limit that could not be seen is now listed in `unverified` in every mode. Under systemd (strict) it ALSO stays in `failed`, so the gate stays closed.
- *Test of the whole path:* `tests/test_selftest_diagnostics_path.py` drives the real probe-line judge, the real `Executor` and the real MCP tools and checks the complete tool response
  (diagnostics present, hostile or oversized entries removed, gate closed). It fails if the executor change is reverted.

## dev12: diagnostics for the live `limits` failure (dev11 live test: 13 of 14 checks passed)

dev11 on the Ryzen passed every confinement check except `limits`, which was one compound check (pids, memory, file-size, /tmp size, write rate). A failure there could not say
WHICH limit, nor whether it was real enforcement or a visibility problem. dev12 changes ONLY the self-test reporting; the gate stays closed on any failure and no confinement changed.

- `limits` is split into `limit_pids`, `limit_memory`, `limit_fsize`, `limit_tmp`, `limit_io`; each is its own PASS/FAIL and all are required on a backend that enforces limits.
- The verdict now carries `diagnostics`: the expected and actual value of each limit (numbers and short tokens only, filtered; nothing from the filesystem is echoed) plus the probe's cgroup path.
- The old duplicate `["limits","limits"]` in `failed` is gone (names are listed once).
- If the cgroup files cannot be read at all the result is SKIP (visibility), which still fails the gate under systemd: it is reported as `unverified`, distinct from FAIL (enforcement mismatch).

## dev11: fix from ChatGPT's independent review of dev10 (3c6080f)

One blocker, nothing added. dev10 was never installed: dev11 replaces it as the dev7 upgrade target.

- *Blocker:* when the owner-helper call timed out, the cleanup (`systemctl kill`) had its own timeout, and its `TimeoutExpired` could escape the helper, kill the
  disk-watchdog thread and leave the job running. Now the cleanup's failure or timeout is swallowed (the unit still ends at `RuntimeMaxSec`), the helper only ever raises
  `HelperError`, and the watchdog treats ANY exception as "cannot tell, stop the job". Stopping the job is itself exception-proof: backend failure still ends with SIGKILL of the
  job's process group. Regression tests: cleanup times out / fails; helper raises the raw error AND the backend cancel raises, job still ends `disk_limit` in bounded time.
- *Reserve:* `JobRunner.worst_overshoot()` = two writers x (64 MB/s x (poll 1 s + measure 4 s + slack 1 s + cleanup 2 s + kill 3 s + stop 5 s)) + 20% of the 2 GiB memory limit
  of dirty (buffered) pages each = about 2.8 GiB. The kill line is now 4 GiB free (was 2) and a job needs 6 GiB free to start (was 4); the production runner refuses to start
  with a smaller kill line. Tested.
- *For the first live test:* use only a NEW disposable workspace with no credentials or important files.

**Tracked before broader use:** (1) a pre-existing file moved into a workspace during a run keeps its permission bits (out-of-band movement); (2) no per-workspace byte
quota (per-job growth cap of 4 GiB is the bound); (3) systemd unit properties are proven only by the live self-test.

Non-root tests: 591 passed + 88 skipped (679 total); as root the 41 baseline failures are unchanged and 22 new real-isolation tests pass.

## dev10: fixes from ChatGPT's independent review of dev9 (54caf0b)

Same architecture and capabilities; nothing new added. dev9 and dev8 were never installed: dev10 replaces them as the dev7 upgrade target.

**Findings and fixes**
1. *Disk watchdog.* Every helper call now has a hard deadline (`RuntimeMaxSec` plus a subprocess timeout, then `systemctl kill`); the watchdog's
   measurement uses a 4 s bound and fails closed (job cancelled) on any error. Cancel is bounded too. Inodes are watched (start refused below 5% free,
   killed below 2% or after 15% consumed), per-job growth is capped at 4 GiB, and writes are throttled with `IOWriteBandwidthMax` on the real block
   device (fail closed if it cannot be resolved). `LimitFSIZE=512M`, `/tmp` 256M, `/run` 8M. There is no per-workspace byte quota; the per-job growth budget is the aggregate bound.
2. *Credentials.* Runtime boundary instead of name filtering: new files in a workspace get no sandbox entry by default (default ACL gives other = none), the
   job runs with only its own account, and the owner helper grants access per job start. Scans fail closed: anything unreadable, over 64 levels deep or over 50,000 entries refuses the job
   (`scan_incomplete`, `workspace_too_deep`), never a silent skip. Protected names are masked and never descended into.
3. *Enrollment.* `Executor._runner_do` has no `lexists`/`mkdir`/`chown`; the owner helper creates and verifies the folder (0700). Tested with the home hidden from root.
4. *Concurrency.* Two accounts (`stynpilot-run`, `stynpilot-run-2`); each live job gets its own. The live self-test runs a decoy job in another workspace and proves the
   probe cannot read its files, see its processes, or reach it. A third job is refused (`too_many_jobs_running`).
5. *Permission repair.* Runs as the job's own account (`acl_repair`), only on entries the owner owns, skips protected names, links and hard-linked files, and leaves files carrying
   unrelated named ACL entries exactly as they are (the sweep reads ACLs first and fails closed if it cannot).

**Honest limits**
- A world-readable file moved into a workspace during a run keeps its permission bits. No AI tool does this.
- There is no filename-independent kernel boundary against the owner's own out-of-band actions.
- Inode creation rate is bounded by the watchdog and thresholds, not prevented.
- Systemd unit properties can only be proven by the live self-test on the Ryzen.

**Test count 634 -> 591.** dev8: 587 passed + 47 skipped = 634 total. dev9: 591 passed + 66 skipped = 657 total. dev10: 591 passed + 85 skipped = 676 total (non-root).
The earlier figures compared a total with a passed count. The new tests are root-only isolation tests and show as skips without root; as root they all run (19 new, all pass).

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
