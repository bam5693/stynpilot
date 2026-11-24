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
