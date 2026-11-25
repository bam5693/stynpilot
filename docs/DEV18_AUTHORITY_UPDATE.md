# Dev18: authority update (manual publication, one last time)

Why a manual release is unavoidable: the live Dev17 sandbox profile kills Python 3.14 on Ubuntu 26.04 with SIGSYS when it loads a
native extension (kernel audit: syscall 122 = setfsuid, five events, UIDs 992 build and 994 runner). The profile is installed code,
so no candidate commit can change it. Dev19 (version bump only) is then the first fully automated release.

## What Dev18 contains
1. Packaging without a tar child (496000c): the .deb is written in-process; byte-identical across umasks.
2. Sandbox: re-allow exactly `setfsuid` after `~@privileged @resources` (`runner.ALLOWED_EXTRA_SYSCALLS`). setfsgid, setuid,
   setresuid, setgroups and every other id/capability call stay denied.
   - Why it is safe: every unit has an empty capability bounding set, no ambient capabilities, NoNewPrivileges and
     RestrictSUIDSGID. Without CAP_SETUID, setfsuid can only select the account's own real/effective/saved uid.
   - Proven live by new required self-test checks: `ids_all_equal` (real/effective/saved/fs uid and gid identical),
     `no_capabilities` now also covers CapInh, `fs_identity_fixed` (setfsuid(0) and setfsuid(owner) leave the fs uid unchanged
     and a visible root-only 0600 file unreadable) and, on systemd, `setid_calls_denied` (setfsgid, setuid, setresuid, setgroups
     still kill with SIGSYS).
3. default_run keeps the command's real exit status when its output closes before it exits (was recorded as -9).
4. Phase S1 (GREEN, read-only): new tool `computer_system_status`: sleep/hibernate targets and masking, logind and sleep.conf
   effective settings, GNOME idle sleep; Wi-Fi autoconnect and retry policy (no secrets requested); boot-enabled units and linger;
   power supplies and Wake-on-LAN per card; reboot-required and why; firmware power-loss recovery (reported honestly as not
   readable from Linux on most PCs); StyNpilot owner-state backups with the newest one verified.

## Verification
- Suite: 780 passed, 5 skipped on Python 3.14.6 + pytest 9.0.2 and on 3.13 (test_g7 / test_compat_check excluded as before).
- After install: runner_selftest must pass every check, including the four new ones, before any job or release build runs.
- Rollback: Dev17 (installed .deb kept by the upgrader).
