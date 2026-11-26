# StyNpilot development handoff (Claude -> Codex, and back)

Written 2026-11-25 by Claude (lead developer) because Claude's usage was near its limit. Read this file first; it is
self-contained. The canonical plan is the GitLab master plan (see "Where things live"); this file is the working snapshot.

## Roles and rules (unchanged, owner-approved)
- Claude = lead developer when available. Codex = authorized to continue development when Claude is out of usage.
  ChatGPT = independent reviewer, project coordinator, release manager and the owner's command center.
- Neither AI approves its own work for live deployment. Every release: independent ChatGPT review -> owner phone approval.
- GREEN automatic within authorized scope; YELLOW needs the owner's own passkey/Auth0 approval; BLACK never.
- No paid CI, no new subscriptions, $0 extra spending without asking the owner. No Codex usage for development unless Claude is
  out of usage (this handoff).
- One developer per branch at a time. Before starting, `git fetch` and check nobody else pushed to the branch; work on your own
  branch (e.g. `codex/<topic>`) and say so to ChatGPT. Never force-push someone else's branch.

## Vacation safety restrictions (owner is out of state, no physical access to the Ryzen or the Pi)
Allowed: development and source review, local testing, independently reviewed AND owner-approved releases, repository
reconciliation (read-only first), software research and setup planning, disposable recovery/rollback testing.
DEFER until the owner is home: destructive live restore tests, authentication/OAuth changes, Tailscale or any network
configuration change, boot configuration changes, anything that could lose remote access. Exercise restore code only against
disposable environments, never live security-critical state. Do not weaken any security restriction.

## Where things live
- Code: GitHub `bam5693/stynpilot` (public). Branches: `claude/dev20-first-automated`, `claude/dev21-tar-free`,
  `claude/dev22-backups` (= installed baseline), `claude/dev23-stage1-retention` (current work).
- Master plan (canonical, private, newest entries at the top of its log) and the Ideas Vault (`MASTER_IDEAS.md`, never recreate
  it) live in the owner's PRIVATE GitLab knowledge branch. Machine identifiers, key fingerprints, repository/project IDs and other
  private operational details are kept there, not in this public file. Ask ChatGPT or the owner for access if you do not have it.
- Docs per release: `docs/DEV16_RELEASE_AUTHORITY.md` ... `docs/DEV22_BACKUPS.md`, `docs/DEV23_STAGE1_RETENTION_AND_VERIFICATION.md`.

## Installed / stable
- Live on the Ryzen: Dev22, package 0.1.0~dev22, source `ca24e68a3eab3078d30e892b3139c88cdc3d57bd`. Stable baseline and
  rollback target. Older rollbacks kept: Dev21 (f55cda4), Dev20 (471fc77), Dev19, Dev18, Dev17.
- Dev22 live verification: 846 passed / 0 failed / 95 skipped; 21/21 confinement checks; runner gate open; owner vault and root
  vault complete+verified, drills passed.
- PRESERVE: Codex's two encrypted precautionary Dev21 archives (20,592,730 bytes total) and their separate recovery credentials;
  never include them in any retention/cleanup. All existing backups and Pi backups.

## Current work: Dev23 stage 1 (retention settings + periodic re-verification)
- Branch `claude/dev23-stage1-retention`. First reviewed commit `9cc6a50` (version 0.1.0.dev23). ChatGPT review: architecture,
  payload validation, single-use approval, write gate and daily verification PASSED. The findings below are FIXED in commit
  `d2366356` and the second review's findings in the following commit (see the branch head and the private plan for exact
  hashes and test numbers): a MISSING settings file after any approval (durable `policy.log` evidence) holds pruning, and owner-
  side pruning happens only under an installer-held lease, with the lease's policy (no retention change can be applied while the
  lease is held).
  **Exact next action:** ChatGPT focused review of the branch head -> if PASS, automated release as 0.1.0~dev23 -> live checks
  -> start Dev23 stage 2 (secure key rotation) on a NEW branch from the released commit, package version 0.1.0.dev24.
- Findings (now fixed):
  1. BLOCKER: a damaged/unreadable/invalid approved settings file must NOT fall back to 7+4 for pruning: prune nothing, keep
     backing up and verifying, report `retention_settings_untrusted`. Owner side: no pruning unless the installer's current
     policy was confirmed in this run. No pruning when the newest complete verified backup's check is stale (> 1 day).
  2. SHOULD-FIX: monthly full re-check must use a durable timestamp independent of the oldest retained backup (it could never
     come due under normal retention); test >60 days of daily backups.
  3. Release versions: do not reuse a published version for later Dev23 stages. Proposal (awaiting ChatGPT): the PACKAGE version
     simply increments per release (stage 1 = 0.1.0.dev23, stage 2 = 0.1.0.dev24, ...) while milestone names (Dev23 stage N,
     Dev24 off-machine, Dev25 repositories) stay as labels. dev numbers must keep increasing or the upgrader refuses the release.

## Milestone -> package version (approved: the package number increments per release; milestone names stay labels)
| Milestone | Package version |
|---|---|
| Dev20 first automated release | 0.1.0~dev20 |
| Dev21 tar-free packages | 0.1.0~dev21 |
| Dev22 encrypted backups (installed baseline) | 0.1.0~dev22 |
| Dev23 stage 1 retention + verification | 0.1.0~dev23 |
| Dev23 stage 2 key rotation | 0.1.0~dev24 (next free number) |
| Dev23 stage 3 root restore / stage 4 owner restore | next free numbers in order |
| Dev24 off-machine, Dev25 repositories | next free numbers when released |
Never reuse a published version; the upgrader refuses anything not newer than what is installed.

## Tests (how to run, latest results)
- Normal: `PYTHONPATH=src python3 -m pytest -q -p no:cacheprovider tests --ignore=tests/test_g7.py --ignore=tests/test_compat_check.py`
  (those two have root-environment-only failures in Claude's sandbox). At 9cc6a50: 857 passed, 5 skipped.
- Release-sandbox emulation (root on a throwaway machine): `tools/diagnostics/emulate_release_test_phase.sh -q tests` with
  `FAKETAR=1`; needs `seccomp_wrap.py`, `loopback_up.py` (copy to /tmp and /var), `faketar.py` at /var/faketar, python3-seccomp,
  a uid-992 account. At 9cc6a50: 855 passed, 95 skipped, 0 failed. Live Ryzen numbers have matched the emulation since Dev21.
- The 95 sandbox skips are inherent (87 need real root, 3 need root + real dev3/dev4 packages, 2 TCP-client subjects, 2 real apt,
  1 dev7 package). Keep them tracked.

## Release procedure (automated authority, since Dev20)
1. Push the exact commit; ChatGPT reviews it independently.
2. ChatGPT: `commander_prepare_stynpilot_release(device_id, commit=<40 hex>, version="0.1.0~devNN")` -> poll
   `stynpilot_release_status` (two reproducible builds + full test suite in the sandbox) -> `commander_request_stynpilot_release`.
3. Owner approves ONCE on his phone (passkey). The Ryzen signs with its own release key, publishes the GitHub release, installs,
   health-checks and rolls back automatically on failure. Interrupted after approval -> `commander_resume_stynpilot_release`.
4. After install, ChatGPT checks: both services, runner_selftest 21/21 + gate open, backup_status, system status, rollback ready.
- Manual release path (only if an authority change cannot ship otherwise; needs explicit owner OK): build with
  `tools/build_deb.py` twice (umask 022 and 077 must be identical), sign with the existing trusted key (`tools/sign_release.py`),
  stage branch `release-staging-<tag>`, ChatGPT Work publishes. Neither AI ever touches the Ryzen's signing key or GitHub token.
- Rollback: the upgrader keeps the previous package; failed health -> automatic rollback; otherwise an owner-approved
  `commander_request_stynpilot_upgrade` to the earlier signed release.

## Approved Dev23 architecture (stages in order, each reviewed separately)
1. Retention settings (YELLOW, daily 1-30 / weekly 0-12) + periodic verification (daily newest complete, monthly all) - in progress.
2. Secure key rotation: identified key generations and nonce logs; durable resumable rotation progress; every re-encrypted backup
   verified before replacing the original; never destroy a key any retained backup needs; missing key keeps unreadable archives
   (moved aside, never auto-deleted); Dev24 export-compatible. Lost nonce log -> owner-approved new key (no re-encryption).
3. Root restore, 4. Owner restore - one side at a time; YELLOW approval bound to backup SHA-256 + scope + current security state;
   only complete verified backups; journal + vaults + keys + nonce history + safety backups OUTSIDE the restore boundary;
   verified safety backup first; original live state kept until health passes; automatic rollback, and if rollback fails ->
   safe recovery mode with the runner gate closed; recovery works with the service stopped/damaged; automatic resume after
   power loss; idempotent durably recorded steps; no concurrent upgrades/installs/restores/rotations/conflicting backups;
   runner gate closed during restore and reopened only after service health AND all 21 confinement checks pass; owner/root
   separation kept (root never gets unrestricted access to the owner's home); settings preserved by default, differences shown,
   replacing/recovering a settings file needs explicit owner approval.
   Replay protection: keep current connector/device/token/passkey revocations, consumed approval IDs and security-critical
   history; expire restored pending requests, challenges and enrollment windows; abandon historical release transactions; never
   replay install/release/rollback/restore authorizations; quarantine restored passkeys; monotonic restore counter outside the
   restored state.
   Tests: interruption/power loss at every stage; swapped files, stale approvals, concurrency, corruption, missing keys,
   revocations; failed startup, failed confinement, successful and failed rollback; disposable environments only (vacation).

## Dev24 (off-machine) and Dev25 (repositories) - requirements in the master plan
- Dev24: encrypted external backups (Pi 8 TB drive first), owner-controlled key export/recovery, independent verification of
  transferred archives, recovery after full Ryzen drive failure, scoped transfers without exposing credentials/keys to AI workers.
- Dev25 (required Core): GitHub/GitLab/Forgejo/local Git management with GREEN/YELLOW/BLACK rules; first acceptance test =
  reconcile the owner's DeckPlay HQ project across its GitHub, GitLab and Pi Forgejo copies (repository details in the private
  plan; the GitLab main branch is NOT the baseline) and create one canonical authorized Ryzen workspace without losing history.
  Read-only reconciliation may run in parallel; never blindly overwrite/merge/sync/delete/deploy.

## Deferred tracker (keep)
authority SHOULD-FIX (tmpfs size/options check, verified unmount + cleanup, keep test counts after a later failure); self-test
syscall numbers per architecture; release build account identity check; Wake-on-LAN read on the installer side; KDE Plasma power
settings; 'unavailable' vs 'effective default' in system status; ScopeChallenge body limits; audit-dir fsync ordering; pkexec
helper routing; stricter fetch-destination filtering before public release; signing-key rotation drill + retiring the old key
(details in the private plan); manifest v2 multi-signature + signed revocation list; passkey enrollment GUI; delete staging branches
dev12/dev13; Phase S2/S4/S5 (system changes, shutdown/reboot, network safety net); independent published-asset verification.
