# Dev23 stage 1: owner-approved retention settings and periodic re-verification

## Retention settings (YELLOW)
- New request kind `backup` (action `retention`): daily 1-30, weekly 0-12, enforced by the request tool, the installer's
  payload check and the vault itself. Exact payload keys, owner and device must match; it expires after an hour.
- Tool `commander_request_backup_retention(device_id, daily, weekly)` (write gate: workspace.propose + enrolled client) files the
  request; the owner sees the installer-rendered summary and approves with a single-use proof (passkey or Auth0), exactly like the
  other YELLOW kinds. The approval is consumed (`already_decided_or_used` on replay).
- On approval the installer writes `settings.json` in the ROOT vault (atomic, 0600, waits for any running backup operation);
  nothing is backed up, restored or deleted at that moment.
- The owner vault follows the installer's approved setting (GREEN read op `vault_settings`); if the installer is unreachable or
  answers something out of range, the owner side keeps the last setting it had.
- A settings file that is out of range, not private or unreadable is ignored (the built-in 7 daily + 4 weekly applies).
- Whatever the setting: the newest complete verified backup and the newest verified backup are always kept, and backups that
  failed a re-check are kept for inspection.

## Periodic re-verification
- Daily: full re-check of the newest verified backup AND the newest COMPLETE verified backup, independently of newer incomplete
  ones. Hourly: presence.
- Monthly: every retained backup (`full_check_at`).
- A backup that fails stops counting (`check_failed`) but is never deleted by retention; status reports
  `backups_failed_a_recheck:<n>`, `no_complete_verified_backup`, `complete_backup_overdue`; if the newest complete one failed, a
  new backup is made at once.

## Review corrections (fail-closed pruning)
- A settings file that exists but cannot be trusted (damaged, unreadable, loose, out of range) no longer falls back to 7+4:
  backups continue and are verified, but NOTHING is pruned (`retention_settings_untrusted`, `pruning_on_hold:<why>`).
- Owner side: pruning only after this run confirmed the installer's policy (a valid answer: approved, or none approved). If the
  installer is unreachable, answers with an untrusted policy, or no longer reports an approval the owner side holds, pruning is
  held (`retention_policy_unconfirmed`).
- Before pruning, the newest complete verified backup must have been checked within a day; if not, it is re-verified first, and
  if that fails it is kept (check_failed) and nothing is pruned.
- The monthly full check has a durable start (`full_check_at`, set at the first successful backup) and no longer depends on the
  oldest retained backup; 65 days of daily backups under normal retention run it at least twice.
- Release versions: the package dev number increments per release (stage 1 = 0.1.0.dev23); a published version is never reused.

## Second and third focused reviews
- Crash consistency: every applied policy is appended (fsynced) to `policy.log` BEFORE settings.json is written, and a setting is
  trusted only if settings.json EXACTLY matches the LATEST log entry (request id, daily, weekly). A missing settings file is the
  first-time default only when the log has no entries. A crash between the two writes, an older setting than the latest
  approval, a damaged last log entry, a loose or damaged file: pruning holds (`retention_settings_untrusted`).
- Owner-side pruning is DISABLED in this stage (the earlier lease design was not robust across concurrent installer connections,
  restarts and expiry, so it was removed rather than patched with timeouts). Owner backups, verification, re-checks and drills
  continue; status reports `pruning_on_hold:owner_side_pruning_disabled_until_safe_coordination`. Owner backups are small
  (~170 KB each). Safe owner pruning is a required follow-up.
- Root side: pruning continues under the vault lock (a retention change waits for any running backup operation) with the
  crash-consistent policy check above. Retention changes are serialized by the installer's one-change-at-a-time lock.
