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
