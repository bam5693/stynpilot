# Dev22: encrypted automatic backups, verification and recovery drills

Two vaults, one per side (privilege separation unchanged): the owner service backs up the owner side as the owner; the installer
backs up the root side as root. Each side has its own key and can open only its own backups.

- Owner side (`~/.local/state/stynpilot-owner/vault`): owner state (request queue, revocations, token revocations, provisioned
  marker) via backup.py, plus owner.json, the pairing database and read-roots.json.
- Root side (`/var/lib/stynpilot-installer/vault`): ledgers, rollback snapshots, attention records and the passkey database via
  backup.py (root backups are refused while an install runs), plus /etc/stynpilot/{installer,passkeys,release}.json, the
  trusted-release-key addendum and release-transaction records.
- Never included: /var/lib/stynpilot/release/ (signing key, GitHub token); any extra file with a private-key or GitHub-token marker
  or a secret-named JSON key is left out and listed in the status.
- File: `STYNVLT1 | header | AES-256-GCM(bundle)`; header (format, side, created, version, key id, nonce, size) authenticated;
  96-bit random nonces, recorded before use and never reused; bundle = backup.py archive + extra files, each SHA-256.
- Key: created once (0600); if missing while backups or the index exist, nothing is created and status reports backup_key_missing.
- Every backup is verified at once (decrypt, hashes, backup.read_backup, SQLite integrity_check). Atomic writes with fsync;
  folders 0700, files 0600, links refused; ownership and modes checked on every run.
- Schedule: first backup ~30 s after the service starts, then hourly checks; due after 24 h (catches up after downtime); a failing
  backup is retried hourly; a recovery drill weekly and after the first backup.
- Retention 7 daily + 4 weekly; the newest verified backup (and the one just made) is never deleted; nothing is deleted to make
  space (insufficient_storage is reported instead); files the vault did not create (legacy tar backups, pre-upgrade copies, upgrade
  rollback records) are never touched.
- Drill: newest verified backup restored into a NEW folder inside the vault's private scratch area (never live state, no network),
  every file and database checked (root: every restored passkey must be quarantined), then deleted.
- Tools: backup_status (GREEN, read-only, metadata only), commander_backup_now and commander_backup_drill (GREEN, owner side then
  root side, rate limited 10 min / 1 h). Retention changes, key export, external destinations and live restore are YELLOW (Dev23/24).
- Failures never stop the services: every error is recorded and shown (overdue, key missing, corruption, low storage, failed drill).

## Review corrections (focused review)
- Resource safety: every backup, verification, re-check and drill runs in a separate short-lived process (`python3 -I`, address
  space limited to 1280 MiB); the owner service and the installer only read the small index. A child that runs out of memory,
  crashes or times out is recorded (`backup_process_failed_exit_N`) and the service carries on. Sizes are checked from `lstat`
  BEFORE anything is read: 256 MiB per backup, 128 MiB per state file, 16 MiB per settings file.
- Settings are checked against their own schema (owner.json = OWNER_KEYS, so token_endpoint is fine; installer.json,
  passkeys.json, release.json, read-roots.json, trusted-release-keys.json likewise); unexpected fields are refused. Required files
  (owner.json, the pairing database; installer.json) that are missing or refused make the backup `complete: false`, reported as
  `incomplete_backup:<names>`.
- Drills restore the state archive AND every extra into the scratch folder, compare every restored file's hash with the backup
  (the passkey database must instead have every activated, non-revoked passkey quarantined; any SQLite error fails), and run
  integrity checks.
- Re-checks: the newest verified backup is checked for presence hourly and fully daily; a missing or damaged one stops counting
  and a replacement backup is made at once.
- Index: schema and every name are validated before retention may delete anything; a damaged index is kept aside
  (`index.damaged-<time>.json`), rebuilt from the backup files themselves (each re-verified) and retention is skipped in that run.
  Nonces live in an append-only, fsynced `nonces.log` (plus the headers of every backup present), independent of the index.
- Retention deletes only files named like its own backups AND listed in its own index; anything else in or near the vault
  (including Codex's two precautionary Dev21 archives, wherever they are kept) is never touched.
- commander_backup_now and commander_backup_drill go through the write gate (workspace.propose + an enrolled client), like the
  other tools that change something; backup_status stays a read tool.

## Second focused review
- Retention separates VERIFIED from COMPLETE: the newest complete verified backup is never deleted, and the daily/weekly windows
  are filled with complete backups only, so any number of incomplete ones cannot displace the last complete recovery point
  (test: one complete backup, then 60 incomplete daily ones).
- A rebuilt index takes `excluded` / `incomplete` from each backup's authenticated bundle; an unreadable one counts as incomplete.
- The worker refuses all work (`backup_worker_memory_limit_unavailable`) if its memory limit cannot be set and confirmed.
- Free space (3x the measured size + 64 MiB) is checked before any temporary file is written.
- Worker crashes and timeouts are recorded for drills and re-checks too; a crashed check never un-verifies a good backup.
- The nonce log is created together with the key; if it later disappears, new backups stop (`nonce_log_missing`) instead of
  trusting the surviving files. Recovery = an owner-approved new key (tracked for Dev23). An empty log left by an interrupted
  first start does not block the first backup.
