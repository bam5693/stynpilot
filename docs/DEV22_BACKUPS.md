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
