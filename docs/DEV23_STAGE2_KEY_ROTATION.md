# Dev23 stage 2: secure backup key rotation (package 0.1.0.dev24)

Branch `claude/dev23-stage2-keys`, from the released Dev23 stage 1 commit `a611385`. First reviewed commit `28a5a7a`;
this revision answers ChatGPT's review of it (3 blockers, the lost-nonce-log design decision, the additional safety checks).

## What the owner gets
- YELLOW request `commander_request_backup_key_rotation(device_id, side, mode)` (write gate), approved only with the owner's
  passkey/Auth0 single-use approval. No assistant sees or touches any key.
- `side`: `root` (installer side, runs inside the installer) or `owner` (his own side; see "Owner-side hand-off").
- `mode`:
  - `normal`: replace the key; every backup is re-encrypted with the new key and verified before it replaces the original.
  - `fresh_key`: ONLY when the nonce log is missing or uncertain. A new generation (with its own new nonce log) is used for NEW
    backups; existing backups are NOT re-encrypted and stay readable with their key, which is kept and never encrypts again.
    (`normal` is refused while the log is missing or uncertain; `fresh_key` is refused while the log is fine.)
  - `lost_key`: ONLY when the key is gone. Backups that need it are preserved in `unreadable/` (never deleted); a fresh key starts.

## Key generations - never destroyed in this stage
- Key file format unchanged (`STYNKEY1` + 8-byte id + 32-byte key; Dev24-export compatible). Each backup header names its
  `key_id`; it is opened with that generation: the active `backup-key`, or a kept one in `keys/<id>.key`.
- Every earlier generation is KEPT with its full nonce history (`keys/<id>.nonces`, or reported `nonce_history: false` when the
  history was lost). Folder 0700, files 0600. Status lists generations (ids + whether history exists), never key material.
- No key is ever destroyed automatically (BLOCKER 1). Only the two staging copies of the now-active key are removed, after a
  byte-for-byte check. Controlled key retirement is a TRACKED FOLLOW-UP after Dev24 external recovery (it must account for
  unreadable/ archives and external copies, and never trust an unreadable or unauthenticated header).
- Kept generations only decrypt. New material is only ever encrypted with the active generation.

## Nonce histories
- Appends are written fully, fsynced, and CHECKED (file size must grow by exactly the line; otherwise `log_write_incomplete`).
- Reading: every complete line must be a valid nonce. An unfinished last line (power cut mid-write; never used, because a nonce
  is fsynced before use) is tolerated and is closed with a `!` marker before the next append. Anything else is
  `nonce_log_uncertain`: no new backups until an owner-approved `fresh_key` rotation.

## The journal (`rotation.json`)
- Validated completely before anything acts on it: exact key set per mode and state, ids (16 hex), request id (64 hex), file names
  (strict backup-name pattern), state machine. Anything else is `key_rotation_journal_damaged`: nothing runs, status shows it.
- Every step is fsynced and idempotent; the scheduler resumes an active rotation before anything else (also after a restart).
- Spent approvals: append-only, fsynced, UNBOUNDED `rotation-requests.log` (no bounded list).

## Normal rotation steps
1. New generation in `keys/`, then the journal, then the approval id is spent.
2. Per backup made with the old key: decrypt; space check; record a new nonce (checked write) BEFORE use; encrypt to
   `.rotate-<name>`; read back, decrypt with the new key, compare bundle SHA-256 and all header fields; only then `os.replace`.
   A failed check leaves the original untouched and stops (resumes later). Unreadable headers / backups the old key cannot open
   are left exactly as they are.
3. Switch: old key and its log copied into `keys/` FIRST; then the INDEX names the new key; then the new log and new key are put
   in place. (Older StyNpilot after a rollback: until the new key is in place it sees a key/index mismatch and refuses to make
   backups, so it can never pair the old key with the new log.)
4. Finish: staging copies removed (after checks), `last_rotation` recorded, journal removed.

## Lost-key recovery (BLOCKER 3)
- Each archive is preserved with a hard link (which fails if the name exists, so nothing is ever overwritten), the destination
  folder is fsynced, the copy is checked byte-for-byte (SHA-256), and only then the source is removed and its folder fsynced.
  A different file already at the destination: the archive gets a new name (`<name>.1`, ...). An identical copy already there
  (interrupted earlier move): counted as preserved.
- The lost key's nonce history is preserved the same way (`nonces-<id>.log`).
- Crash recovery reconciles the index with what is actually in `unreadable/` (also files whose journal entry was lost).

## Owner-side hand-off (BLOCKER 2)
1. Before the installer is asked, the owner service writes a durable marker bound to the exact request
   (`awaiting_authorization`: mode, request id, expiry). It changes nothing and does not stop backups.
2. The installer verifies and spends the approval and records an AUTHORIZATION (`rotation: authorized_owner_side_runs_it`), not
   a completion.
3. The owner service rotates its own vault with that request id. The owner's request becomes `done` only when the owner vault
   reports completion; if the rotation is interrupted it stays `running` and the vault finishes it and settles the request.
4. After a crash anywhere in between: the approval flow's recovery never marks such a request done from the installer's
   authorization; the vault (after a 10-minute grace) asks the installer's own record: authorized -> rotate and settle;
   not received / denied / failed -> drop the marker, spend the id, settle as failed; installer unreachable -> wait.
- States: awaiting_authorization -> (authorized at the installer) -> in progress (journal state) -> completed | failed;
  interrupted = journal present, resumed automatically. Results carry `rotation` and `progress` read from the journal itself.

## Overlap and rollback compatibility
- The installer refuses installs, rollbacks, upgrades and another rotation while a root rotation is active
  (`key_rotation_in_progress`). A root rotation itself holds the installer's operation lock, so it never runs during an install,
  rollback or backup of the installer's records. Vault operations are serialized by the vault lock; restore (stages 3/4) must
  check the journal too.
- Rollback to 0.1.0~dev23 checked with the RELEASED dev23 vault code (`a611385`) against rotated vaults: after a completed normal
  rotation it works normally; after `fresh_key` the backups under the kept generation fail its recheck and are reported
  (`backups_failed_a_recheck`) and kept, never deleted; after `lost_key` it works on the new key and ignores `unreadable/`; cut
  at every durable step of a normal rotation, dev23 never paired the old key with the new nonce log (95 steps, 0 unsafe), and
  this version finished every rotation afterwards.

## Tests (`tests/test_dev23_key_rotation.py`)
Power loss at EVERY durable step (atomic write, rename, delete, fsync, link) of normal, fresh_key and lost-key rotations, each
followed by restart + resume and full checks (contents, keys, nonce uniqueness, preserved archives, index), plus an
older-reader safety check at every step; unreadable headers never cost a key; verification failure; out of space; forged/
damaged journals; unbounded replay record; uncertain/torn/short nonce writes; swapped key; destination collisions and an
identical earlier copy; owner hand-off end to end with the real approval flow and installer (normal, crash after authorization,
crash before the installer received it); installer refusing other changes during a rotation; installer lock; isolated worker.

## Not in this stage
No live rotation during the vacation (not needed to verify the release). Key retirement, restore stages 3/4, Dev24 export later.
