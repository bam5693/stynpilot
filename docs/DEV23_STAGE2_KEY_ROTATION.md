# Dev23 stage 2: secure backup key rotation (package 0.1.0.dev24)

Branch `claude/dev23-stage2-keys`, from the released Dev23 stage 1 commit `a611385`.

## What the owner gets
- A new YELLOW request, filed by an assistant with `commander_request_backup_key_rotation(device_id, side, mode)` (write gate
  required) and approved only by the owner's passkey/Auth0 single-use approval. The assistant never sees or touches any key.
- `side`: `root` (installer side; runs inside the installer) or `owner` (the owner's own side: the installer verifies and spends
  the approval, then the owner service rotates its own vault with that exact request id).
- `mode normal`: replace the key. Also the approved way out of `nonce_log_missing` (a lost nonce log): the new key generation
  starts with its own fresh nonce log, so no nonce can repeat under the new key.
- `mode lost_key`: only when the key is really gone (`backup_key_missing`). Backups that needed it are moved to
  `unreadable/` and KEPT (never deleted automatically); a fresh key starts. Refused while a key is present.

## Key generations
- Key file format unchanged (`STYNKEY1` + 8-byte id + 32-byte key; Dev24 export-compatible). Every backup header already names its
  `key_id`, so each backup is opened with the generation that made it: the active `backup-key`, or a kept generation in `keys/`
  (`keys/<id>.key`, `keys/<id>.nonces`, folder 0700, files 0600).
- Each generation has its own nonce log. The active one is `nonces.log`; retired logs are kept in `keys/`.
- A key whose id does not match the vault index is never trusted (`backup_key_does_not_match_the_vault`).

## Normal rotation, step by step (journal `rotation.json`, fsynced after every step)
1. Create the new generation (`keys/<new>.key` + empty `keys/<new>.nonces`), then write the journal.
2. Record the approval id (an approval can never start a second rotation).
3. For each backup made with the old key: decrypt it; check free space; record a NEW nonce in the new log BEFORE use; encrypt;
   write `.rotate-<name>` atomically; read it back and decrypt it with the new key; compare the bundle SHA-256 and every header
   field; only then `os.replace` it over the original. A failed check removes the temporary copy, leaves the original untouched
   and stops (it resumes later). A backup the old key cannot open is left as it is and keeps the old key alive.
4. Switch: copy the old key and its nonce log into `keys/` FIRST, then install the new nonce log and the new key, then the index.
5. Cleanup: destroy every kept key generation that no retained backup needs any more (counted from the backups' own headers);
   remove temporary copies; record `last_rotation`; delete the journal.

While a journal exists nothing else runs (`key_rotation_in_progress`). The scheduler resumes an interrupted rotation first, on the
next tick (also after a service restart or power loss). Status shows `key_rotation_incomplete` meanwhile, and `keys` (active id,
kept generations, last rotation - never key material or the approval id).

## Lost-key recovery
1. Journal, then approval id recorded.
2. Move every backup whose key generation is not present to `unreadable/` (kept, never deleted; retention never looks there);
   backups of a kept older generation stay in place and stay usable. The lost key's nonce log is kept beside them.
3. Fresh key + fresh nonce log; index updated; journal removed. Status shows `unreadable_backups_kept:N`.

## Where it runs
- Inside the isolated, memory-limited (`RLIMIT_AS` 1280 MiB) backup worker, under the vault lock, like every heavy vault operation.
  Peak memory is about two copies of one backup.

## Tests (`tests/test_dev23_key_rotation.py`)
- Power loss at EVERY durable step (every atomic write, rename, delete and fsync) of a normal rotation and of a lost-key recovery:
  after a restart the rotation completes (or, before the approval was recorded, can be re-approved), all backups are intact with
  identical contents, all under the new key, no old key left that nothing needs, no temporary copies, no repeated nonce.
- Re-encrypted copy failing verification never replaces the original; out of space stops safely and resumes.
- Separate key ids and nonce logs per generation; nonce uniqueness across 3 rotations.
- Never destroying a key a retained backup needs; a retired generation still opens its backups.
- Lost nonce log resolved by an approved new key; swapped key never trusted.
- Lost key: unreadable archives preserved byte-for-byte, retention never touches them; refused while the key is present; older
  readable generations kept in place.
- Executor: single-use proof, replay refused, malformed/expired/forged requests refused; owner-side only authorizes; owner hook
  rotates only for its own authorized request id; request tool needs the write gate.
- The isolated worker path.

## Not in this stage
- No live rotation during the vacation (not needed to verify the release). Restore stages 3/4 and Dev24 export come later.
