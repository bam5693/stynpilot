# G7: install, check, back up, roll back (owner guide, draft)

Nothing here is deployed yet. G8 (owner-approved upgrade of the Ryzen) will give the exact commands.

- **Install:** open the `.deb` with Discover/Dolphin (or `sudo apt install ./stynpilot_*.deb`). Installing starts and
  enables nothing and changes nothing else. Preview26 is not touched.
- **First run:** open **StyNpilot Setup** from the menu. Type the seven values, press *Save and prepare*, then *Allow
  system part* (your normal password prompt). Nothing is started.
- **Check:** open **StyNpilot Doctor** from the menu. It only reads; it prints OK / WARN / FAIL.
- **Back up:** `stynpilot backup` (one verified file with hashes). **Recover lost state:** `stynpilot restore --archive FILE`.
  Restoring keeps revoked AI connectors revoked. A normal start never recreates lost state on its own.
- **Roll back the package:** `sudo apt remove stynpilot`. This removes only the program; your settings, state and Preview26
  stay. `sudo apt install ./older.deb` brings back an earlier build.

## Setup can be resumed (G7 review corrections)

Setup is a set of small, ordered stages: owner settings, the proposed installer settings, owner state, then the one
system step (the password prompt). If the window is closed, the prompt is cancelled or the computer stops part-way,
open **StyNpilot Setup** again and choose **Continue where I left off**. Existing settings and revocations are never
rewritten. If the saved settings differ from what is now typed, are loose (not private), or were tampered with, setup
stops and changes nothing. If setup had finished and the owner state later disappears, it is **not** recreated:
restore a backup. The setup link in the browser works once and then becomes a private session.

## Three different kinds of recovery

| Kind | Holds | Made / restored by |
|---|---|---|
| Owner state | requests, revoked clients, token revocations | `stynpilot backup` / `restore` (as the owner) |
| Software-install rollback records | root ledgers `installs.sqlite3`, `runs.sqlite3`, `snapshots/`, attention records | `stynpilot root-backup` / `root-restore` (graphical password prompt, fixed helper) |
| Preview26 rollback | existing Preview26 mechanism | unchanged; not touched by StyNpilot |

Backups carry an exact manifest with their kind; a backup of the wrong kind or a partial one is refused. Manifest
hashes detect damage; they are **not** a signature and do not prove who made the backup.

## Acceptance script

`tools/isolated_install_check.sh` exits nonzero on the first false assertion. `SP_INJECT=<name>` breaks one invariant
on purpose (`enable_unit`, `etc_created`, `allow_overwrite`, `keep_state`, `remove_config`) to prove it can fail.

## Root backup/restore is enforced to be consistent

- A root **backup** takes the installer's operation lock (`installer.lock`). It is refused while an install or rollback
  is running, and the installer refuses to start a change while a backup is reading. A run still marked "running"
  (an interrupted install not yet recorded by the installer) also blocks it.
- A root **restore** additionally needs the installer stopped (`installer.alive`) and only writes into an empty folder.
- Every snapshot the install ledger still points at (not yet rolled back) must be in the archive, complete and
  hash-correct, or backup/restore is refused. Archives are limited in file count, per-file size and total size, and
  duplicate member names are refused.
- Setup only counts as finished when `/etc/stynpilot/installer.json` is a root-owned private file with exactly the
  settings this owner's setup proposed. The password prompt names the one operation being approved (one polkit action
  per job: root-setup, root-backup, root-restore).
