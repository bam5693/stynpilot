# Upgrading a running StyNpilot to M1 (0.1.0~dev1) and rolling back

**Nothing in this guide has been run on the owner's computer.** Each live step needs the owner's approval, one command at a time.
The currently installed StyNpilot `0.1.0~dev0` is the rollback baseline. Preview26 is an older emergency fallback and is not touched.
Do **not** repeat setup, Auth0 configuration or pairing: the package keeps all of that (see "Proof").

## The two packages (pinned commits, published checksums)

| Package | Built from commit | sha256 |
|---|---|---|
| baseline `stynpilot_0.1.0~dev0_all.deb` | `bfa1ef0be968fbbd6e24f1dfc9bae72a0c3b2e62` (PR #14) | `b3d639bd190abe240ea87526cb31b4e58096fe4aac9a09c7ca2996a32c4c91cf` |
| M1 `stynpilot_0.1.0~dev1_all.deb` | `5f82d33db35390e6206e211d3f93525e5de29ceb` (PR #15; later commits only add documentation, tools and test evidence) | `f055d1dd397b0e94edee30263197423d8cd7364969dc43b9a7f3bde80f9a66ed` |

The build is reproducible (pinned, hash-checked wheels; fixed timestamps): `tools/get_release.sh` builds each package from a fresh clone of the public
repository at the pinned commit and refuses to save a file whose checksum differs (`docs/evidence/get-release-check.txt`: both hashes reproduced
on a different machine and path; a wrong expected hash is refused). Versions differ (`~dev1` > `~dev0`), so apt treats M1 as an upgrade and the baseline as an explicit downgrade.

## What is protected, and by what (no claim beyond this table)

| Item | Where it lives | Protected by |
|---|---|---|
| Owner settings file (AI-endpoint and Auth0 *connection* settings on this machine) | `~/.config/stynpilot/owner.json` | `tools/preflight_backup.sh` |
| Existing device pairing database | path from `owner.json` (`pairing_db`) | `tools/preflight_backup.sh` (SQLite online copy, integrity-checked) |
| Approval/request history, revocations, provisioned marker (every file in the owner state folder) | `state_dir` from `owner.json` | `tools/preflight_backup.sh` **and** `stynpilot backup` (the latter holds only four named files) |
| Root installer settings and setup receipt | `/etc/stynpilot/installer.json`, `setup-receipt.json` | `tools/preflight_backup.sh` root side -> root-only `/var/backups/stynpilot-pre-m1-<time>` (0700) |
| Installation records, run history, rollback snapshots | `/var/lib/stynpilot-installer` | `stynpilot root-backup` (polkit password prompt) |
| The program itself and its units/policy | package files | the saved baseline `.deb` + `tools/verify_baseline.sh` |
| Auth0 tenant settings, Tailscale | outside this machine | **not** backed up by anything here; not changed by this upgrade |

All backup folders are created new (0700), files 0600, never overwriting. Every copy is checked: SHA-256 list, SQLite integrity check, live files unchanged
while copying; `--verify` re-checks later. Contents are never printed. Tests: `tools/preflight_tools_check.sh`, evidence in `docs/evidence/preflight-tools-check.txt`
(tamper on either side is detected; existing destination is refused).

## Preflight (read-only, or writes only into new private folders under the owner's home and /var/backups)

1. Status: `dpkg-query -W stynpilot` -> `0.1.0~dev0`; `systemctl is-active stynpilot-installer`; `systemctl --user is-active stynpilot-owner`; `stynpilot doctor` shows no problems.
2. Get the reviewed tools and check you have the reviewed commit:
   `git clone --depth 1 --branch claude/m1-universal-install https://github.com/bam5693/stynpilot.git ~/stynpilot-m1-tools && git -C ~/stynpilot-m1-tools rev-parse HEAD`
   (must equal the commit ChatGPT approved in PR #15). Nothing is installed by this.
3. Build and checksum-verify both packages (stops on any mismatch):
   `sh ~/stynpilot-m1-tools/tools/get_release.sh bfa1ef0be968fbbd6e24f1dfc9bae72a0c3b2e62 b3d639bd190abe240ea87526cb31b4e58096fe4aac9a09c7ca2996a32c4c91cf ~/stynpilot-releases`
   `sh ~/stynpilot-m1-tools/tools/get_release.sh 5f82d33db35390e6206e211d3f93525e5de29ceb f055d1dd397b0e94edee30263197423d8cd7364969dc43b9a7f3bde80f9a66ed ~/stynpilot-releases`
   If a build tool is missing, report it; do not install anything ad hoc.
4. Prove the saved baseline is what is installed: `sh ~/stynpilot-m1-tools/tools/verify_baseline.sh ~/stynpilot-releases/stynpilot_0.1.0~dev0_all.deb`.
   It compares version, **every** file the package ships (program, root helper, both systemd units, polkit policy, desktop entries, docs) byte-for-byte and by mode,
   rejects extra packaged files, and runs `dpkg --verify`. **Any FAIL: stop.** Limits: it covers what the package installed; settings and state created later are covered by step 5, and
   it cannot prove nothing was hand-edited outside the package's own files.
5. Protect configuration, pairing, approvals and installer settings: `sh ~/stynpilot-m1-tools/tools/preflight_backup.sh` (asks for sudo for the root-only part). It prints both folders and `RESULT: PASS`.
6. Protect installation records and snapshots: `stynpilot root-backup --out ~/pre-m1-root.tar` (password prompt), and the owner archive `stynpilot backup --out ~/pre-m1-owner.tar`; check each with `tar -tf`.
7. Re-verify later at any time: `sh ~/stynpilot-m1-tools/tools/preflight_backup.sh --verify <owner backup folder>`.

## Upgrade (owner approval first)

`sudo apt-get install ~/stynpilot-releases/stynpilot_0.1.0~dev1_all.deb`, then `stynpilot stop`, `stynpilot start` (running services keep the old code until restarted),
`stynpilot doctor`, then refresh the ChatGPT and Claude connectors (new tools: `commander_software_search`, `computer_inventory`).
Confirm the ChatGPT and Claude connections still work with a health check before the live install test.

## Roll back

`stynpilot stop`; `sudo apt-get install --allow-downgrades ~/stynpilot-releases/stynpilot_0.1.0~dev0_all.deb`; `stynpilot start`; `stynpilot doctor`;
`sh ~/stynpilot-m1-tools/tools/verify_baseline.sh ~/stynpilot-releases/stynpilot_0.1.0~dev0_all.deb` must pass again; refresh the connectors.
State is untouched in both directions. A not-yet-decided M1 request made by package name would be unreadable to the older installer; let it expire or deny it.

**Only if configuration or state were damaged** (services stopped first: `stynpilot stop`), restore from the preflight folders, keeping restricted permissions:
`install -m 600 <backup>/owner/owner.json ~/.config/stynpilot/owner.json`; the pairing database and each `<backup>/owner/state/*` file likewise with `install -m 600` to the paths in `owner.json`;
root side: `sudo install -m 600 -o root -g root <root backup>/installer.json /etc/stynpilot/installer.json` (and `setup-receipt.json` the same way);
installer records: `stynpilot root-restore --archive ~/pre-m1-root.tar` (needs the installer stopped and an empty destination). Then `stynpilot start`, `stynpilot doctor`.

## Proof (disposable Ubuntu 26.04 chroot/VM; never the live machine)

* `tools/upgrade_rollback_check.sh` -> `docs/evidence/upgrade-rollback-check.txt`: state, permissions and owners byte-for-byte identical across upgrade and rollback; nothing enabled; baseline restored byte-for-byte; repeatable. PASS.
* `tools/preflight_tools_check.sh` -> `docs/evidence/preflight-tools-check.txt`; `docs/evidence/get-release-check.txt`.
* Not provable off the machine: the live service restart and the real polkit prompts (covered by the VM scenarios for the same package).
