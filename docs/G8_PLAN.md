# G8 plan: first real install on the owner's Ryzen (nothing here has been run on it)

Everything below is for the owner to approve step by step. Nothing is deployed, merged, or changed on the Ryzen,
the Raspberry Pi, Auth0, Tailscale, Cloudflare or Forgejo until the owner says so for that step.

## What the free isolated tests already prove (Ubuntu 26.04 under QEMU, real systemd/logind/polkit; 46 + 19 checks)
Evidence: `docs/evidence/vm-run-1.txt`, `docs/evidence/vm-run-preview26.txt`. Reproduce: `tools/vmtest/README.md`.
- Package installs by apt, starts and enables nothing; both unit files verify.
- Setup wizard end to end through the real polkit password prompt; Start/Stop buttons through their own prompts;
  `stynpilot start|stop`; reboot brings both services back with nobody logged in; a killed installer is restarted.
- Whole workflow: AI files an install request -> a second AI sees it pending -> AI has no approve path and a forged
  token is refused -> owner approves through the sign-in page (PKCE, nonce-bound proof) -> the root installer really
  installs `htop` from the Ubuntu archive -> both AIs read the same result -> state survives reboot -> rollback
  request, owner approval, rollback completes -> root backup/restore -> wrong user is refused by the root helper.
- Preview26 rehearsal: backup of a stand-in install, new StyNpilot installed beside it (Preview26 untouched), damage
  (package purged, settings deleted, database emptied), refused restores (damaged / world-readable archive), real
  restore: files, modes, owners, database content and running services identical to before.
- Bugs this found and fixed: setup page crashed on Save (missing form library); backups refused the normal 0750 home
  folder; "running" was reported before the AI endpoint was listening.

## What only the real Ryzen can prove
KDE's own password dialog (the VM uses polkit's text prompt; if KDE rejects a correct password with "No session for
cookie", that is a polkit-helper issue seen in the VM too, not StyNpilot); the real Auth0 tenant (scopes, revocation,
the actual ChatGPT/Claude connector enrolment); Tailscale/port 443 coexistence; the real Preview26 file layout; real
hardware reboot. These are the G8 steps below.

## Owner steps (each: exact action, what it changes, how to undo)
0. Pick the package: the `.deb` built from this PR (`python3 tools/build_deb.py`, sha256 in the PR comment).
1. READ-ONLY recon (changes nothing): `sh tools/preview26/inventory.sh`. Paste the output to Claude: it lists the real
   Preview26 files, units, listeners. Claude adjusts the backup tool if the layout differs from what was assumed.
2. BACKUP (copies only): `sudo apt install dpkg-repack` (free; lets the backup contain a reinstallable package copy),
   then `sudo sh tools/preview26/backup.sh`. Result: one private file in the home folder plus a `.sha256`. Copy both
   off the computer (USB or the Raspberry Pi). Undo: delete the two files.
3. DRY-RUN the restore (changes nothing): `sudo sh tools/preview26/restore.sh ~/preview26-backup-*.tar`.
4. INSTALL beside Preview26: `sudo apt install ./stynpilot_*_all.deb`. Starts nothing. Undo: `sudo apt remove stynpilot`
   (settings in /etc/stynpilot/installer.json and the receipt stay unless you delete them; Preview26 is not involved).
5. SETUP: menu "StyNpilot Setup" (or `stynpilot setup`): browser page, one password prompt (copies one settings file).
   Owner supplies Auth0 values (see "Owner actions outside the computer"). Undo: `stynpilot stop`.
6. START: "Start StyNpilot" (one password prompt). Check with the "StyNpilot Doctor" menu entry: no FAIL lines.
7. FIRST REAL REQUEST: ask ChatGPT to install a harmless package (e.g. `htop`); the request link appears; the owner
   opens it on their own sign-in and approves; both ChatGPT and Claude must report the same final result.
8. ROLLBACK DRILL: ask for the rollback of that install; approve; confirm the package is gone.
9. REBOOT the Ryzen; confirm Doctor is clean and Preview26 behaves as before.
10. ROLLBACK OF THE WHOLE UPGRADE if anything is wrong: `stynpilot stop`, `sudo apt remove stynpilot`; if Preview26 was
    harmed, `sudo sh tools/preview26/restore.sh <backup> --really`. Preview26 settings/units are never edited by the new
    package; the backup is the safety net, not a plan to need.

## Owner actions outside the computer (Claude cannot do these)
- Auth0: create/confirm the approval application and API audience; give Claude only non-secret values via the Vault
  (never the repo). Confirm token revocation endpoint is enabled.
- Tailscale: decide how the AI endpoint is reached (the new service listens on loopback 18443; Preview26 holds 443).
  Do not change Tailscale until step 1's output shows who owns 443.
- Raspberry Pi: only used as an off-computer place to copy the backup file.

## Cost
$0: QEMU, Ubuntu archive, Python. The VM test runs on the Ryzen too (it has KVM: much faster).
