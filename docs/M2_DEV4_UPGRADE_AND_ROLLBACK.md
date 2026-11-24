# StyNpilot dev4: first install, self-upgrade, rollback

dev4 adds (S1) read-only diagnostics, protected log and file reads, and (S2) owner-approved, signed self-upgrade.
dev4 is the **last** upgrade that needs a terminal. After it, upgrades are requested by ChatGPT or Claude,
approved on the owner's phone, and verified (with automatic rollback) by StyNpilot.

## Rollback chain
dev4 -> dev3 -> dev2 -> dev1 -> dev0 -> Preview26. dev0-dev3 packages and all backups are kept.

## First manual dev4 install (the last one)
Do this only after the independent review and the owner's go-ahead.

1. Back up first (existing preflight backup tool): `sudo tools/preflight_backup.sh`.
2. Download `stynpilot-v0.1.0-dev4.deb` and check its SHA-256 against the value in the signed
   `release-manifest.json` and in the review packet.
3. Install: `sudo dpkg -i --force-confold stynpilot_0.1.0~dev4_all.deb`
   (the package has no maintainer scripts: it starts and changes nothing by itself).
4. Restart the installer and the owner service, then run the doctor check.
5. Confirm from the phone: ChatGPT/Claude read `computer_health`; status should show version 0.1.0~dev4.

## Manual rollback (works even if everything else is broken)
`sudo dpkg -i --force-downgrade --force-confold stynpilot_0.1.0~dev3_all.deb` then restart the installer and owner
services. Upgrades also leave a README with this command in `upgrades/<id>/`.

## Every later upgrade (no terminal)
1. The release builder signs the package with `tools/sign_release.py` and publishes three files to the GitHub
   release: the `.deb`, `release-manifest.json`, `release-manifest.json.sig`.
2. An AI calls `commander_request_stynpilot_upgrade(device_id, version)`. It fetches and verifies the manifest;
   an untrusted, mismatched or older release is refused.
3. The owner opens the approval link on the phone and signs in again. Neither AI can approve.
4. The root installer: re-verifies, checks the proof (without consuming it), backs up its records, downloads and
   inspects the package (no maintainer scripts, no setuid, only StyNpilot paths, same Depends), saves a verified
   rollback copy, then hands off to a detached worker.
5. The worker installs, restarts, and checks: right version, installer answering, owner service staying up, config
   files unchanged, doctor not worse. On ANY failure it reinstalls the saved previous package and re-checks. If
   that fails too, it flags the owner.

## Honest limits
- The release signing key exists only on the release builder; losing it means one more manual terminal install
  (new key via a manually installed package).
- A reboot or crash during the few minutes of an upgrade leaves no worker; the owner is flagged and the README
  has the manual rollback.
- An upgrade that changes the Depends line is refused (deliberate; later work).
- Redaction of file/log content is heuristic, and what is read is sent to the AI provider.
- Reading the system journal needs the owner to be in the `adm` or `systemd-journal` group.
- The live self-upgrade is first proven for real by upgrading dev4 -> dev5.
