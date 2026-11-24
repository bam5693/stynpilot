# StyNpilot dev4: first install, self-upgrade, rollback

dev4 adds (S1) read-only diagnostics, protected log and file reads, and (S2) owner-approved, signed self-upgrade.
dev4 is the **last** upgrade that needs a terminal. After it, upgrades are requested by ChatGPT or Claude,
approved on the owner's phone, and verified (with automatic rollback) by StyNpilot.

## Rollback chain
dev4 -> dev3 -> dev2 -> dev1 -> dev0 -> Preview26. dev0-dev3 packages and all backups are kept.

## First manual dev4 install (the last one): ONE command
Only after the independent review and the owner's go-ahead. Run as the normal account (not root), in one terminal.
The command (with the real COMMIT and SHA-256 filled in by the chat) downloads the install script from the pinned commit,
checks the script's own SHA-256, then runs it:

    curl -fsSL https://raw.githubusercontent.com/bam5693/stynpilot/COMMIT/tools/install_dev4.sh -o /tmp/install_dev4.sh && echo "SCRIPT_SHA256  /tmp/install_dev4.sh" | sha256sum -c - && sh /tmp/install_dev4.sh COMMIT PACKAGE_SHA256

It asks for the password once and then, with no further input:
1. Preflight (no changes): must be exactly dev3; services running; baseline doctor and MCP-endpoint results recorded;
   settings files fingerprinted; disk space; the new package is REBUILT from the pinned commit and refused unless its
   SHA-256 matches; the dev3 rollback package is checked (or rebuilt from its pinned commit); no install scripts; same Depends.
2. Backup of owner settings/records and the installer's records, verified (existing preflight tool).
3. Install, restart both services, then up to 90 s of health checks: version, both services up and STAYING up, doctor not
   worse than before, the local MCP endpoint answers and demands a token, settings files byte-identical.
4. ANY failure, Ctrl-C or a dropped terminal after the first change: dev3 is reinstalled and re-checked.
   Final line is one of `RESULT: SUCCESS`, `RESULT: ROLLED BACK`, or `RESULT: NEEDS HELP` (with the one manual command).
A log is kept in `~/stynpilot-upgrade-logs/`; paste only the last lines to ChatGPT if asked. Nothing is ever deleted.
The script is drilled in the sandbox (`tools/install_dev4_check.sh`, root, sandbox only) against real packages: success,
doctor failure, service down, failed restart, broken endpoint, wrong checksum, already installed, refusing root, Ctrl-C.

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

## File reads: which folders an assistant may read
The home folder is NOT readable. By default only narrow diagnostic locations are (logs under /var/log and a few system
files such as os-release and the apt sources). Project folders become readable only if the owner lists them in
`read-roots.json` in the StyNpilot state folder (`{"project_roots": ["/home/you/work"]}`; folders strictly inside the home
folder, never hidden ones). A bad file or entry means none. Inside an authorized folder, credential names, symlink escapes,
binary files and secret-looking content are still refused or redacted. The whole file is scanned before any part is shown,
files over 4 MiB are refused, and log text is redacted before any filtering. A phone-approved way to authorize a folder is future work.

## Honest limits
- The release signing key exists only on the release builder; losing it means one more manual terminal install
  (new key via a manually installed package).
- A reboot or crash during the few minutes of an upgrade leaves no worker; the owner is flagged and the README
  has the manual rollback.
- An upgrade that changes the Depends line is refused (deliberate; later work).
- Redaction of file/log content is heuristic, and what is read is sent to the AI provider.
- Reading the system journal needs the owner to be in the `adm` or `systemd-journal` group.
- The live self-upgrade is first proven for real by upgrading dev4 -> dev5.
