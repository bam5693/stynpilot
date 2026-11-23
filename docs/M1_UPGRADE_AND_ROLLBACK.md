# Upgrading a running StyNpilot to M1 (0.1.0~dev1) and rolling back

**Nothing here has been run on the owner's computer.** Every step needs the owner's approval first.
The current installation is the rollback baseline. Preview26 is untouched and stays an older emergency fallback.
Do **not** repeat setup, Auth0 configuration or pairing: the package keeps all of that (proved below).

## Files

| File | sha256 |
|---|---|
| `baseline_0.1.0~dev0_all.deb` (built reproducibly from commit `bfa1ef0`, PR #14) | `b3d639bd190abe240ea87526cb31b4e58096fe4aac9a09c7ca2996a32c4c91cf` |
| `stynpilot_0.1.0~dev1_all.deb` (M1, PR #15) | `f055d1dd397b0e94edee30263197423d8cd7364969dc43b9a7f3bde80f9a66ed` |

The version differs (`~dev1` > `~dev0`), so apt treats it as an upgrade; installing the baseline back is an explicit downgrade.

## Before (read-only, then backups)

1. `dpkg-query -W stynpilot` shows `0.1.0~dev0`; `systemctl is-active stynpilot-installer`, `systemctl --user is-active stynpilot-owner`, `stynpilot doctor` are healthy.
2. Keep the baseline package and prove it **is** what is installed:
   `sha256sum baseline_0.1.0~dev0_all.deb`, then `dpkg-deb -x baseline_0.1.0~dev0_all.deb /tmp/bx && diff -r /tmp/bx/usr/lib/stynpilot /usr/lib/stynpilot && echo SAME`.
   If it prints differences, the live build is not `bfa1ef0`: stop, and keep a copy of the package that was actually installed before going on.
3. Backups (configuration, pairing, approvals, request history, installer state): `stynpilot backup --out ~/pre-m1-owner.tar` and
   `stynpilot root-backup --out ~/pre-m1-root.tar` (polkit password prompt). Check each with `tar -tf`.
4. `sha256sum stynpilot_0.1.0~dev1_all.deb` must equal the value above.

## Upgrade

`sudo apt-get install ./stynpilot_0.1.0~dev1_all.deb`, then `stynpilot stop` and `stynpilot start` (the running services keep the old code until restarted),
`stynpilot doctor`, then refresh the ChatGPT and Claude connectors (new tools: `commander_software_search`, `computer_inventory`).

## Roll back

`stynpilot stop`; `sudo apt-get install --allow-downgrades ./baseline_0.1.0~dev0_all.deb`; `stynpilot start`; `stynpilot doctor`; refresh connectors.
State is untouched by both directions. Use the backups (`stynpilot restore`, `stynpilot root-restore`) only if state were somehow damaged.
A not-yet-decided M1 request made by package name would be unreadable to the older installer; let it expire or deny it.

## Proof (disposable Ubuntu 26.04 chroot; `tools/upgrade_rollback_check.sh`)

Installs the baseline, creates owner and installer state (settings, receipt, pairing, approvals, request history, ledger, snapshots),
upgrades, and checks: state byte-for-byte identical and same permissions/owners; no unit enabled; program changed; downgrade restores the
baseline program byte-for-byte, state still identical, the program runs; upgrading again gives the same result. Result: PASS.
Not provable off the machine: the live services restart and the real polkit prompts (covered by the VM scenarios for the same package).
