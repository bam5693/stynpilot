# M1: install any eligible Ubuntu package by name, and read the hardware inventory

An assistant (ChatGPT or Claude) can now **name** Ubuntu packages instead of picking from a fixed catalog.
The owner still approves every install separately on his phone; the assistant can never approve its own request.

## What an assistant can do

| Tool | Class | What it does |
|---|---|---|
| `commander_software_search(device_id, query)` | GREEN, read-only | Searches the computer's *local, signed* Ubuntu package lists by package name (bounded, strict text). Returns name, version, summary, whether it is installed, and whether an AI may request it. |
| `commander_request_software_install(device_id, packages=[…])` | YELLOW (owner approval) | 1–3 package names. StyNpilot resolves exact versions and dependencies itself and files one exact plan. `software=<catalog id>` still works as before. |
| `computer_inventory(device_id)` | GREEN, read-only | OS, CPU, motherboard, RAM capacity, GPU, drives, installed Ubuntu packages. No serial numbers, UUIDs, MAC/IP addresses, host names or file paths. |
| `commander_software_install_status`, `commander_request_software_rollback` | unchanged | Work for generic installs too (rollback names the generated software id `apt-<name>-<hash>`). |

If every requested package is already installed, the request tool answers `already_installed` and files nothing.

## What is checked, and where

1. **Owner side (early, friendly refusal)** – strict names (`[a-z0-9][a-z0-9+.-]*`, max 3, distinct), the impact gate,
   an `apt-get -s` simulation (no changes), every chosen source must be the signed Ubuntu archive, no removals.
2. **Root installer (authoritative, repeats everything)** – derives the allowed set *itself* from the requested names only
   (`apt.analyze`), refuses a plan that differs by one package, re-runs the impact gate, requires the software id to equal
   the deterministic id of the requested names, downloads the exact files, checks each file against the signed index hash,
   inspects every downloaded `.deb` (`dpkg-deb -c`) and refuses one that ships boot, kernel-module, sudoers, PAM, ssh, apt,
   polkit-rule or account files, then installs with `--no-download`, diffs the dpkg state, and rolls back on any difference.
3. **Owner approval** – the summary is rendered by the root installer and says which packages the assistant asked for, which
   were pulled in as dependencies, and that install scripts run as root: a signed source proves origin, not harmlessness.

## Refused outright for an AI (`src/stynpilot/impact.py`)

Kernels, boot loader, firmware; sudo, PAM, polkit, login screens; SSH / remote-desktop / FTP / file-sharing servers; core system
packages (systemd, libc, apt, dpkg, bash …); firewalls and network managers, Tailscale; container runtimes (they need the
separately reviewed container installer, C3); disk-encryption and volume tools; StyNpilot's own packages; anything that would
**remove** a package or **upgrade** an essential/required/important one. Notes shown to the owner (not refused): likely network
server, service files, setuid programs, large size, upgrades of already-installed packages.

## Limits (stated plainly)

* Backup/rollback is the existing bounded package rollback, not a system snapshot (see `LIMITS` in the result).
* The approval summary lists exact packages and versions plus a fixed warning; the `.deb`-content findings (service files,
  setuid) are enforced as a hard refusal for dangerous paths but are not yet shown as notes at approval time.
* DIMM slot/speed details need administrator access (`dmidecode`); the inventory reports them as unavailable, never guessed.
* Tool list changed (`commander_software_search`, `computer_inventory` are new): connectors must be refreshed after the upgrade.

## Evidence

* Unit tests: `tests/test_impact.py`, `tests/test_m1_apt.py`, `tests/test_inventory.py`, plus new cases in `test_plan.py`,
  `test_broker.py`, `test_propose_tools.py`, `test_server.py`.
* Real apt on an Ubuntu 26.04 chroot: `tests/test_broker_real_apt.py` (non-catalog `ncdu`: search → plan → approval → install →
  verify → already_installed → rollback; blocked names refused).
* QEMU VM, full workflow incl. real provider-style approval: `tools/vmtest/run_vm_test.py --scenario full` (M1 steps).
