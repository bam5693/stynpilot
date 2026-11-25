"""Phase S1: read-only system-management status (GREEN). Sleep and hibernation, Wi-Fi reconnection, what starts at boot, power and
Wake-on-LAN, pending reboot, firmware power-recovery and StyNpilot backups.

Same rules as diagnostics.py: FIXED commands with fixed arguments, no shell, short timeouts, bounded output, and no value chosen by an
assistant ever reaches a command. Only setting NAMES and short values are reported: never Wi-Fi passwords or keys (nmcli is asked for
named, non-secret fields only), never serial numbers. Every section is independent; one that cannot be read says so and the rest answer.
Nothing here changes the machine. Changes (Phase S2) are YELLOW and go through owner approval; they are not in this module.
"""
from __future__ import annotations

import os
import re
import stat
import time
from pathlib import Path

from .diagnostics import real_run

SLEEP_TARGETS = ("sleep.target", "suspend.target", "hibernate.target", "hybrid-sleep.target", "suspend-then-hibernate.target")
BOOT_UNITS = ("NetworkManager.service", "tailscaled.service", "ssh.service", "stynpilot-installer.service")
USER_BOOT_UNITS = ("stynpilot-owner.service",)
LOGIND_KEYS = ("HandleLidSwitch", "HandleLidSwitchExternalPower", "HandleLidSwitchDocked", "HandleSuspendKey", "HandleHibernateKey",
               "HandlePowerKey", "IdleAction", "IdleActionSec")
SLEEP_KEYS = ("AllowSuspend", "AllowHibernation", "AllowHybridSleep", "AllowSuspendThenHibernate", "SuspendState", "HibernateMode",
              "HibernateDelaySec")
GNOME_POWER = ("sleep-inactive-ac-type", "sleep-inactive-ac-timeout", "sleep-inactive-battery-type", "sleep-inactive-battery-timeout")
FIRMWARE_NOTE = ("Restore-after-power-loss ('Restore on AC Power Loss' / 'AC Back') is a firmware (BIOS/UEFI) setting. Linux cannot read "
                 "or change it on most PCs; check it once in the firmware setup screen.")
MAX_VERIFY_BYTES = 64 * 1024 * 1024        # owner-state backups are small; a bigger file is reported, never loaded
_IFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}\Z")
_SAFE = re.compile(r"[^A-Za-z0-9 _.,:/+@()%=\[\]-]")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def _clean(text, limit=80):
    return _SAFE.sub("?", str(text).strip())[:limit]


def _nmcli_fields(line):
    """nmcli -t: fields split on ':' with '\\:' as an escaped colon."""
    out, cur, i = [], "", 0
    while i < len(line):
        if line[i] == "\\" and i + 1 < len(line):
            cur += line[i + 1]
            i += 2
            continue
        if line[i] == ":":
            out.append(cur)
            cur = ""
        else:
            cur += line[i]
        i += 1
    return out + [cur]


def _settings(text, keys):
    """The effective value of each key in a systemd 'cat-config' dump (last assignment wins; comments ignored)."""
    found = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "[")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip() in keys:
            found[key.strip()] = _clean(value, 40)
    return found


class SystemStatus:
    def __init__(self, *, run=real_run, sys_root="/sys", reboot_flag="/var/run/reboot-required", backup_dir=None, uid=None,
                 clock=time.time):
        self.run, self.sys, self.reboot_flag = run, Path(sys_root), reboot_flag
        self.backup_dir, self.uid, self.clock = (Path(backup_dir) if backup_dir else None), (os.getuid() if uid is None else uid), clock

    def _read(self, path, limit=200):
        try:
            return Path(path).read_text(errors="replace")[:limit].strip()
        except OSError:
            return None

    def _enabled(self, prefix, unit):
        """One unit per call, so a missing unit can never shift another unit's answer."""
        _, out = self.run(prefix + ["is-enabled", unit])
        words = out.split()
        return _clean(words[0], 20) if len(words) == 1 else "unknown"

    # -- sections ---------------------------------------------------------------------------------------
    def sleep(self):
        targets = {t: self._enabled(["systemctl"], t) for t in SLEEP_TARGETS}
        _, logind = self.run(["systemd-analyze", "cat-config", "systemd/logind.conf"])
        _, sleepconf = self.run(["systemd-analyze", "cat-config", "systemd/sleep.conf"])
        desktop = {}
        for key in GNOME_POWER:
            c, value = self.run(["gsettings", "get", "org.gnome.settings-daemon.plugins.power", key])
            if c == 0 and value.strip():
                desktop[key] = _clean(value.strip().strip("'"), 30)
        masked = [t for t, s in targets.items() if s == "masked"]
        return {"targets": targets, "sleep_blocked_by_masking": bool(masked) and "sleep.target" in masked,
                "kernel_supports": (self._read(self.sys / "power/state") or "").split(),
                "suspend_mode": _clean(self._read(self.sys / "power/mem_sleep") or "", 40) or None,
                "hibernate_mode": _clean(self._read(self.sys / "power/disk") or "", 60) or None,
                "logind": _settings(logind, LOGIND_KEYS), "sleep_conf": _settings(sleepconf, SLEEP_KEYS),
                "desktop_idle": desktop or None}

    def network(self):
        code, out = self.run(["nmcli", "-t", "-f", "NAME,UUID,TYPE,DEVICE,AUTOCONNECT,AUTOCONNECT-PRIORITY", "connection", "show"])
        if code != 0:
            return {"unavailable": "nmcli_not_answering"}
        connections = []
        for line in out.splitlines()[:40]:
            f = _nmcli_fields(line)
            if len(f) < 6 or not _UUID.fullmatch(f[1]):
                continue
            entry = {"name": _clean(f[0], 60), "type": _clean(f[2], 30), "device": _clean(f[3], 20) or None,
                     "autoconnect": f[4] == "yes", "priority": _clean(f[5], 6)}
            if "wireless" in f[2]:
                c, retries = self.run(["nmcli", "-g", "connection.autoconnect-retries", "connection", "show", "uuid", f[1]])
                value = retries.strip()
                entry["autoconnect_retries"] = _clean(value, 6) if c == 0 else None
                # NetworkManager: 0 = forever (unless the global default says otherwise), -1 = use the global default (4 tries)
                entry["reconnects_forever"] = value == "0" if c == 0 else None
            connections.append(entry)
        _, conn = self.run(["nmcli", "-t", "networking", "connectivity"])
        return {"connectivity": _clean(conn, 20) or None, "connections": connections}

    def boot(self):
        system = {u: self._enabled(["systemctl"], u) for u in BOOT_UNITS}
        user = {u: self._enabled(["systemctl", "--user"], u) for u in USER_BOOT_UNITS}
        _, linger = self.run(["loginctl", "show-user", str(int(self.uid)), "-p", "Linger", "--value"])
        _, failed = self.run(["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"])
        return {"system_units": system, "user_units": user, "linger": {"yes": True, "no": False}.get(linger.strip()),
                "failed_system_units": [_clean(l.split()[0], 80) for l in failed.splitlines() if l.strip()][:20]}

    def power(self):
        supplies = []
        base = self.sys / "class/power_supply"
        for d in sorted(base.iterdir())[:8] if base.is_dir() else []:
            kind = self._read(d / "type", 20)
            row = {"name": _clean(d.name, 20), "type": kind}
            for key in ("online", "capacity", "status"):
                value = self._read(d / key, 20)
                if value is not None:
                    row[key] = _clean(value, 20)
            supplies.append(row)
        wol = []
        nets = self.sys / "class/net"
        for d in sorted(nets.iterdir())[:16] if nets.is_dir() else []:
            if not _IFACE.fullmatch(d.name) or d.name == "lo" or not (d / "device").exists():
                continue
            row = {"interface": d.name, "wireless": (d / "wireless").exists(), "kernel_wakeup": self._read(d / "device/power/wakeup", 20)}
            code, out = self.run(["ethtool", d.name])
            if code == 0:
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith("Supports Wake-on:"):
                        row["supports_wake_on"] = _clean(line.split(":", 1)[1], 20)
                    elif line.startswith("Wake-on:"):
                        row["wake_on"] = _clean(line.split(":", 1)[1], 20)
                if "supports_wake_on" in row:
                    row["magic_packet_supported"] = "g" in row["supports_wake_on"]
                    row["magic_packet_enabled"] = "g" in row.get("wake_on", "")
            else:
                row["ethtool"] = "unavailable"
            wol.append(row)
        return {"supplies": supplies, "wake_on_lan": wol}

    def firmware(self):
        dmi = self.sys / "class/dmi/id"
        info = {k: _clean(self._read(dmi / k, 80) or "", 60) or None for k in ("sys_vendor", "product_name", "board_name", "bios_version")}
        return {"machine": info, "power_loss_recovery": {"readable": False, "note": FIRMWARE_NOTE}}

    def reboot(self):
        pkgs = self._read(self.reboot_flag + ".pkgs", 2000)
        return {"reboot_required": os.path.exists(self.reboot_flag),
                "because_of": sorted({_clean(p, 40) for p in pkgs.split()})[:20] if pkgs else []}

    def backups(self):
        if not self.backup_dir:
            return {"unavailable": "no_backup_folder_configured"}
        try:
            found = sorted(self.backup_dir.glob("stynpilot-backup-*.tar"), key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            return {"unavailable": "backup_folder_unreadable"}
        rows = []
        for p in found[:5]:
            st = p.lstat()
            rows.append({"name": _clean(p.name, 60), "size_kb": st.st_size // 1024, "age_days": round((self.clock() - st.st_mtime) / 86400, 1)})
        newest = {"verified": None}
        newest_st = found[0].lstat() if found else None
        if newest_st and not stat.S_ISREG(newest_st.st_mode):
            newest = {"verified": False, "problem": "not_a_regular_file"}
        elif newest_st and newest_st.st_size > MAX_VERIFY_BYTES:
            newest = {"verified": None, "problem": "too_large_to_verify_here"}
        elif newest_st:
            from . import backup
            try:
                manifest, files = backup.read_backup(str(found[0]), expected_kind="owner")
                newest = {"verified": True, "files": len(files), "kind": _clean(manifest.get("kind", ""), 20)}
            except Exception as error:                                   # BackupError or a damaged archive: report, never raise
                newest = {"verified": False, "problem": _clean(getattr(error, "code", None) or str(error) or type(error).__name__, 60)}
        return {"owner_state_backups": rows, "count": len(found), "newest": newest,
                "scope_note": "These are StyNpilot owner-state backups only; they are not a backup of the computer's files."}

    def report(self):
        out = {}
        for name, probe in (("sleep", self.sleep), ("network", self.network), ("startup", self.boot), ("power", self.power),
                            ("firmware", self.firmware), ("reboot", self.reboot), ("backups", self.backups)):
            try:
                out[name] = probe()
            except Exception:
                out[name] = {"unavailable": True}
        return out
