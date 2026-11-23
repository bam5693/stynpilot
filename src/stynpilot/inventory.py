"""Read-only hardware and software inventory for the paired computer (GREEN).

Reads /proc, /sys, /etc/os-release and runs three fixed, read-only commands without root
(``lspci -mm``, ``lsblk -J``, ``dpkg-query`` / ``apt-mark showmanual``). Nothing is written.

Never returned: host name, user names, serial numbers, UUIDs, MAC or IP addresses, file or mount
paths (except the standard system mount points), environment, logs. DIMM slot/speed details need
administrator access on most machines, so they are reported as unavailable, never guessed.
Every value is bounded; anything the machine does not expose is None.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"}
MAX_PACKAGES = 150
MAX_DEVICES = 16
_SYSTEM_MOUNTS = ("/", "/boot", "/boot/efi", "/home")
_TEXT = re.compile(r"[^\x20-\x7e]")


def _clean(value, limit=96):
    return _TEXT.sub("", value or "").strip()[:limit] or None


def _read(path, limit=65536):
    try:
        with open(path, "rb") as handle:
            return handle.read(limit).decode("ascii", "replace")
    except OSError:
        return None


def real_run(argv, timeout=10):
    try:
        done = subprocess.run(argv, env=ENV, capture_output=True, text=True, timeout=timeout, check=False,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return 127, ""
    return done.returncode, done.stdout


def os_info(*, os_release="/etc/os-release", proc="/proc", uname=None):
    fields = {}
    for line in (_read(os_release) or "").splitlines():
        key, _, value = line.partition("=")
        fields[key] = value.strip().strip('"')
    arch = uname if uname is not None else __import__("os").uname().machine
    return {"name": _clean(fields.get("PRETTY_NAME")), "version_id": _clean(fields.get("VERSION_ID"), 32),
            "kernel": _clean(_read(Path(proc) / "sys/kernel/osrelease", 128), 64), "architecture": _clean(arch, 32)}


def cpu_info(*, proc="/proc", sys_root="/sys"):
    text = _read(Path(proc) / "cpuinfo", 1 << 20) or ""
    model, logical, cores_per, sockets = None, 0, None, set()
    for line in text.splitlines():
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key == "model name" and model is None:
            model = _clean(value)
        elif key == "processor":
            logical += 1
        elif key == "cpu cores" and cores_per is None and value.isdigit():
            cores_per = int(value)
        elif key == "physical id":
            sockets.add(value)
    top = _read(Path(sys_root) / "devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", 32)
    max_mhz = int(top.strip()) // 1000 if top and top.strip().isdigit() else None
    cores = cores_per * max(1, len(sockets)) if cores_per else None
    return {"model": model, "logical_cpus": logical or None, "physical_cores": cores, "max_mhz": max_mhz}


def board_info(*, sys_root="/sys"):
    base = Path(sys_root) / "class/dmi/id"
    names = {"board_vendor": "motherboard_vendor", "board_name": "motherboard", "bios_vendor": "bios_vendor",
             "bios_version": "bios_version", "bios_date": "bios_date", "sys_vendor": "system_vendor",
             "product_name": "product"}
    return {out: _clean(_read(base / key, 128)) for key, out in names.items()}      # never *_serial, product_uuid


def memory_info(*, proc="/proc"):
    total = None
    for line in (_read(Path(proc) / "meminfo") or "").splitlines():
        parts = line.replace(":", " ").split()
        if parts[:1] == ["MemTotal"] and len(parts) >= 2 and parts[1].isdigit():
            total = int(parts[1]) * 1024
    return {"total_bytes": total, "total_gib": round(total / 2**30, 1) if total else None,
            "modules": None, "speed_mhz": None,
            "note": "DIMM count, slot layout and speed need administrator access and are not read."}


def gpu_info(run=real_run, *, sys_root="/sys"):
    code, out = run(["lspci", "-mm"])
    gpus = []
    if code == 0:
        for line in out.splitlines():
            try:
                parts = __import__("shlex").split(line)
            except ValueError:
                continue
            # slot, class, vendor, device, ...
            if len(parts) >= 4 and re.search(r"VGA|3D|Display", parts[1], re.I):
                gpus.append({"vendor": _clean(parts[2]), "device": _clean(parts[3])})
    drivers = []
    for card in sorted(Path(sys_root).glob("class/drm/card[0-9]/device/driver"))[:MAX_DEVICES]:
        try:
            drivers.append(card.resolve().name)
        except OSError:
            continue
    return {"adapters": gpus[:MAX_DEVICES], "drivers": sorted(set(drivers))[:MAX_DEVICES],
            "vram": None, "note": "Video memory size is not read."}


def drive_info(run=real_run):
    code, out = run(["lsblk", "-J", "-b", "-o", "NAME,MODEL,SIZE,ROTA,TRAN,TYPE,FSTYPE,MOUNTPOINTS"])
    if code != 0:
        return {"drives": None, "note": "lsblk unavailable"}
    try:
        tree = json.loads(out).get("blockdevices", [])
    except (ValueError, AttributeError):
        return {"drives": None, "note": "lsblk output not understood"}
    drives = []
    for dev in tree:
        if not isinstance(dev, dict) or dev.get("type") != "disk" or str(dev.get("name", "")).startswith(("zram", "loop", "ram")):
            continue
        size = dev.get("size")
        parts = []
        for child in dev.get("children") or []:
            mounts = [m for m in (child.get("mountpoints") or []) if m in _SYSTEM_MOUNTS]
            parts.append({"size_bytes": int(child["size"]) if str(child.get("size", "")).isdigit() else None,
                          "filesystem": _clean(child.get("fstype"), 24), "system_mounts": mounts})
        rota = dev.get("rota")
        kind = "nvme" if dev.get("tran") == "nvme" or str(dev.get("name", "")).startswith("nvme") \
            else ("hdd" if rota in (True, 1, "1") else "ssd")
        drives.append({"model": _clean(dev.get("model")), "size_bytes": int(size) if str(size).isdigit() else None,
                       "size_gib": round(int(size) / 2**30, 1) if str(size).isdigit() else None, "kind": kind,
                       "bus": _clean(dev.get("tran"), 16), "partitions": parts[:MAX_DEVICES]})
    return {"drives": drives[:MAX_DEVICES]}


def software_info(run=real_run):
    code, out = run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${db:Status-Abbrev}\n"])
    if code != 0:
        return {"apt_packages": None, "note": "dpkg unavailable"}
    installed = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[2].strip().startswith("ii"):
            installed[parts[0]] = parts[1]
    code, manual_out = run(["apt-mark", "showmanual"])
    manual = sorted(n for n in manual_out.split() if n in installed) if code == 0 else []
    listed = manual[:MAX_PACKAGES]
    return {"apt_package_count": len(installed), "apt_manual_count": len(manual) if code == 0 else None,
            "apt_manual": [{"name": n, "version": installed[n]} for n in listed],
            "apt_manual_truncated": len(manual) > MAX_PACKAGES,
            "note": "Ubuntu packages only (first %d manually installed shown; use commander_software_search to check one by name); snap and flatpak apps are not listed." % MAX_PACKAGES}


def snapshot(run=real_run, *, proc="/proc", sys_root="/sys", os_release="/etc/os-release"):
    """The full inventory. Each section fails on its own (None/unavailable), never the whole call."""
    sections = {"os": lambda: os_info(os_release=os_release, proc=proc), "cpu": lambda: cpu_info(proc=proc, sys_root=sys_root),
                "motherboard": lambda: board_info(sys_root=sys_root), "memory": lambda: memory_info(proc=proc),
                "gpu": lambda: gpu_info(run, sys_root=sys_root), "storage": lambda: drive_info(run),
                "software": lambda: software_info(run)}
    out = {}
    for name, read in sections.items():
        try:
            out[name] = read()
        except Exception:
            out[name] = {"unavailable": True}
    return out
