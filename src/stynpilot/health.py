"""Read-only machine health: CPU, memory, disk, temperature, uptime (GREEN).

Standard library only. Reads /proc, /sys and statvfs. Runs no commands and
returns no host name, user, file name, environment or log text. Values are
None when the machine does not expose them.

Ported from the GitLab prototype (src/stynpilot_system_status.py). The systemd
unit and hostname fields were dropped: the AI-facing health tool never returned them.
"""
from __future__ import annotations

import os
from pathlib import Path

# Bounds a value must fall inside before it is reported (anything else is dropped).
METRIC_BOUNDS = {
    "cpu_temperature_c": (0.0, 150.0),
    "cpu_usage_percent": (0.0, 100.0),
    "uptime_hours": (0.0, 1_000_000.0),
    "memory_used_percent": (0.0, 100.0),
    "disk_used_percent": (0.0, 100.0),
}


def _read(path, limit=65536):
    try:
        with open(path, "rb") as handle:
            return handle.read(limit).decode("ascii", "replace")
    except OSError:
        return None


def memory_used_percent(proc="/proc"):
    text = _read(Path(proc) / "meminfo")
    if text is None:
        return None
    values = {}
    for line in text.splitlines():
        parts = line.replace(":", " ").split()
        if len(parts) >= 2 and parts[1].isdigit():
            values[parts[0]] = int(parts[1])
    total, available = values.get("MemTotal"), values.get("MemAvailable")
    if not total or available is None:
        return None
    return round(100 * max(0, total - available) / total, 1)


def temperature_c(sys_root="/sys"):
    """Highest plausible CPU/SoC temperature (thermal zones, hwmon such as k10temp)."""
    root, found = Path(sys_root), []
    for pattern in ("class/thermal/thermal_zone*/temp", "class/hwmon/hwmon*/temp*_input"):
        for path in sorted(root.glob(pattern))[:32]:
            try:
                value = int((_read(path, 32) or "").strip()) / 1000.0
            except ValueError:
                continue
            if -40.0 < value < 150.0:
                found.append(value)
    return round(max(found), 1) if found else None


def disk_used_percent(paths=("/",), statvfs=os.statvfs):
    """Fullest of the given mount points."""
    worst = None
    for path in paths:
        try:
            info = statvfs(path)
        except OSError:
            continue
        total, free = info.f_blocks * info.f_frsize, info.f_bavail * info.f_frsize
        if total > 0:
            used = round(100 * (total - free) / total, 1)
            worst = used if worst is None else max(worst, used)
    return worst


def cpu_usage_percent(getloadavg=os.getloadavg, cpu_count=os.cpu_count):
    """One-minute load divided by core count, as a rough percentage."""
    try:
        load1 = getloadavg()[0]
    except (OSError, IndexError):
        return None
    return round(min(100.0, 100 * load1 / (cpu_count() or 1)), 1)


def uptime_hours(proc="/proc"):
    text = _read(Path(proc) / "uptime", 64)
    try:
        return float(text.split()[0]) / 3600 if text else None
    except (ValueError, IndexError):
        return None


def snapshot(*, proc="/proc", sys_root="/sys", storage_paths=("/",), statvfs=os.statvfs,
             getloadavg=os.getloadavg, cpu_count=os.cpu_count):
    """The five health metrics, each within METRIC_BOUNDS or left out."""
    raw = {
        "cpu_temperature_c": temperature_c(sys_root),
        "cpu_usage_percent": cpu_usage_percent(getloadavg, cpu_count),
        "uptime_hours": uptime_hours(proc),
        "memory_used_percent": memory_used_percent(proc),
        "disk_used_percent": disk_used_percent(storage_paths, statvfs),
    }
    return {key: float(value) for key, value in raw.items()
            if type(value) in (int, float) and METRIC_BOUNDS[key][0] <= value <= METRIC_BOUNDS[key][1]}
