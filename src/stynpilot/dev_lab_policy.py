"""Restricted development lab discovery and scenario vocabulary.

This first stage never launches QEMU, executes cached/candidate code, downloads
packages, or treats cache presence as trust. Owner-side inspection is fixed to
the existing lab's default location. No caller-selected paths are accepted.
"""
from __future__ import annotations

import fcntl
import os
import re
import stat
from pathlib import Path
from types import MappingProxyType

GIB = 1 << 30
MIN_RAM = 6 * GIB
MIN_DISK = 22 * GIB
SCENARIOS = MappingProxyType({
    "offline_normal": ("offline", "normal", None),
    "offline_release_sandbox": ("offline", "sandbox", None),
    "static_checks": ("offline", "check", None),
    "reproducible_build": ("build", "double_build", None),
    "guest_boot_smoke": ("guest", "smoke", "STYNPILOT_GUEST_BOOT_OK"),
    "guest_restore": ("guest", "restore", "STYNPILOT_APPROVED_RESTORE_OK"),
    "guest_restore_faults": ("guest", "fault-cases", "STYNPILOT_RESTORE_FAULT_CASES_OK"),
    "guest_power_recovery": ("guest", "power-case", "STYNPILOT_POWER_RECOVERY_OK"),
})
SHA = re.compile(r"[0-9a-f]{40}\Z")
CACHE_FILES = MappingProxyType({
    "emulator": "cache/qemu/usr/bin/qemu-system-x86_64",
    "image_tool": "cache/qemu/usr/bin/qemu-img",
    "firmware": "cache/qemu/usr/share/ovmf/OVMF.fd",
    "base_image": "cache/ubuntu-resolute/ubuntu-26.04-server-cloudimg-amd64.img",
    "image_manifest": "cache/ubuntu-resolute/SHA256SUMS",
    "image_signature": "cache/ubuntu-resolute/SHA256SUMS.gpg",
})


class LabError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def scenario_request(commit, scenario):
    """Pure validation only. A valid request is NOT an authorization to launch."""
    if type(commit) is not str or not SHA.fullmatch(commit):
        raise LabError("lab_exact_commit_required")
    if type(scenario) is not str or scenario not in SCENARIOS:
        raise LabError("lab_scenario_invalid")
    return {"commit": commit, "scenario": scenario}


def _child(base, relative, uid, *, directory=False):
    """Metadata only; reject symlink components and foreign/writable entries.

    Not a launch-time secure opener: a later execution stage must pin/verify
    all artifacts independently and run only trusted installed launchers.
    """
    path = base
    try:
        for index, part in enumerate(Path(relative).parts):
            path = path / part
            info = os.lstat(path)
            final = index == len(Path(relative).parts) - 1
            if info.st_uid != uid or info.st_mode & 0o022:
                return False
            if (not final or directory):
                if not stat.S_ISDIR(info.st_mode):
                    return False
            elif not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
                return False
        return True
    except OSError:
        return False


def _kvm():
    try:
        fd = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            return stat.S_ISCHR(os.fstat(fd).st_mode) and fcntl.ioctl(fd, 0xAE00, 0) == 12
        finally:
            os.close(fd)
    except OSError:
        return False


def _available_memory():
    try:
        with open("/proc/meminfo", "rb") as stream:
            raw = stream.read(16385)
        if len(raw) > 16384:
            return None
        rows = [line.split() for line in raw.splitlines() if line.startswith(b"MemAvailable:")]
        if len(rows) != 1 or len(rows[0]) != 3 or rows[0][2] != b"kB":
            return None
        return int(rows[0][1]) * 1024
    except (OSError, ValueError):
        return None


def _disk(path):
    try:
        info = os.statvfs(path)
        return info.f_bavail * info.f_frsize
    except OSError:
        return None


def inspect(*, home=None, uid=None, kvm=_kvm, memory=_available_memory, disk=_disk):
    uid = os.geteuid() if uid is None else uid
    home = Path.home() if home is None else Path(home)
    root = home / ".local/share/stynpilot-dev"
    # Metadata observations only. Never expose home, paths or raw files.
    layout = uid > 0 and _child(home, ".local/share/stynpilot-dev", uid, directory=True)
    work = layout and _child(root, "work", uid, directory=True)
    cached = {name: bool(layout and _child(root, relative, uid)) for name, relative in CACHE_FILES.items()}
    free = disk(root / "work") if work else None
    available = memory()
    checks = {
        "owner_lab_present": bool(layout),
        "work_directory_present": bool(work),
        "kvm_access": uid > 0 and kvm() is True,
        "memory_headroom": type(available) is int and available >= MIN_RAM,
        "disk_headroom": type(free) is int and free >= MIN_DISK,
        "guest_cache_present": all(cached.values()),
    }
    return {"checks": checks, "cache_files_present": cached,
            "minimum_ram_bytes": MIN_RAM, "minimum_disk_bytes": MIN_DISK,
            "planned_scenarios": list(SCENARIOS),
            "preflight_checks_passed": all(checks.values()),
            "cache_integrity_verified": False,
            "launch_enabled": False,
            "reason": "lab_execution_not_enrolled_or_implemented"}
