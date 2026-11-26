"""Read-only evidence for the fixed, owner-managed Ollama pilot service.

No caller-selected unit, path, command, environment key, or endpoint.
Only bounded numeric/boolean evidence leaves this module. This is a
point-in-time resource check, not a proof of recovery exclusion or egress.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

UNIT = "stynpilot-local-ollama.service"
GIB = 1024 ** 3
MAX_HIGH = 7 * GIB
MAX_MEMORY = 9 * GIB
MAX_TASKS = 128
MAX_CPU = 4
ENV_REQUIRED = {
    b"OLLAMA_HOST": b"127.0.0.1:11435",
    b"OLLAMA_NO_CLOUD": b"1",
    b"OLLAMA_NUM_PARALLEL": b"1",
    b"OLLAMA_MAX_LOADED_MODELS": b"1",
    b"OLLAMA_MAX_QUEUE": b"1",
    b"OLLAMA_CONTEXT_LENGTH": b"4096",
}
SHOW = ("/usr/bin/systemctl", "--user", "show", "--no-pager",
        "--property=ActiveState,MainPID,ControlGroup,KillMode", UNIT)
LISTEN = ("/usr/bin/ss", "-H", "-ltnp", "sport", "=", ":11435")


def read_bounded(path, limit=65536):
    with open(path, "rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise ValueError("oversize")
    return data


def command(argv):
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, timeout=5, check=True)
    if len(p.stdout) > 16384:
        raise ValueError("oversize")
    return p.stdout.decode("utf-8")


def number(raw):
    if not re.fullmatch(rb"[0-9]{1,20}", raw.strip()):
        raise ValueError("unbounded or invalid control")
    return int(raw)


def evaluate_limits(values):
    high = number(values["memory.high"])
    memory = number(values["memory.max"])
    swap = number(values["memory.swap.max"])
    tasks = number(values["pids.max"])
    quota, period = map(number, values["cpu.max"].split())
    current = number(values["memory.current"])
    if not period:
        raise ValueError("invalid CPU period")
    checks = {
        "memory_high": 0 < high <= min(MAX_HIGH, memory),
        "memory_max": 0 < memory <= MAX_MEMORY,
        "swap_disabled": swap == 0,
        "cpu_quota": 0 < quota <= MAX_CPU * period,
        "tasks_max": 0 < tasks <= MAX_TASKS,
    }
    return checks, {"memory_high_bytes": high, "memory_max_bytes": memory,
                    "memory_swap_max_bytes": swap, "memory_current_bytes": current,
                    "cpu_quota_us": quota, "cpu_period_us": period,
                    "tasks_max": tasks}


def inspect(*, run=command, read=read_bounded, uid=None):
    """Fail closed if any mandatory observation is missing or inconsistent."""
    uid = os.getuid() if uid is None else uid
    report = {"unit": UNIT, "resource_checks_passed": False, "checks": {},
              "limits": {}, "error": None}
    checks = report["checks"]
    try:
        if uid <= 0:
            raise ValueError("unprivileged owner required")
        info = dict(line.split("=", 1) for line in run(SHOW).splitlines())
        if info.get("ActiveState") != "active" or info.get("KillMode") != "control-group":
            raise ValueError("inactive or unsafe unit")
        pid = number(info["MainPID"].encode())
        if pid <= 1 or pid > 2**31-1:
            raise ValueError("invalid pid")
        cgroup = info["ControlGroup"]
        prefix = f"/user.slice/user-{uid}.slice/user@{uid}.service/"
        if (not cgroup.startswith(prefix) or cgroup.split("/")[-1] != UNIT
                or any(part in ("", ".", "..") for part in cgroup[1:].split("/"))
                or not re.fullmatch(r"/[A-Za-z0-9_@.\-/]+", cgroup)):
            raise ValueError("unexpected service cgroup")
        proc = Path("/proc") / str(pid)
        if read(proc / "comm", 128).strip() != b"ollama":
            raise ValueError("unexpected process")
        status = read(proc / "status").splitlines()
        uids = [line.split()[1:] for line in status if line.startswith(b"Uid:")]
        if len(uids) != 1 or uids[0] != [str(uid).encode()] * 4:
            raise ValueError("unexpected service identity")
        if read(proc / "cgroup", 4096).strip() != ("0::" + cgroup).encode():
            raise ValueError("process not in service cgroup")
        checks["service_identity"] = True
        root = Path("/sys/fs/cgroup" + cgroup)
        names = ("memory.high", "memory.max", "memory.swap.max",
                 "pids.max", "cpu.max", "memory.current")
        limits, observed = evaluate_limits({name: read(root / name, 128) for name in names})
        checks.update(limits)
        report["limits"] = observed
        # Inspect only these fixed environment settings, never return raw environment.
        # Duplicate keys are refused rather than choosing one.
        env = read(proc / "environ")
        for key, expected in ENV_REQUIRED.items():
            entries = [item[len(key)+1:] for item in env.split(b"\0") if item.startswith(key+b"=")]
            checks[key.decode().lower()] = entries == [expected]
        lines = run(LISTEN).splitlines()
        fields = lines[0].split() if len(lines) == 1 else []
        checks["loopback_listener"] = (
            len(fields) >= 6 and fields[0] == "LISTEN"
            and fields[3] == "127.0.0.1:11435"
            and re.search(r"\bpid=" + str(pid) + r"\b", lines[0]) is not None)
        # Re-read identity after sampling to reject a restart during observation.
        checks["stable_unit"] = dict(line.split("=", 1) for line in run(SHOW).splitlines()) == info
        report["resource_checks_passed"] = all(checks.values())
        if not report["resource_checks_passed"]:
            report["error"] = "local_ai_containment_required"
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, UnicodeError):
        report["error"] = "local_ai_containment_unverified"
    return report
