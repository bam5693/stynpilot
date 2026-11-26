"""Fixed Ollama quiescence checks for an explicitly approved settlement.

The enrolled owner is trusted; direct manual service restarts are outside this
protocol. No AI-selected command, unit, path, UID or service name is accepted.
This module never starts the service. Call under exclusive restore admission.
"""
from __future__ import annotations

import os
import pwd
import re
import subprocess
import time
from pathlib import Path

from .local_ai_readiness import UNIT, LISTEN, read_bounded
from .managed_activity import ActivityError


def service_cgroup(uid):
    if type(uid) is not int or uid <= 0:
        raise ActivityError("inference_owner_invalid")
    return Path(f"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/app.slice/{UNIT}")


def owner_command(uid, operation):
    """Run a fixed systemctl operation AS the enrolled unprivileged owner."""
    account = pwd.getpwuid(uid)
    if uid <= 0 or account.pw_uid != uid or operation not in ("show", "stop"):
        raise ActivityError("inference_owner_invalid")
    argv = ["/usr/bin/systemctl", "--user", operation]
    if operation == "show":
        argv += ["--no-pager", "--property=LoadState,ActiveState,MainPID,ControlGroup"]
    argv.append(UNIT)
    result = subprocess.run(
        argv, user=uid, group=account.pw_gid, extra_groups=[], cwd="/",
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
             "XDG_RUNTIME_DIR": f"/run/user/{uid}",
             "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{uid}/bus"},
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=5 if operation == "show" else 30, check=True)
    if len(result.stdout) > 16384:
        raise ActivityError("inference_unit_evidence_invalid")
    return result.stdout.decode("utf-8")


def listeners():
    result = subprocess.run(LISTEN, cwd="/", env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=5, check=True)
    return result.stdout


def empty_group(group, *, read=read_bounded):
    try:
        info = read(group / "cgroup.events", 1024)
    except FileNotFoundError:
        # Missing group is acceptable only if the group itself is gone;
        # a missing control in a still-present group is not evidence.
        return not os.path.lexists(group)
    try:
        fields = dict(line.split() for line in info.decode("ascii").splitlines())
    except (ValueError, UnicodeError):
        return False
    return fields.get("populated") == "0"


def unit_info(uid, command):
    rows = command(uid, "show").splitlines()
    fields = dict(row.split("=", 1) for row in rows)
    if len(rows) != len(fields) or not {"LoadState", "ActiveState", "MainPID", "ControlGroup"} <= fields.keys():
        raise ActivityError("inference_unit_evidence_invalid")
    if fields["LoadState"] not in ("loaded", "not-found"):
        raise ActivityError("inference_unit_evidence_invalid")
    expected = str(service_cgroup(uid)).removeprefix("/sys/fs/cgroup")
    if fields["ControlGroup"] not in ("", expected):
        raise ActivityError("inference_unit_cgroup_mismatch")
    if fields["ActiveState"] == "active" and fields["ControlGroup"] != expected:
        raise ActivityError("inference_unit_cgroup_mismatch")
    return fields


def inactive(info):
    return info["ActiveState"] in ("inactive", "failed") and info["MainPID"] == "0"


def stop_and_verify(uid, *, command=owner_command, scan=listeners, empty=empty_group):
    """Stop only the fixed user unit, then verify its actual cgroup is empty.

    Must be invoked ONLY after the exact claim's independent approval is
    spent. A refused/uncertain check must retain the claim. A stopped service
    is not automatically restarted, even when clearing a failed claim.
    """
    group = service_cgroup(uid)
    try:
        before = unit_info(uid, command)
        if not inactive(before):
            command(uid, "stop")
        first = unit_info(uid, command)
        if not inactive(first) or not empty(group) or scan():
            raise ActivityError("inference_quiescence_unverified")
        second = unit_info(uid, command)
        if first != second or not empty(group) or scan():
            raise ActivityError("inference_quiescence_unverified")
    except ActivityError:
        raise
    except (OSError, KeyError, ValueError, subprocess.SubprocessError, UnicodeError):
        raise ActivityError("inference_quiescence_unverified") from None


def verify_idle(uid, *, command=owner_command, scan=listeners, read=read_bounded,
                clock=time.monotonic, sleep=time.sleep):
    """Bounded residual-service observation after a successful managed request.

    This is not a proof against direct manual traffic from the trusted owner.
    Keep the claim if the model worker, subgroup or more than 1 GiB of memory
    remains, or if evidence is ambiguous. Never stop a service here.
    """
    group = service_cgroup(uid)
    deadline = clock() + 10
    def sample():
        info = unit_info(uid, command)
        if inactive(info):
            return (info, "stopped") if empty_group(group, read=read) and not scan() else None
        if info["ActiveState"] != "active" or not re.fullmatch(r"[1-9][0-9]{0,9}", info["MainPID"]):
            return None
        pid = info["MainPID"]
        if pid == "1":
            return None
        # The service must be the sole listener and have no model child process
        # or descendant cgroup. memory.current is deliberately conservative.
        raw = scan()
        lines = raw.decode("utf-8").splitlines()
        if len(lines) != 1:
            return None
        fields = lines[0].split()
        if len(fields) < 6 or fields[0] != "LISTEN" or fields[3] != "127.0.0.1:11435":
            return None
        if re.findall(r"\bpid=([0-9]+)\b", lines[0]) != [pid]:
            return None
        if read(group / "cgroup.procs", 4096).split() != [pid.encode()]:
            return None
        stats = dict(line.split() for line in read(group / "cgroup.stat", 4096).decode("ascii").splitlines())
        if stats.get("nr_descendants") != "0" or stats.get("nr_dying_descendants") != "0":
            return None
        if int(read(group / "memory.current", 128)) > 1024**3 or int(read(group / "memory.swap.current", 128)) != 0:
            return None
        return (info, "idle")
    try:
        while True:
            a = sample()
            if a is not None and sample() == a:
                return
            if clock() >= deadline:
                break
            sleep(0.25)
    except ActivityError:
        raise
    except (OSError, KeyError, ValueError, subprocess.SubprocessError, UnicodeError):
        pass
    raise ActivityError("inference_quiescence_unverified")
