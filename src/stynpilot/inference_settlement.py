"""Fixed Ollama quiescence checks for an explicitly approved settlement.

The enrolled owner is trusted; direct manual service restarts are outside this
protocol. No AI-selected command, unit, path, UID or service name is accepted.
This module never starts the service. Call under exclusive restore admission.
"""
from __future__ import annotations

import os
import pwd
import subprocess
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
        stderr=subprocess.DEVNULL, timeout=30, check=True)
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
