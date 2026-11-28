"""How the root installer reaches the owner's home folder: never directly. It asks the projects helper (projects_helper.py),
which runs as the OWNER with no capabilities, so a path race can only ever touch what the owner already owns.

``SystemdHelper`` is production (a transient unit as the owner, read-only system, writes only to the projects folder, no network).
``LocalHelper`` is the test double that does the same uid drop with setpriv, so tests exercise a REAL privilege boundary.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

from .. import managed_activity

HELPER = str(Path(__file__).resolve().parent.parent / "projects_helper.py")
DEFAULT_TIMEOUT = 120          # walks over big workspaces; the measurement the disk watchdog uses asks for much less
MEASURE_TIMEOUT = 4
SLACK = 1               # seconds the client waits past the unit's own deadline before it stops the unit itself
STOP_WAIT = 2           # seconds the cleanup (systemctl kill) may take; it can fail or time out without ever escaping the helper
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def checkout_unit(job):
    if type(job) is not str or not managed_activity.ID.fullmatch(job):
        raise HelperError("deckplay_checkout_dispatch_invalid")
    return "stynpilot-deckplay-checkout-" + job + ".service"


class HelperError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _parse(done):
    try:
        data = json.loads(done.stdout.decode().strip().splitlines()[-1])
    except (ValueError, IndexError, UnicodeDecodeError):
        raise HelperError("projects_helper_failed") from None
    if type(data) is not dict or data.get("ok") is not True:
        raise HelperError(str(data.get("error", "projects_helper_failed")) if type(data) is dict else "projects_helper_failed")
    return data


class SystemdHelper:
    def __init__(self, owner_user, python="/usr/bin/python3"):
        self.owner_user, self.python = owner_user, python

    def call(self, request, timeout=DEFAULT_TIMEOUT, *, data=None):
        """One owner-side operation with a HARD deadline: systemd itself ends the unit at ``timeout`` (RuntimeMaxSec), and if the
        client is still hanging a little later the unit is stopped by name and the call fails. A slow measurement is a failed one."""
        operation = request.get("op")
        writable = (request.get("home") if operation == "prepare" else request.get("projects")) if operation != "deckplay_snapshot_preview" else None
        dispatch = request.get("dispatch") if operation == "deckplay_snapshot_checkout" else None
        unit = checkout_unit(request.get("checkout_job")).removesuffix(".service") if dispatch else "stynpilot-projects-helper-" + secrets.token_hex(8)
        cmd = ["systemd-run", "--pipe", "--wait", "--collect", "--quiet", "--unit", unit, "-p", "RuntimeMaxSec=%d" % max(1, int(timeout)),
               "-p", "User=" + self.owner_user, "-p", "ProtectSystem=strict",
               "-p", "PrivateNetwork=yes", "-p", "PrivateTmp=yes", "-p", "NoNewPrivileges=yes", "-p", "CapabilityBoundingSet=",
               "-p", "ProtectKernelModules=yes", "-p", "RestrictAddressFamilies=AF_UNIX", "-p", "TimeoutStopSec=5"]
        if writable:
            cmd += ["-p", "ReadWritePaths=" + str(writable)]
        if dispatch:
            cmd += ["-p", "Slice=system.slice", "-p", "ExitType=cgroup", "-p", "BindsTo=stynpilot-installer.service",
                    "-p", "After=stynpilot-installer.service", "-p", "BindReadOnlyPaths=" + dispatch + ":/run/stynpilot-deckplay-dispatch"]
            request = dict(request, dispatch="/run/stynpilot-deckplay-dispatch")
        if data is not None or request.get("op") in ("deckplay_snapshot_preview", "deckplay_snapshot_checkout"):
            cmd += ["-p", "MemoryMax=768M", "-p", "MemorySwapMax=0", "-p", "TasksMax=32",
                    "-p", "CPUQuota=200%", "-p", "LimitFSIZE=64M", "-p", "KillMode=control-group", "-p", "UMask=0077"]
        if operation in ("deckplay_snapshot_preview", "deckplay_snapshot_checkout"):
            cmd += ["-p", "LimitCORE=0", "-p", "TemporaryFileSystem=/tmp:rw,nosuid,nodev,noexec,size=256M,mode=1777"]
        cmd += ["--", self.python, "-IB", "-X", "pycache_prefix=/usr/lib/stynpilot/.source-only", HELPER, json.dumps(request)]
        try:
            done = subprocess.run(cmd, input=data, capture_output=True, timeout=timeout + SLACK, env=_ENV, check=False)
        except subprocess.TimeoutExpired:
            try:
                subprocess.run(["systemctl", "kill", "--signal=SIGKILL", unit + ".service"], capture_output=True, timeout=STOP_WAIT,
                               check=False, env=_ENV)
            except (subprocess.SubprocessError, OSError):
                pass            # the cleanup itself hung or failed: the unit still ends at RuntimeMaxSec; the caller must see only HelperError
            raise HelperError("projects_helper_timed_out") from None
        except OSError:
            raise HelperError("projects_helper_failed") from None
        return _parse(done)


class LocalHelper:
    """Root sandbox only: the same helper, really running as the owner uid with no capabilities."""
    def __init__(self, owner_uid, owner_gid=None, python=None):
        self.owner_uid, self.owner_gid, self.python = owner_uid, owner_gid, python or sys.executable

    def call(self, request, timeout=DEFAULT_TIMEOUT, *, data=None):
        gid = self.owner_gid if self.owner_gid is not None else self.owner_uid
        cmd = ["setpriv", "--reuid=%d" % self.owner_uid, "--regid=%d" % gid, "--clear-groups", "--no-new-privs", "--bounding-set=-all",
               "--inh-caps=-all", "--", self.python, "-I", HELPER, json.dumps(request)]
        try:
            done = subprocess.run(cmd, input=data, capture_output=True, timeout=timeout, env=dict(_ENV), check=False, cwd="/")
        except subprocess.TimeoutExpired:
            raise HelperError("projects_helper_timed_out") from None
        except OSError:
            raise HelperError("projects_helper_failed") from None
        return _parse(done)
