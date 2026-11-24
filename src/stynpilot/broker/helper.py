"""How the root installer reaches the owner's home folder: never directly. It asks the projects helper (projects_helper.py),
which runs as the OWNER with no capabilities, so a path race can only ever touch what the owner already owns.

``SystemdHelper`` is production (a transient unit as the owner, read-only system, writes only to the projects folder, no network).
``LocalHelper`` is the test double that does the same uid drop with setpriv, so tests exercise a REAL privilege boundary.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

HELPER = str(Path(__file__).resolve().parent.parent / "projects_helper.py")
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


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

    def call(self, request):
        writable = request.get("home") if request.get("op") == "prepare" else request.get("projects")
        cmd = ["systemd-run", "--pipe", "--wait", "--collect", "--quiet", "-p", "User=" + self.owner_user, "-p", "ProtectSystem=strict",
               "-p", "PrivateNetwork=yes", "-p", "PrivateTmp=yes", "-p", "NoNewPrivileges=yes", "-p", "CapabilityBoundingSet=",
               "-p", "ProtectKernelModules=yes", "-p", "RestrictAddressFamilies=AF_UNIX", "-p", "TimeoutStopSec=5"]
        if writable:
            cmd += ["-p", "ReadWritePaths=" + str(writable)]
        cmd += ["--", self.python, "-I", HELPER, json.dumps(request)]
        try:
            done = subprocess.run(cmd, capture_output=True, timeout=300, env=_ENV, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise HelperError("projects_helper_failed") from None
        return _parse(done)


class LocalHelper:
    """Root sandbox only: the same helper, really running as the owner uid with no capabilities."""
    def __init__(self, owner_uid, owner_gid=None, python=None):
        self.owner_uid, self.owner_gid, self.python = owner_uid, owner_gid, python or sys.executable

    def call(self, request):
        gid = self.owner_gid if self.owner_gid is not None else self.owner_uid
        cmd = ["setpriv", "--reuid=%d" % self.owner_uid, "--regid=%d" % gid, "--clear-groups", "--no-new-privs", "--bounding-set=-all",
               "--inh-caps=-all", "--", self.python, "-I", HELPER, json.dumps(request)]
        try:
            done = subprocess.run(cmd, capture_output=True, timeout=300, env=dict(_ENV), check=False, cwd="/")
        except (OSError, subprocess.TimeoutExpired):
            raise HelperError("projects_helper_failed") from None
        return _parse(done)
