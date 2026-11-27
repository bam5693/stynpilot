"""Installer-side enrollment, execution and private evidence for fixed lab jobs."""
from __future__ import annotations

import json
import os
import pwd
import re
import secrets
import shutil
import subprocess
import time
from pathlib import Path

from .. import dev_lab_policy, dev_lab_source, dev_lab_worker, managed_activity, release, vault

REPOSITORY = release.REPOSITORY
PROFILE = "offline_normal"
POLICY = "offline-normal-v1"
JOB_SECONDS = 660
RETAIN = 16
CLIENT = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
CALLS = frozenset(("lab_enrollment", "lab_prepare", "lab_start", "lab_jobs", "lab_job_status", "lab_job_output", "lab_cancel"))
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
_WORKER = ("import sys;sys.pycache_prefix='/usr/lib/stynpilot/.source-only';"
           "sys.path.insert(0,'/usr/lib/stynpilot/lib');"
           "from stynpilot.dev_lab_worker import installed;raise SystemExit(installed(*sys.argv[1:]))")


class LabError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _name(job):
    if type(job) is not str or not managed_activity.ID.fullmatch(job):
        raise LabError("lab_unknown_job")
    return "stynpilot-lab-" + job + ".service"


def _control(argv, timeout):
    return subprocess.run(argv, env=_ENV, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=timeout, check=False)


class SystemdLab:
    """The root controller can start and stop only its own named transient units."""

    def __init__(self, *, control=_control, cgroups="/sys/fs/cgroup"):
        self.control, self.cgroups = control, Path(cgroups)

    def ready(self):
        return (all(os.access(path, os.X_OK) for path in
                    ("/usr/bin/bwrap", "/usr/bin/pytest", "/usr/bin/systemd-run", "/usr/bin/systemctl"))
                and (self.cgroups / "cgroup.controllers").is_file())

    def start(self, row, folder):
        name = _name(row["id"])
        try:
            pwd.getpwnam("stynpilot-lab")
        except KeyError:
            pass
        else:
            # DynamicUser may reuse a statically provisioned account with the
            # same name. The lab requires a fresh, dedicated runtime identity.
            raise LabError("lab_worker_identity_already_exists")
        props = {
            "Slice": "system.slice", "DynamicUser": "yes", "User": "stynpilot-lab",
            "ExitType": "cgroup", "KillMode": "control-group", "SendSIGKILL": "yes", "Delegate": "no",
            "TimeoutStartSec": "20s", "TimeoutStopSec": "5s", "RuntimeMaxSec": str(JOB_SECONDS),
            "CPUQuota": "200%", "MemoryMax": "2G", "MemorySwapMax": "0", "TasksMax": "64",
            "ProtectHome": "yes", "ProtectSystem": "strict", "ProtectControlGroups": "yes",
            "PrivateNetwork": "yes", "NoNewPrivileges": "yes", "UMask": "0077",
            "TemporaryFileSystem": "/tmp:rw,nosuid,nodev,noexec,size=192M,mode=1777",
            "InaccessiblePaths": "-/run/stynpilot",
            "BindReadOnlyPaths": (str(folder / "source.tar") + ":/run/stynpilot-lab-source.tar "
                                  + str(folder / "dispatch") + ":/run/stynpilot-lab-dispatch"),
            "StandardOutput": "append:" + str(folder / "result"),
            "StandardError": "journal", "LimitFSIZE": "64M", "LimitCORE": "0",
        }
        command = ["/usr/bin/systemd-run", "--quiet", "--collect", "--service-type=exec", "--unit=" + name]
        command.extend("--property=" + key + "=" + value for key, value in props.items())
        command += ["/usr/bin/python3", "-IB", "-c", _WORKER, row["commit"], row["artifact_sha256"]]
        if self.control(command, 24).returncode:
            raise LabError("lab_start_failed")

    def _properties(self, job):
        unit = _name(job)
        request = ["/usr/bin/systemctl", "show", "--all", "--no-pager",
                   "--property=LoadState,ActiveState,ControlGroup,Job", unit]
        result = self.control(request, 3)
        data = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if (result.returncode not in (0, 1)
                or data.get("LoadState") not in ("loaded", "not-found")
                or data.get("ActiveState") not in ("active", "inactive", "failed", "activating", "deactivating", "reloading")
                or data.get("ControlGroup") not in ("", "/system.slice/" + unit)
                or data.get("Job") is None):
            raise LabError("lab_quiescence_unverified")
        return data

    def idle(self, job):
        data = self._properties(job)
        if data["ActiveState"] not in ("inactive", "failed") or data["Job"] not in ("", "0"):
            return False
        if not (self.cgroups / "cgroup.controllers").is_file():
            raise LabError("lab_quiescence_unverified")
        events = self.cgroups / "system.slice" / _name(job) / "cgroup.events"
        try:
            values = dict(line.split() for line in events.read_text().splitlines())
        except FileNotFoundError:
            if events.parent.exists():
                raise LabError("lab_quiescence_unverified") from None
        else:
            if values.get("populated") != "0":
                return False
        return True

    def stop(self, job):
        if not self.idle(job):
            self.control(["/usr/bin/systemctl", "stop", _name(job)], 12)
        if not self.idle(job):
            raise LabError("lab_quiescence_unverified")


def _read(path, limit=32768):
    return json.loads(vault._read_private(path, limit))


def _write(path, value):
    vault._write_atomic(path.parent, path.name, json.dumps(value, ensure_ascii=False).encode())


class LabJobs:
    """All calls are serialized by the installer's exclusive restore admission lock."""

    def __init__(self, state, authority, *, owner, device, backend=None, clock=time.time,
                 memory=dev_lab_policy._available_memory):
        self.state = Path(state)
        self.root = vault._private_folder(self.state / "dev-lab")
        self.authority, self.owner, self.device = authority, owner, device
        self.backend, self.clock, self.memory = backend or SystemdLab(), clock, memory
        self.grants = self.root / "grants.json"

    def _scope(self, client):
        if type(client) is not str or not CLIENT.fullmatch(client):
            raise LabError("lab_client_invalid")
        return {"owner": self.owner, "device": self.device, "client": client,
                "repository": REPOSITORY, "profile": POLICY}

    def _grants(self):
        try:
            return _read(self.grants)
        except FileNotFoundError:
            return {}

    def enrollment(self, client, repository):
        scope = self._scope(client)
        if repository != REPOSITORY:
            raise LabError("lab_repository_not_supported")
        return {"enrolled": self._grants().get(client) == scope, "ready": self.backend.ready(),
                "repository": REPOSITORY, "scenario": PROFILE}

    def enroll(self, client):
        scope = self._scope(client)
        grants = self._grants()
        if client not in grants and len(grants) >= RETAIN:
            raise LabError("lab_enrollment_limit")
        grants[client] = scope
        _write(self.grants, grants)
        return {"ok": True, "action": "lab_enroll", "enabled": True}

    def _folder(self, job):
        _name(job)
        return self.root / job

    def _rows(self):
        return [_read(child / "job.json") for child in self.root.iterdir() if managed_activity.ID.fullmatch(child.name)]

    def _owned(self, client, job):
        try:
            row = _read(self._folder(job) / "job.json")
        except FileNotFoundError:
            raise LabError("lab_unknown_job") from None
        if row["scope"] != self._scope(client):
            raise LabError("lab_unknown_job")
        return row

    def _public(self, row):
        return {key: value for key, value in row.items() if key not in ("scope", "requested_stop")}

    def start(self, client, repository, commit, artifact_sha256, scenario):
        scope = self._scope(client)
        if not self.enrollment(client, repository)["enrolled"]:
            raise LabError("lab_enrollment_required")
        dev_lab_policy.scenario_request(commit, scenario)
        if scenario != PROFILE:
            raise LabError("lab_scenario_not_implemented")
        if not self.backend.ready():
            raise LabError("lab_executor_unavailable")
        self.reconcile()
        if managed_activity.held(self.state):
            raise LabError("managed_activity_busy")
        available = self.memory()
        disk = os.statvfs(self.root)
        if (available is None or available < (3 << 30) or disk.f_bavail * disk.f_frsize < (512 << 20)
                or disk.f_favail < 1024):
            raise LabError("lab_insufficient_headroom")
        started = self.clock()
        source = self.authority.lab_artifact(commit, artifact_sha256)
        if not 0 < len(source) <= dev_lab_source.MAX_ARCHIVE:
            raise LabError("lab_source_archive_invalid")
        rows = sorted(self._rows(), key=lambda row: row["started"])
        while len(rows) >= RETAIN:
            shutil.rmtree(self._folder(rows.pop(0)["id"]))
        job = secrets.token_hex(16)
        folder = self._folder(job)
        # Write the durable intent before claiming admission; interrupted pre-claim
        # staging is collected on the next reconciliation without launching it.
        vault._private_folder(folder)
        row = {"id": job, "scope": scope, "repository": repository, "commit": commit, "scenario": scenario,
               "artifact_sha256": artifact_sha256, "started": started, "deadline": started + JOB_SECONDS,
               "state": "starting", "exit_code": None}
        _write(folder / "job.json", row)
        managed_activity.claim(self.state, "dev_lab", job)
        try:
            # The private ancestor protects this inode on the host. The worker can
            # read it solely through the exact read-only service bind mount.
            vault._write_atomic(folder, "source.tar", source, mode=0o644)
            vault._write_atomic(folder, "result", b"")
            vault._write_atomic(folder, "dispatch", b"")
            self.backend.start(row, folder)
        except (OSError, LabError, subprocess.SubprocessError, vault.VaultError):
            self._request_stop(row, "start_failed")
            self.reconcile()
            raise LabError("lab_start_failed") from None
        row["state"] = "running"
        _write(folder / "job.json", row)
        return self._public(row)

    def _request_stop(self, row, reason):
        folder = self._folder(row["id"])
        (folder / "dispatch").unlink(missing_ok=True)
        vault._fsync_dir(folder)
        row["requested_stop"] = reason
        _write(folder / "job.json", row)

    def reconcile(self, *, startup=False):
        claim = managed_activity.current(self.state)
        current = claim["job_id"] if claim and claim["kind"] == "dev_lab" else None
        if current is None:
            self._prune_staging()
            return
        folder = self._folder(current)
        row = _read(folder / "job.json")
        if row["id"] != current:
            raise LabError("lab_job_record_invalid")
        if not row.get("requested_stop"):
            if startup or row["state"] == "starting" or self.clock() >= row["deadline"]:
                reason = "timeout" if self.clock() >= row["deadline"] else "interrupted"
                self._request_stop(row, reason)
            elif not self.backend.idle(current):
                return
        # Revoke even on normal completion. A delayed manager dispatch cannot
        # execute after settlement, and a surviving child keeps the claim held.
        (folder / "dispatch").unlink(missing_ok=True)
        vault._fsync_dir(folder)
        self.backend.stop(current)
        if not self.backend.idle(current):
            raise LabError("lab_quiescence_unverified")
        if row["state"] in ("starting", "running"):
            try:
                result = _read(folder / "result", 2 << 20)
            except (OSError, ValueError, vault.VaultError):
                result = {}
            valid = (isinstance(result, dict) and result.get("commit") == row["commit"]
                     and result.get("scenario") == row["scenario"]
                     and result.get("state") in ("passed", "failed", "timeout", "output_limit")
                     and type(result.get("output")) is str)
            if row.get("requested_stop") or not valid:
                row.update(state=row.get("requested_stop", "interrupted"), exit_code=None)
                vault._write_atomic(folder, "evidence", b"")
            else:
                clean, _ = dev_lab_worker.redact(result["output"])
                vault._write_atomic(folder, "evidence", clean[:dev_lab_worker.OUTPUT_LIMIT].encode())
                row.update(state=result["state"], exit_code=result.get("exit_code"))
            row["ended"] = self.clock()
            _write(folder / "job.json", row)
        for name in ("source.tar", "result"):
            (folder / name).unlink(missing_ok=True)
        vault._fsync_dir(folder)
        managed_activity.finish(self.state, "dev_lab", current)
        if startup:
            self._prune_staging()

    def _prune_staging(self):
        # Dispatch is possible only after a durable claim. Orphaned records
        # created before it can be removed, never adopted into a new job.
        for child in self.root.iterdir():
            if managed_activity.ID.fullmatch(child.name) and (
                    not (child / "job.json").exists() or _read(child / "job.json")["state"] == "starting"):
                shutil.rmtree(child)

    def jobs(self, client):
        scope = self._scope(client)
        return {"jobs": [self._public(row) for row in sorted(self._rows(), key=lambda r: r["started"], reverse=True)
                         if row["scope"] == scope]}

    def status(self, client, job):
        return self._public(self._owned(client, job))

    def output(self, client, job, offset, limit):
        row = self._owned(client, job)
        if type(offset) is not int or type(limit) is not int or offset < 0 or not 1 <= limit <= 16384:
            raise LabError("lab_output_window_invalid")
        if row["state"] in ("starting", "running"):
            return {"text": "", "next_offset": 0, "complete": False}
        text = vault._read_private(self._folder(job) / "evidence", 4 * dev_lab_worker.OUTPUT_LIMIT).decode()
        start = min(offset, len(text))
        return {"text": text[start:start + limit], "next_offset": min(start + limit, len(text)),
                "complete": start + limit >= len(text)}

    def cancel(self, client, job):
        row = self._owned(client, job)
        if row["state"] in ("starting", "running"):
            if managed_activity.current(self.state) != {"kind": "dev_lab", "job_id": job}:
                raise LabError("lab_reservation_mismatch")
            self._request_stop(row, "cancelled")
            self.reconcile()
        return self.status(client, job)
