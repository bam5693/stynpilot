"""The upgrade worker: ONE self-contained script (standard library only) that installs a verified StyNpilot package,
checks that StyNpilot still works, and puts the previous version back by itself if it does not.

The root installer copies this file into a private job folder and starts it as its own systemd unit, so it keeps
running while the installer and the owner service (both replaced by the upgrade) restart. It trusts nothing but
``job.json`` in that folder, which only the root installer wrote after an owner-approved, signature-checked plan.

  1. confirm the two package files still match the hashes the installer recorded, and the installed version is the
     one the plan started from (otherwise nothing is touched);
  2. ``dpkg -i`` the new package (settings and state live outside the package and are never touched);
  3. restart the services that were running, then wait until the installer answers, the owner service stays up,
     StyNpilot's own doctor reports no problems and the configuration files are byte-for-byte unchanged;
  4. on ANY failure: install the saved previous package, restart, check again. If even that fails the result says
     plainly that the owner must look (and the exact manual command is in the job folder's README).

The outcome is written atomically to ``result.json``; progress to ``state.json``. Never prints secrets.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import time

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive"}


def sh(argv, timeout=120, env=None):
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env or ENV, check=False,
                              stdin=subprocess.DEVNULL)
        return done.returncode, (done.stdout + done.stderr)[-4000:]
    except (OSError, subprocess.TimeoutExpired) as error:
        return 127, type(error).__name__


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, data):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, json.dumps(data, sort_keys=True).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def socket_answers(path, timeout=5):
    """The installer's own door answers a harmless status question. Proves the NEW installer is up."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(path)
            conn.sendall(json.dumps({"op": "status", "request_id": "0" * 64}).encode() + b"\n")
            reply = json.loads(conn.recv(65536).split(b"\n", 1)[0].decode())
        return reply.get("ok") is True
    except (OSError, ValueError):
        return False


class Worker:
    def __init__(self, job, *, run=sh, answers=socket_answers, sleep=time.sleep, monotonic=time.monotonic,
                 hash_file=sha256_file):
        self.job, self.run, self.answers, self.sleep, self.monotonic, self.hash_file = job, run, answers, sleep, monotonic, hash_file
        self.dir = job["job_dir"]
        self.notes = []

    # -- plumbing ---------------------------------------------------------------------------------------
    def state(self, name):
        write_json(os.path.join(self.dir, "state.json"), {"step": name, "at": int(time.time())})

    def note(self, text):
        self.notes.append(text[:200])

    def dpkg(self, args, timeout=300):
        return self.run(["dpkg", *self.job.get("dpkg_extra", []), *args], timeout)

    def installed_version(self):
        code, out = self.run(["dpkg-query", *self.job.get("query_extra", []), "-W", "-f", "${Version}", "stynpilot"], 30)
        return out.strip() if code == 0 else None

    def systemctl(self, scope, verb, unit, timeout=90):
        base = ["systemctl"]
        if scope == "user":
            base += ["--user", "--machine=%s@.host" % self.job["owner_user"]]
        return self.run(base + [verb] + ([unit] if unit else []), timeout)

    def is_active(self, scope, unit):
        return self.systemctl(scope, "is-active", unit, 30)[1].strip() == "active"

    # -- checks -----------------------------------------------------------------------------------------
    def config_unchanged(self):
        for path, digest in sorted(self.job.get("config_hashes", {}).items()):
            try:
                if self.hash_file(path) != digest:
                    self.note("configuration file changed: " + os.path.basename(path))
                    return False
            except OSError:
                self.note("configuration file unreadable: " + os.path.basename(path))
                return False
        return True

    def doctor_ok(self):
        command = self.job.get("doctor_command")
        if not command:
            return True
        code, _ = self.run(command, 120)
        baseline = self.job.get("baseline_doctor_code", 0)
        return code == 0 or (baseline != 0 and code == baseline)        # never worse than it was before the upgrade

    def healthy(self, expected_version):
        """True only when everything below holds within ``health_wait`` seconds."""
        deadline = self.monotonic() + self.job.get("health_wait", 90)
        why = "not_checked"
        while True:
            why = None
            if self.installed_version() != expected_version:
                why = "wrong_version_installed"
            elif self.job["restart_installer"] and not (self.is_active("system", self.job["installer_unit"])
                                                        and self.answers(self.job["socket_path"])):
                why = "installer_not_answering"
            elif self.job["restart_owner"] and not self.is_active("user", self.job["owner_unit"]):
                why = "owner_service_not_running"
            if why is None:
                break
            if self.monotonic() >= deadline:
                self.note("health: " + why)
                return False
            self.sleep(3)
        if self.job["restart_owner"]:
            self.sleep(self.job.get("settle_seconds", 8))              # it must STAY up, not just start
            if not self.is_active("user", self.job["owner_unit"]):
                self.note("health: owner_service_did_not_stay_up")
                return False
        if not self.config_unchanged():
            return False
        if not self.doctor_ok():
            self.note("health: doctor_reported_problems")
            return False
        return True

    def restart_services(self):
        ok = True
        # A new package may carry changed unit files; systemd must re-read them before the restart.
        if self.job["restart_installer"]:
            self.systemctl("system", "daemon-reload", None)
        if self.job["restart_owner"]:
            self.systemctl("user", "daemon-reload", None)
        if self.job["restart_installer"]:
            code, out = self.systemctl("system", "restart", self.job["installer_unit"])
            ok = ok and code == 0
            if code != 0:
                self.note("restart installer failed")
        if self.job["restart_owner"]:
            code, out = self.systemctl("user", "restart", self.job["owner_unit"])
            ok = ok and code == 0
            if code != 0:
                self.note("restart owner service failed")
        return ok

    # -- the job ----------------------------------------------------------------------------------------
    def verify_inputs(self):
        for key in ("new", "old"):
            path, want = self.job[key + "_deb"], self.job[key + "_sha256"]
            try:
                if self.hash_file(path) != want:
                    return "%s_package_changed_on_disk" % key
            except OSError:
                return "%s_package_missing" % key
        if self.installed_version() != self.job["from_version"]:
            return "installed_version_is_not_the_planned_starting_version"
        return None

    def roll_back(self, reason):
        self.state("rolling_back")
        code, out = self.dpkg(["-i", "--force-downgrade", "--force-confold", self.job["old_deb"]])
        if code != 0:
            self.note("dpkg could not reinstall the previous package")
        self.restart_services()
        restored = self.healthy(self.job["from_version"])
        return {"ok": False, "stopped": reason, "rolled_back": restored, "changed_anything": True,
                "from_version": self.job["from_version"], "to_version": self.job["to_version"],
                "needs_owner_intervention": not restored, "notes": self.notes}

    def execute(self):
        self.state("checking_inputs")
        problem = self.verify_inputs()
        if problem:
            return {"ok": False, "stopped": problem, "changed_anything": False, "rolled_back": False,
                    "from_version": self.job["from_version"], "to_version": self.job["to_version"], "notes": self.notes}
        self.state("installing")
        code, out = self.dpkg(["-i", "--force-confold", self.job["new_deb"]])
        if code != 0:
            self.note("dpkg refused the new package")
            return self.roll_back("install_failed")
        self.state("restarting")
        if not self.restart_services():
            return self.roll_back("restart_failed")
        self.state("checking_health")
        if not self.healthy(self.job["to_version"]):
            return self.roll_back("health_check_failed")
        return {"ok": True, "installed": self.job["to_version"], "from_version": self.job["from_version"],
                "to_version": self.job["to_version"], "rolled_back": False, "changed_anything": True,
                "config_preserved": True, "notes": self.notes}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    job_dir = argv[0]
    with open(os.path.join(job_dir, "job.json")) as handle:
        job = json.load(handle)
    job["job_dir"] = job_dir
    try:
        result = Worker(job).execute()
    except Exception as error:                         # never leave without a recorded outcome
        result = {"ok": False, "stopped": "worker_crashed_%s" % type(error).__name__, "changed_anything": None,
                  "needs_owner_intervention": True, "rolled_back": False}
    write_json(os.path.join(job_dir, "result.json"), result)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
