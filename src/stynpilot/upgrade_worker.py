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
import pwd
import signal
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


def endpoint_answers(target, timeout=10):
    """The local MCP endpoint really works: a request without a token is answered 401 with a Bearer challenge.
    (An active service that serves nothing, or serves the wrong thing, fails this.)"""
    try:
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", int(target["port"]), timeout=timeout)
        conn.request("POST", "/mcp", body="{}", headers={"Host": target["host"], "Content-Type": "application/json"})
        reply = conn.getresponse()
        reply.read(4096)
        conn.close()
        return reply.status == 401 and "bearer" in (reply.getheader("WWW-Authenticate") or "").lower()
    except Exception:
        return False


_PROBE = (
    "import json,socket,sys\n"
    "try:\n"
    "    c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.settimeout(float(sys.argv[2]));c.connect(sys.argv[1])\n"
    "    c.sendall(json.dumps({'op':'status','request_id':'0'*64}).encode()+b'\\n')\n"
    "    r=json.loads(c.recv(65536).split(b'\\n',1)[0].decode())\n"
    "    sys.exit(0 if r.get('ok') is True else 1)\n"
    "except (OSError,ValueError):\n"
    "    sys.exit(1)\n")


def socket_answers(path, uid=None, gid=None, timeout=5):
    """The installer's own door answers a harmless status question. Proves the NEW installer is up.

    The installer admits ONLY the enrolled owner (kernel-checked SO_PEERCRED), and must keep doing so. So the
    worker, which runs as root, asks AS THE OWNER: a short-lived child process drops to the owner's uid/gid (no
    supplementary groups) before it connects. Nothing about the installer's permissions is widened.
    """
    if uid is None or gid is None:
        return False                               # never guess an identity; no owner identity = not proven
    try:
        done = subprocess.run([sys.executable, "-I", "-c", _PROBE, path, str(timeout)], timeout=timeout + 5, env=ENV,
                              user=int(uid), group=int(gid), extra_groups=[], capture_output=True, check=False,
                              stdin=subprocess.DEVNULL, cwd="/")
        return done.returncode == 0
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


class Worker:
    def __init__(self, job, *, run=sh, answers=socket_answers, endpoint=endpoint_answers, sleep=time.sleep, monotonic=time.monotonic,
                 hash_file=sha256_file):
        self.job, self.run, self.answers, self.sleep, self.monotonic, self.hash_file = job, run, answers, sleep, monotonic, hash_file
        self.endpoint = endpoint
        self.dir = job["job_dir"]
        self.notes = []
        self.touched = False             # True from the moment we ask dpkg to change the installed package

    # -- plumbing ---------------------------------------------------------------------------------------
    def state(self, name):
        try:
            write_json(os.path.join(self.dir, "state.json"), {"step": name, "at": int(time.time())})
        except OSError:
            pass                                          # progress notes must never stop an upgrade or a rollback

    def note(self, text):
        self.notes.append(text[:200])

    def dpkg(self, args, timeout=300):
        return self.run(["dpkg", *self.job.get("dpkg_extra", []), *args], timeout)

    def ensure_projects_folder(self):
        """The owner service may write only to ~/StyNpilot-Projects (its unit lists that one folder), and systemd binds it only
        if it exists when the service starts. So make sure it exists BEFORE the restart. Best effort: never stops an upgrade."""
        uid = self.job.get("owner_uid")
        if type(uid) is not int or not self.job.get("restart_owner"):
            return
        try:
            info = pwd.getpwuid(uid)
            path = os.path.join(info.pw_dir, "StyNpilot-Projects")
            if not os.path.lexists(path):
                os.mkdir(path, 0o700)
                os.chown(path, info.pw_uid, info.pw_gid)
                self.note("created the StyNpilot-Projects folder for the owner")
        except (OSError, KeyError):
            self.note("could not create the StyNpilot-Projects folder")

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
                                                        and self.answers(self.job["socket_path"], self.job.get("owner_uid"),
                                                                         self.job.get("owner_gid"))):
                why = "installer_not_answering"
            elif self.job["restart_owner"] and not self.is_active("user", self.job["owner_unit"]):
                why = "owner_service_not_running"
            elif self.job.get("endpoint") and self.job.get("baseline_endpoint_ok") and not self.endpoint(self.job["endpoint"]):
                why = "mcp_endpoint_not_answering"        # only gated when it answered BEFORE the upgrade
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
        """Reinstall the saved previous package. ``rolled_back`` is True ONLY when dpkg reinstalled it, the
        services restarted and the health checks passed on the old version; anything less asks for the owner."""
        self.state("rolling_back")
        self.touched = True
        installed = restarted = healthy = False
        try:
            code, out = self.dpkg(["-i", "--force-downgrade", "--force-confold", self.job["old_deb"]])
            installed = code == 0
            if not installed:
                self.note("dpkg could not reinstall the previous package")
        except Exception as error:
            self.note("rollback install error: %s" % type(error).__name__)
        try:
            restarted = bool(self.restart_services())
            healthy = bool(self.healthy(self.job["from_version"]))
        except Exception as error:
            self.note("rollback check error: %s" % type(error).__name__)
        restored = installed and restarted and healthy
        return {"ok": False, "stopped": reason, "rolled_back": restored, "changed_anything": True,
                "from_version": self.job["from_version"], "to_version": self.job["to_version"],
                "needs_owner_intervention": not restored, "notes": self.notes}

    def execute(self):
        """Run the upgrade. An unexpected error never ends the run silently: once the package may have been
        modified, a verified rollback is attempted; before that nothing was changed."""
        try:
            return self._execute()
        except Exception as error:
            reason = "unexpected_%s" % type(error).__name__
            self.note("unexpected error: %s" % type(error).__name__)
            if self.touched:
                try:
                    return self.roll_back(reason)
                except Exception:
                    pass
                return {"ok": False, "stopped": reason, "rolled_back": False, "changed_anything": True,
                        "needs_owner_intervention": True, "from_version": self.job.get("from_version"),
                        "to_version": self.job.get("to_version"), "notes": self.notes}
            return {"ok": False, "stopped": reason, "rolled_back": False, "changed_anything": False,
                    "from_version": self.job.get("from_version"), "to_version": self.job.get("to_version"),
                    "notes": self.notes}

    def _execute(self):
        self.state("checking_inputs")
        problem = self.verify_inputs()
        if problem:
            return {"ok": False, "stopped": problem, "changed_anything": False, "rolled_back": False,
                    "from_version": self.job["from_version"], "to_version": self.job["to_version"], "notes": self.notes}
        self.state("installing")
        self.touched = True                                   # from here on a failure must be rolled back
        code, out = self.dpkg(["-i", "--force-confold", self.job["new_deb"]])
        if code != 0:
            self.note("dpkg refused the new package")
            return self.roll_back("install_failed")
        self.state("restarting")
        self.ensure_projects_folder()
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

    def stopped(signum, frame):                       # a stop request mid-upgrade becomes a verified rollback
        raise RuntimeError("stopped_by_signal_%d" % signum)
    signal.signal(signal.SIGTERM, stopped)
    try:
        result = Worker(job).execute()
    except Exception as error:                         # never leave without a recorded outcome
        result = {"ok": False, "stopped": "worker_crashed_%s" % type(error).__name__, "changed_anything": None,
                  "needs_owner_intervention": True, "rolled_back": False}
    write_json(os.path.join(job_dir, "result.json"), result)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
