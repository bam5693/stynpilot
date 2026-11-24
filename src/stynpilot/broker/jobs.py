"""S3b core (root side): workspaces, the runner user, and sandboxed jobs. No door/approval wiring here (S3b-2): this class
is what the installer will call AFTER it has checked who is asking and what was approved.

* ``ensure_user``   creates the locked-down ``stynpilot-run`` account (YELLOW at the door, once).
* ``enroll``        a workspace becomes usable: the run user (and the owner, for files the run user creates later) get an
                    ACL on the folder's contents. Never on links, hard-linked files (their inode may live outside),
                    credential-named files, other file systems, or anything but plain files and folders.
* ``run``           validated recipe -> transient unit as the run user; output captured (bounded) and redacted on read.
* ``status/output/cancel/reconcile``  poll, page, stop, and recover after an installer restart.

Backends: ``SystemdBackend`` is production (the hardened unit from runner.unit_command). ``LocalBackend`` runs the same
validated argv as the run user with setpriv; it exists so the privilege separation and the ACL behaviour are tested for
REAL in a root sandbox, and is never used on the owner's machine.
"""
from __future__ import annotations

import json
import os
import pwd
import secrets
import shutil
import signal
import sqlite3
import stat
import subprocess
import threading
import time
from pathlib import Path

from .. import redact, runner, safefs
from . import apt
from .helper import HelperError, LocalHelper, SystemdHelper

MAX_OUT = 256 * 1024
MAX_ENTRIES = 50000
MAX_JOBS_KEPT = 200
BATCH = 100
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


class JobError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class SystemdBackend:
    enforces_limits = True          # the self-test must SEE the limits from inside, or it fails

    def start(self, job_id, argv, workspace, limits, run_user, masked=()):
        cmd = runner.unit_command(job_id, argv, workspace, run_user=run_user, masked=masked, **limits)
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=_ENV,
                                start_new_session=True)

    def cancel(self, job_id, proc):
        subprocess.run(["systemctl", "stop", "stynpilot-job-" + job_id], capture_output=True, timeout=30, check=False, env=_ENV)
        _kill_group(proc)


class LocalBackend:
    """Root sandbox only: same argv, same fixed environment, real uid/gid drop, no systemd."""
    enforces_limits = False

    def start(self, job_id, argv, workspace, limits, run_user, masked=()):
        pw = pwd.getpwnam(run_user)
        cmd = ["setpriv", "--reuid=%d" % pw.pw_uid, "--regid=%d" % pw.pw_gid, "--clear-groups", "--no-new-privs", "--bounding-set=-all", "--inh-caps=-all", "--"] + list(argv)
        return subprocess.Popen(cmd, cwd=workspace, env=dict(runner.ENV), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True)

    def cancel(self, job_id, proc):
        _kill_group(proc)


def _kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


class JobRunner:
    def __init__(self, state_dir, *, owner_uid, home, backend=None, run=apt.real_run, run_user=runner.RUN_USER, clock=time.time,
                 max_running=2, extra_deny=(), projects_dir=None, disk_start_free=4 << 30, disk_kill_free=2 << 30, disk_poll=2.0, version="0", gate=True,
                 selftest_root="/var/lib/stynpilot-run", python="/usr/bin/python3", helper=None):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        # projects_dir: when set, a workspace must be a DIRECT child of it (production: ~/StyNpilot-Projects).
        # gate: general jobs refuse to start until the live confinement self-test passed for THIS version.
        # A symlinked base is REFUSED (not canonicalised first), so the folder the owner approved is the folder that is used.
        self.projects_dir = os.path.abspath(projects_dir) if projects_dir else None
        self.version, self.gate, self.selftest_root, self.python = str(version), bool(gate), str(selftest_root), python
        (self.dir / "jobs").mkdir(parents=True, exist_ok=True, mode=0o700)
        self.owner_uid, self.home, self.run_user = owner_uid, os.path.abspath(home), run_user
        owner = pwd.getpwuid(owner_uid)
        self.owner_name = owner.pw_name
        self.helper = helper or (SystemdHelper(owner.pw_name) if isinstance(backend or SystemdBackend(), SystemdBackend)
                                 else LocalHelper(owner_uid, owner.pw_gid))
        self.backend, self.runcmd, self.clock, self.max_running = backend or SystemdBackend(), run, clock, max_running
        self.extra_deny = tuple(str(p) for p in extra_deny) + (str(self.dir),)
        self._lock = threading.Lock()
        self.disk_start_free, self.disk_kill_free, self.disk_poll = int(disk_start_free), int(disk_kill_free), float(disk_poll)
        self._ws_lock = threading.RLock()                 # enrol/unenrol/job start never interleave
        self._live = {}                                   # job id -> (thread, process)
        self._db = sqlite3.connect(self.dir / "jobs.sqlite3", check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.executescript("""
            create table if not exists workspaces(path text primary key, enrolled_at integer, skipped integer);
            create table if not exists jobs(id text primary key, workspace text, recipe text, argv text, state text,
                created integer, started integer, ended integer, exit_code integer, truncated integer default 0);""")

    # -- the runner user ----------------------------------------------------------------------------------
    def ensure_user(self):
        try:
            pw = pwd.getpwnam(self.run_user)
        except KeyError:
            code, out = self.runcmd(["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "--user-group",
                                     self.run_user], 60)
            if code != 0:
                raise JobError("could_not_create_the_runner_user") from None
            pw = pwd.getpwnam(self.run_user)
        if pw.pw_uid in (0, self.owner_uid) or pw.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/nologin"):
            raise JobError("runner_user_is_not_locked_down")
        return pw.pw_uid, pw.pw_gid

    # -- workspaces ---------------------------------------------------------------------------------------
    def _ask(self, op, **fields):
        request = {"op": op, "home": self.home, "projects": self.projects_dir, "run_user": self.run_user, "owner_user": self.owner_name}
        request.update(fields)
        try:
            return self.helper.call(request)
        except HelperError as error:
            raise JobError(error.code) from None

    def _acl_scratch(self, folder, spec):
        """ONLY for the self-test's own root-owned scratch folder (never anything in the owner's home)."""
        for default in (False, True):
            argv = ["setfacl"] + (["-d"] if default else []) + ["-m", spec, "--", folder]
            if self.runcmd(argv, 60)[0] != 0:
                raise JobError("could_not_set_permissions_on_the_workspace")

    def _workspace_ok(self, path):
        """The workspace path as the helper (running as the owner) sees it: a REAL folder directly inside the projects folder."""
        if self.projects_dir is None:
            return runner.check_workspace(path, home=self.home, extra_deny=self.extra_deny)
        try:
            runner.check_workspace_text(path)
        except runner.RunnerError as error:
            raise JobError(str(error)) from None
        if os.path.dirname(path) != self.projects_dir:
            raise JobError("workspace_must_be_a_folder_directly_inside_the_projects_folder")
        return self._ask("check", name=os.path.basename(path))["path"]

    def enroll(self, path):
        if not self.enabled():
            raise JobError("runner_not_set_up")
        real = self._workspace_ok(path)
        if real != path:
            raise JobError("workspace_path_is_or_contains_a_link")
        self.ensure_user()
        with self._ws_lock:
            with self._lock:
                if self._db.execute("select 1 from workspaces where path=?", (real,)).fetchone():
                    raise JobError("already_enrolled")
                for other in self._db.execute("select path from workspaces"):
                    o = other["path"]
                    if real.startswith(o + "/") or o.startswith(real + "/"):
                        raise JobError("overlaps_an_enrolled_workspace")
            if self.projects_dir is None:
                raise JobError("projects_folder_not_configured")
            done = self._ask("enroll", name=os.path.basename(real))
            with self._lock:
                self._db.execute("insert into workspaces values(?,?,?)", (real, int(self.clock()), done["skipped"]))
        return {"workspace": real, "entries": done["entries"], "skipped": done["skipped"]}

    def unenroll(self, path):
        with self._ws_lock:
            with self._lock:
                if self._db.execute("select 1 from jobs j where j.workspace=? and j.state='running'", (path,)).fetchone():
                    raise JobError("a_job_is_running_in_this_workspace")
                if not self._db.execute("select 1 from workspaces where path=?", (path,)).fetchone():
                    raise JobError("not_enrolled")
                # The row goes FIRST: from this instant no job can start here, then the access is taken away.
                self._db.execute("delete from workspaces where path=?", (path,))
            try:
                self._ask("unenroll", name=os.path.basename(path))
            except JobError as error:
                if error.code not in ("workspace_name_invalid", "path_contains_a_link", "folder_must_be_a_real_folder_owned_by_the_owner",
                                      "os_error_FileNotFoundError"):
                    raise
        return {"workspace": path, "removed": True}

    def workspaces(self):
        return [dict(r) for r in self._db.execute("select * from workspaces order by path")]

    # -- jobs ---------------------------------------------------------------------------------------------
    def run(self, workspace, recipe_id, args):
        self.require_ready()
        real = self._workspace_ok(workspace)                                                      # still the same real folder
        if real != workspace:
            raise JobError("workspace_changed")
        argv = runner.build_argv(recipe_id, args, real)
        recipe = runner.RECIPES[recipe_id]
        limits = {"seconds": recipe.seconds, "memory_mb": recipe.memory_mb, "tasks": recipe.tasks, "writes": recipe.writes}
        return self._start(real, recipe_id, argv, limits, recipe.seconds)   # masked: computed inside, at start, every time

    def _masked(self, real):
        """Credential-named files/folders and the trash, found NOW and hidden from the sandbox (not merely skipped by the ACL)."""
        names = self._ask("protected", name=os.path.basename(real))["protected"]
        out = [real + "/" + n for n in names]
        return self._safe_masked(real, out)

    @staticmethod
    def _safe_masked(real, paths):
        for m in paths:
            if not runner._PATH_CHARS.fullmatch(m) or ".." in m.split("/") or not m.startswith(real + "/"):
                raise JobError("a_protected_file_has_a_name_that_cannot_be_hidden_safely")   # fail closed: no job
        return paths

    def _free_bytes(self, real, local):
        if local:
            info = os.statvfs(real)
            return info.f_bavail * info.f_frsize
        return int(self._ask("disk", path=self.projects_dir)["free"])

    def _start(self, real, label, argv, limits, seconds, need_enrolled=True, masked=None):
        self.ensure_user()
        if masked is None:
            masked = self._masked(real) if need_enrolled else []
        if self._free_bytes(real, local=not need_enrolled) < self.disk_start_free:
            raise JobError("not_enough_free_disk_space_to_start_a_job")
        job_id = secrets.token_hex(16)
        with self._ws_lock, self._lock:
            if need_enrolled and not self._db.execute("select 1 from workspaces where path=?", (real,)).fetchone():
                raise JobError("workspace_not_enrolled")
            if len(self._live) >= self.max_running:
                raise JobError("too_many_jobs_running")
            self._db.execute("insert into jobs(id,workspace,recipe,argv,state,created) values(?,?,?,?,?,?)",
                             (job_id, real, label, json.dumps(argv), "running", int(self.clock())))
            try:
                proc = self.backend.start(job_id, argv, real, limits, self.run_user, masked=masked)
            except OSError:
                self._db.execute("update jobs set state='failed', ended=? where id=?", (int(self.clock()), job_id))
                raise JobError("could_not_start_the_job") from None
            thread = threading.Thread(target=self._pump, args=(job_id, proc, seconds, not need_enrolled), daemon=True, name="stynpilot-job")
            self._live[job_id] = (thread, proc)
            self._db.execute("update jobs set started=? where id=?", (int(self.clock()), job_id))
        thread.start()
        self._prune()
        return {"job_id": job_id, "argv": list(argv), "limits": limits}

    # -- setup and the self-test gate ---------------------------------------------------------------------
    @property
    def _enabled_file(self):
        return self.dir / "runner-enabled.json"

    @property
    def _selftest_file(self):
        return self.dir / "runner-selftest.json"

    def enabled(self):
        return self._enabled_file.is_file()

    def setup(self):
        """YELLOW at the door, once: the locked-down run user, the fixed projects folder, and the enabled marker."""
        need = ["setfacl"] + (["systemd-run", "systemctl"] if isinstance(self.backend, SystemdBackend) else [])
        for tool in need:
            if shutil.which(tool, path=_ENV["PATH"]) is None:
                raise JobError("missing_tool_" + tool.replace("-", "_") + "_install_the_acl_or_systemd_package")
        uid, gid = self.ensure_user()
        if self.projects_dir is not None:
            created = self._ask("prepare")["created"]      # made BY the owner (so it is the owner's); refused if a link/foreign/world-writable
        _write_json(self._enabled_file, {"enabled": True, "at": int(self.clock()), "version": self.version})
        info = {"runner_user": self.run_user, "projects_folder": self.projects_dir, "enabled": True}
        if self.projects_dir is not None and created and isinstance(self.backend, SystemdBackend):
            # systemd binds the owner service's writable folder only if it exists when the service STARTS. An upgrade from an older
            # build cannot create the folder first (its worker predates this), so the owner service is restarted once, a little
            # later (never during this approval's own reply).
            code, _ = self.runcmd(["systemd-run", "--quiet", "--collect", "--on-active=20", "--unit", "stynpilot-owner-restart",
                                   "systemctl", "--user", "--machine=%s@.host" % self.owner_name, "restart", "stynpilot-owner.service"], 30)
            info["owner_service_restart_scheduled"] = code == 0
        return info

    def selftest_state(self):
        try:
            data = json.loads(self._selftest_file.read_text())
        except (OSError, ValueError):
            return {"ok": False, "ran": False}
        if type(data) is not dict:
            return {"ok": False, "ran": False}
        return data

    def require_ready(self):
        if not self.enabled():
            raise JobError("runner_not_set_up")
        if self.gate:
            state = self.selftest_state()
            if state.get("ok") is not True or state.get("version") != self.version:
                raise JobError("sandbox_self_test_required")

    def selftest(self):
        from .selftest import run_selftest
        return run_selftest(self)

    def _pump(self, job_id, proc, seconds, local=False):
        folder = self.dir / "jobs" / job_id
        folder.mkdir(mode=0o700)
        out = os.open(folder / "out.log", os.O_CREAT | os.O_WRONLY | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        written, truncated = 0, 0
        timed_out = threading.Event()
        timer = threading.Timer(seconds + 10, lambda: (timed_out.set(), self.backend.cancel(job_id, proc)))
        timer.start()
        disk_full = threading.Event()
        stop_watch = threading.Event()

        def watch():
            # A runaway job must not fill the host disk: the kill threshold leaves headroom for the polling interval.
            while not stop_watch.wait(self.disk_poll):
                try:
                    low = self._free_bytes(self._watch_path(job_id), local) < self.disk_kill_free
                except (JobError, OSError, ValueError):
                    low = True                                    # cannot tell -> fail closed
                if low:
                    disk_full.set()
                    self.backend.cancel(job_id, proc)
                    return
        threading.Thread(target=watch, daemon=True, name="stynpilot-job-disk").start()
        try:
            while True:
                chunk = proc.stdout.read(8192)
                if not chunk:
                    break
                room = MAX_OUT - written
                if room > 0:
                    os.write(out, chunk[:room])
                    written += min(len(chunk), room)
                if len(chunk) > max(room, 0):
                    truncated = 1                               # keep draining so the process never blocks on a full pipe
            code = proc.wait()
            self._repair(job_id, local)
        finally:
            timer.cancel()
            stop_watch.set()
            os.close(out)
            proc.stdout.close()
        with self._lock:
            row = self._db.execute("select state from jobs where id=?", (job_id,)).fetchone()
            state = row["state"]
            if state == "running":
                state = "done" if code == 0 else ("disk_limit" if disk_full.is_set() else ("timeout" if timed_out.is_set() else "failed"))
            self._db.execute("update jobs set state=?, exit_code=?, ended=?, truncated=? where id=?",
                             (state, code, int(self.clock()), truncated, job_id))
            self._live.pop(job_id, None)

    def _repair(self, job_id, local):
        """Files the run user created with mode 0600 get an ACL mask of 0 (so the owner's named entry stops working). Re-open the mask,
        AS THE RUN USER (it owns those files), inside the same sandbox, without following links."""
        row = self._db.execute("select workspace from jobs where id=?", (job_id,)).fetchone()
        if row is None or not os.path.isabs(row["workspace"]):
            return
        try:
            proc = self.backend.start(secrets.token_hex(16), ["/usr/bin/setfacl", "-R", "-P", "-m", "m::rwx", "--", "."], row["workspace"],
                                      {"seconds": 60, "memory_mb": 128, "tasks": 16, "writes": True}, self.run_user, masked=())
            proc.stdout.read()
            proc.wait()
        except (OSError, JobError, runner.RunnerError):
            pass

    def _watch_path(self, job_id):
        row = self._db.execute("select workspace from jobs where id=?", (job_id,)).fetchone()
        return row["workspace"] if row else "/"

    def cancel(self, job_id):
        with self._lock:
            live = self._live.get(job_id)
            if live is None:
                raise JobError("not_running")
            self._db.execute("update jobs set state='cancelled' where id=? and state='running'", (job_id,))
        self.backend.cancel(job_id, live[1])
        return {"job_id": job_id, "cancelled": True}

    def wait(self, job_id, timeout=60):
        live = self._live.get(job_id)
        if live:
            live[0].join(timeout)
        return self.status(job_id)

    def status(self, job_id):
        row = self._db.execute("select * from jobs where id=?", (job_id,)).fetchone() if _is_id(job_id) else None
        if row is None:
            raise JobError("unknown_job")
        d = dict(row)
        d["argv"] = json.loads(d["argv"])
        return d

    def output(self, job_id, offset=0, limit=32768):
        self.status(job_id)
        if type(offset) is not int or type(limit) is not int or offset < 0 or not 0 < limit <= 65536:
            raise JobError("bad_window")
        path = self.dir / "jobs" / job_id / "out.log"
        try:
            raw = path.read_bytes()[:MAX_OUT]
        except OSError:
            raw = b""
        clean, found = redact.redact(raw.decode("utf-8", "replace"))          # the WHOLE text is cleaned before any slicing
        window = clean[offset:offset + limit]
        return {"text": window, "offset": offset, "next_offset": offset + len(window), "total": len(clean),
                "redactions": found, "note": safefs.UNTRUSTED}

    def recent(self, limit=20, workspace=None):
        limit = max(1, min(int(limit), 50))
        if workspace is None:
            rows = self._db.execute("select id,workspace,recipe,state,created,started,ended,exit_code,truncated from jobs "
                                    "where recipe!='selftest' order by created desc limit ?", (limit,)).fetchall()
        else:
            rows = self._db.execute("select id,workspace,recipe,state,created,started,ended,exit_code,truncated from jobs "
                                    "where recipe!='selftest' and workspace=? order by created desc limit ?", (workspace, limit)).fetchall()
        return [dict(r) for r in rows]

    def reconcile(self):
        """After an installer restart: a 'running' job with no live worker is lost (its unit is stopped for safety)."""
        lost = 0
        for row in self._db.execute("select id from jobs where state='running'").fetchall():
            if row["id"] not in self._live:
                subprocess.run(["systemctl", "stop", "stynpilot-job-" + row["id"]], capture_output=True, check=False, env=_ENV) \
                    if isinstance(self.backend, SystemdBackend) else None
                self._db.execute("update jobs set state='lost', ended=? where id=?", (int(self.clock()), row["id"]))
                lost += 1
        return lost

    def _prune(self):
        old = self._db.execute("select id from jobs where state!='running' order by created desc limit -1 offset ?", (MAX_JOBS_KEPT,)).fetchall()
        for row in old:
            folder = self.dir / "jobs" / row["id"]
            try:
                (folder / "out.log").unlink()
                folder.rmdir()
            except OSError:
                pass
            self._db.execute("delete from jobs where id=?", (row["id"],))


def _write_json(path, data):
    tmp = Path(str(path) + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(json.dumps(data, sort_keys=True))
    os.replace(tmp, path)


def _is_id(value):
    return type(value) is str and len(value) == 32 and all(c in "0123456789abcdef" for c in value)
