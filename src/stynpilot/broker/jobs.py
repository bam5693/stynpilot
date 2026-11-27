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
import tempfile
import threading
import time
from pathlib import Path

from .. import redact, repo_git, runner, safefs
from . import apt
from ..projects_helper import block_devices
from .helper import MEASURE_TIMEOUT, SLACK, STOP_WAIT, HelperError, LocalHelper, SystemdHelper

MAX_OUT = 256 * 1024
MAX_ENTRIES = 50000
MAX_JOBS_KEPT = 200
BATCH = 100
LIB = str(Path(__file__).resolve().parents[2])      # where the stynpilot package lives (the sandbox imports acl_repair from here)
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


class JobError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class SystemdBackend:
    enforces_limits = True          # the self-test must SEE the limits from inside, or it fails

    def start(self, job_id, argv, workspace, limits, run_user, masked=(), io_devices=(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE):
        cmd = runner.unit_command(job_id, argv, workspace, run_user=run_user, masked=masked, io_devices=io_devices, **limits)
        return subprocess.Popen(cmd, stdout=stdout, stderr=subprocess.STDOUT, stdin=stdin, env=_ENV,
                                start_new_session=True)

    def cancel(self, job_id, proc):
        """Bounded termination: SIGKILL the whole unit first (a few seconds at most), then stop it, then the local client process."""
        unit = "stynpilot-job-" + job_id + ".service"
        for argv, wait in ((["systemctl", "kill", "--signal=SIGKILL", "--kill-whom=all", unit], 3), (["systemctl", "stop", unit], 5)):
            try:
                subprocess.run(argv, capture_output=True, timeout=wait, check=False, env=_ENV)
            except (subprocess.TimeoutExpired, OSError):
                pass
        _kill_group(proc)


class LocalBackend:
    """Root sandbox only: same argv, same fixed environment, real uid/gid drop, no systemd."""
    enforces_limits = False

    def start(self, job_id, argv, workspace, limits, run_user, masked=(), io_devices=(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE):
        pw = pwd.getpwnam(run_user)
        cmd = ["setpriv", "--reuid=%d" % pw.pw_uid, "--regid=%d" % pw.pw_gid, "--clear-groups", "--no-new-privs", "--bounding-set=-all", "--inh-caps=-all", "--"] + list(argv)
        return subprocess.Popen(cmd, cwd=workspace, env=dict(runner.ENV), stdout=stdout, stderr=subprocess.STDOUT,
                                stdin=stdin, start_new_session=True)

    def cancel(self, job_id, proc):
        _kill_group(proc)


def _kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


class JobRunner:
    def __init__(self, state_dir, *, owner_uid, home, backend=None, run=apt.real_run, run_user=runner.RUN_USER, clock=time.time,
                 max_running=2, extra_deny=(), projects_dir=None, disk_start_free=6 << 30, disk_kill_free=4 << 30, disk_growth=4 << 30,
                 inode_start=0.05, inode_kill=0.02, inode_growth=0.15, disk_poll=1.0, measure_timeout=MEASURE_TIMEOUT, version="0", gate=True,
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
        # Two sandbox accounts: jobs that run at the same time never share a uid, so one cannot read another's files, processes
        # (/proc/<pid>/root) or memory. The pool size is also the cap on concurrent jobs.
        self.pool = [run_user, run_user + "-2"]
        self.max_running = min(int(max_running), len(self.pool))
        self._user_of, self._info = {}, {}
        owner = pwd.getpwuid(owner_uid)
        self.owner_name = owner.pw_name
        self.helper = helper or (SystemdHelper(owner.pw_name) if isinstance(backend or SystemdBackend(), SystemdBackend)
                                 else LocalHelper(owner_uid, owner.pw_gid))
        self.backend, self.runcmd, self.clock = backend or SystemdBackend(), run, clock
        self.extra_deny = tuple(str(p) for p in extra_deny) + (str(self.dir),)
        self._lock = threading.Lock()
        self.disk_start_free, self.disk_kill_free, self.disk_growth, self.disk_poll = int(disk_start_free), int(disk_kill_free), int(disk_growth), float(disk_poll)
        self.inode_start, self.inode_kill, self.inode_growth, self.measure_timeout = inode_start, inode_kill, inode_growth, float(measure_timeout)
        if getattr(self.backend, "enforces_limits", False) and self.disk_kill_free < self.worst_overshoot():
            raise ValueError("disk_reserve_smaller_than_what_two_writers_can_add_before_they_are_stopped")   # production never starts so configured
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
        """Create (once) and verify every sandbox account; returns the primary account's (uid, gid)."""
        primary = None
        for name in self.pool:
            try:
                pw = pwd.getpwnam(name)
            except KeyError:
                code, out = self.runcmd(["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "--user-group", name], 60)
                if code != 0:
                    raise JobError("could_not_create_the_runner_user") from None
                pw = pwd.getpwnam(name)
            if pw.pw_uid in (0, self.owner_uid) or pw.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/nologin"):
                raise JobError("runner_user_is_not_locked_down")
            primary = primary or (pw.pw_uid, pw.pw_gid)
        return primary

    def ids(self, name):
        pw = pwd.getpwnam(name)
        return pw.pw_uid, pw.pw_gid

    # -- workspaces ---------------------------------------------------------------------------------------
    def _ask(self, op, _timeout=None, **fields):
        request = {"op": op, "home": self.home, "projects": self.projects_dir, "run_users": list(self.pool), "owner_user": self.owner_name}
        request.update(fields)
        try:
            return self.helper.call(request) if _timeout is None else self.helper.call(request, timeout=_timeout)
        except HelperError as error:
            raise JobError(error.code) from None

    def _acl_scratch(self, folder, *, owner_only=False):
        """ONLY for the self-test's own root-owned scratch folders (never anything in the owner's home). Same model as a real
        workspace: named entries now, no default entry for the sandbox accounts, nothing for "other"."""
        users = [] if owner_only else list(self.pool)
        access = ",".join("u:%s:rwX" % u for u in users + [self.owner_name])
        steps = [["-m", access], ["-d", "-m", "u:%s:rwX,g::---,o::---" % self.owner_name]]
        for step in steps:
            if self.runcmd(["setfacl"] + step + ["--", folder], 60)[0] != 0:
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
        """The workspace folder is created (if missing), checked and given its access by the OWNER-side helper in one step; this
        root-side code never looks at the home folder."""
        if not self.enabled():
            raise JobError("runner_not_set_up")
        if self.projects_dir is None:
            raise JobError("projects_folder_not_configured")
        try:
            runner.check_workspace_text(path)
        except runner.RunnerError as error:
            raise JobError(str(error)) from None
        if os.path.dirname(path) != self.projects_dir:
            raise JobError("workspace_must_be_a_folder_directly_inside_the_projects_folder")
        self.ensure_user()
        with self._ws_lock:
            with self._lock:
                if self._db.execute("select 1 from workspaces where path=?", (path,)).fetchone():
                    raise JobError("already_enrolled")
                for other in self._db.execute("select path from workspaces"):
                    o = other["path"]
                    if path.startswith(o + "/") or o.startswith(path + "/"):
                        raise JobError("overlaps_an_enrolled_workspace")
            done = self._ask("enroll", name=os.path.basename(path))
            if done["path"] != path:
                raise JobError("workspace_path_is_or_contains_a_link")
            with self._lock:
                self._db.execute("insert into workspaces values(?,?,?)", (path, int(self.clock()), done["skipped"]))
        return {"workspace": path, "entries": done["entries"], "skipped": done["skipped"]}

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

    def import_checkout(self, workspace, commit, digest, bundle):
        self.require_ready()
        real = self._workspace_ok(workspace)
        with self._ws_lock:
            with self._lock:
                if not self._db.execute("select 1 from workspaces where path=?", (real,)).fetchone():
                    raise JobError("workspace_not_enrolled")
                if self._db.execute("select 1 from jobs where workspace=? and state='running'", (real,)).fetchone():
                    raise JobError("workspace_git_busy")
            base = self._measure(real, local=False)
            if base["free"] < self.disk_start_free:
                raise JobError("not_enough_free_disk_space_to_start_a_job")
            request = {"op": "import_checkout", "home": self.home, "projects": self.projects_dir,
                       "name": os.path.basename(real), "commit": commit, "digest": digest}
            try:
                return self.helper.call(request, timeout=90, data=bundle)
            except HelperError as error:
                raise JobError(error.code) from None

    def fetch_checkout(self, workspace, commit, digest, bundle):
        self.require_ready()
        real = self._workspace_ok(workspace)
        limits = {"seconds": 90, "memory_mb": 768, "tasks": 32, "writes": True}
        argv = [self.python, "-IB", "-c", runner._GIT_WORKER[-1], repo_git.FETCH, commit, digest]
        job = self._start(real, repo_git.FETCH, argv, limits, 90, input_data=bundle)
        return {"job_id": job["job_id"], "verified_ref": repo_git.VERIFIED_REF_PREFIX + commit}

    def export_push(self, workspace, branch, commit):
        self.require_ready()
        real = self._workspace_ok(workspace)
        with self._ws_lock:
            with self._lock:
                if not self._db.execute("select 1 from workspaces where path=?", (real,)).fetchone():
                    raise JobError("workspace_not_enrolled")
                busy = set(self._user_of.values())
                user = next((account for account in self.pool if account not in busy), None)
                if user is None or self._db.execute(
                    "select 1 from jobs where workspace=? and state='running'", (real,)
                ).fetchone():
                    raise JobError("workspace_git_busy")
            done = self._ask("grant", name=os.path.basename(real))
            masked = self._safe_masked(real, [real + "/" + p for p in done["protected"]])
            argv = [self.python, "-IB", "-c", runner._GIT_WORKER[-1], repo_git.EXPORT, branch, commit]
            limits = {"seconds": 55, "memory_mb": 768, "tasks": 32, "writes": False}
            job = secrets.token_hex(16)
            with tempfile.TemporaryFile() as stream:
                proc = self.backend.start(job, argv, real, limits, user, masked=masked, stdout=stream)
                try:
                    if proc.wait(timeout=65) != 0:
                        raise JobError("git_push_export_refused")
                except subprocess.TimeoutExpired:
                    self.backend.cancel(job, proc)
                    raise JobError("git_push_export_timed_out") from None
                stream.seek(0)
                bundle = stream.read(repo_git.BUNDLE_LIMIT + 1)
            if not bundle.startswith(b"# v2 git bundle\n") and not bundle.startswith(b"# v3 git bundle\n"):
                raise JobError("git_push_bundle_invalid")
            if len(bundle) > repo_git.BUNDLE_LIMIT:
                raise JobError("git_push_bundle_invalid")
            return bundle

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
        return self._start(real, recipe_id, argv, limits, recipe.seconds)

    @staticmethod
    def _safe_masked(real, paths):
        for m in paths:
            if not runner._PATH_CHARS.fullmatch(m) or ".." in m.split("/") or not m.startswith(real + "/"):
                raise JobError("a_protected_file_has_a_name_that_cannot_be_hidden_safely")   # fail closed: no job
        return paths

    def _measure(self, real, local):
        """Free bytes/inodes and the disks under the workspace, with a HARD deadline (a slow measurement counts as a failed one)."""
        if local:
            info = os.statvfs(real)
            return {"free": info.f_bavail * info.f_frsize, "ifree": info.f_favail, "itotal": info.f_files, "devices": block_devices(real)}
        got = self._ask("disk", _timeout=self.measure_timeout, path=self.projects_dir)
        return {k: got[k] for k in ("free", "ifree", "itotal", "devices")}

    def worst_overshoot(self):
        """Most bytes two concurrent writers can add between the disk filling past the kill line and both jobs being dead:
        poll interval + measurement (deadline + slack + cleanup) + termination (kill + stop), at the per-job write cap, plus the
        dirty (buffered) pages each job's memory limit can hold before the kernel throttles it (20% of the limit)."""
        seconds = self.disk_poll + self.measure_timeout + SLACK + STOP_WAIT + 3 + 5
        per_writer = runner.IO_WRITE_BPS * seconds + int(0.2 * max(r.memory_mb for r in runner.RECIPES.values()) * (1 << 20))
        return len(self.pool) * int(per_writer)

    def _low(self, m, base):
        """True when the host disk is too full, or this job has used too much of it. ``base`` is the measurement at job start."""
        if m["free"] < self.disk_kill_free or base["free"] - m["free"] > self.disk_growth:
            return True
        if m["itotal"] > 0 and (m["ifree"] < self.inode_kill * m["itotal"] or base["ifree"] - m["ifree"] > self.inode_growth * m["itotal"]):
            return True
        return False

    def _start(self, real, label, argv, limits, seconds, need_enrolled=True, masked=None, run_user=None, input_data=None):
        self.ensure_user()
        with self._ws_lock:
            if need_enrolled:
                with self._lock:
                    running = self._db.execute(
                        "select recipe from jobs where workspace=? and state='running'", (real,)
                    ).fetchall()
                    if running and (label in repo_git.MUTATIONS or any(row["recipe"] in repo_git.MUTATIONS for row in running)):
                        raise JobError("workspace_git_busy")
                    if not self._db.execute("select 1 from workspaces where path=?", (real,)).fetchone():
                        raise JobError("workspace_not_enrolled")
                # Look at everything that exists NOW: ordinary files get sandbox access, protected names lose it and are hidden.
                # Anything the helper cannot see completely is a refusal (never a partial scan).
                done = self._ask("grant", name=os.path.basename(real))
                masked = self._safe_masked(real, [real + "/" + p for p in done["protected"]])
            masked = list(masked or [])
            base = self._measure(real, local=not need_enrolled)
            if base["free"] < self.disk_start_free or (base["itotal"] > 0 and base["ifree"] < self.inode_start * base["itotal"]):
                raise JobError("not_enough_free_disk_space_to_start_a_job")
            if getattr(self.backend, "enforces_limits", False) and not base["devices"]:
                raise JobError("storage_write_rate_limit_unavailable_for_this_disk")        # fail closed: no unbounded writer
            job_id = secrets.token_hex(16)
            with self._lock:
                if len(self._live) >= self.max_running:
                    raise JobError("too_many_jobs_running")
                busy = set(self._user_of.values())
                user = run_user if run_user is not None else next((u for u in self.pool if u not in busy), None)
                if user is None or user in busy:
                    raise JobError("too_many_jobs_running")
                self._db.execute("insert into jobs(id,workspace,recipe,argv,state,created) values(?,?,?,?,?,?)",
                                 (job_id, real, label, json.dumps(argv), "running", int(self.clock())))
                self._user_of[job_id] = user
                self._info[job_id] = {"base": base, "masked": masked}
                try:
                    kwargs = {"masked": masked, "io_devices": base["devices"]}
                    if input_data is None:
                        proc = self.backend.start(job_id, argv, real, limits, user, **kwargs)
                    else:
                        with tempfile.TemporaryFile() as stream:
                            stream.write(input_data)
                            stream.seek(0)
                            proc = self.backend.start(job_id, argv, real, limits, user, stdin=stream, **kwargs)
                except OSError:
                    self._db.execute("update jobs set state='failed', ended=? where id=?", (int(self.clock()), job_id))
                    self._user_of.pop(job_id, None)
                    self._info.pop(job_id, None)
                    raise JobError("could_not_start_the_job") from None
                thread = threading.Thread(target=self._pump, args=(job_id, proc, seconds, not need_enrolled), daemon=True, name="stynpilot-job")
                self._live[job_id] = (thread, proc)
                self._db.execute("update jobs set started=? where id=?", (int(self.clock()), job_id))
        thread.start()
        self._prune()
        return {"job_id": job_id, "argv": list(argv), "limits": limits, "run_user": user}

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
        from .. import root_restore
        if root_restore.held(self.dir):
            raise JobError("root_restore_in_progress")
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
            # A runaway job must not exhaust the host disk (bytes or inodes). Every measurement has a hard deadline, so a slow or
            # failing one counts as "low"; termination is bounded too. Between checks the write-rate cap (IOWriteBandwidthMax)
            # limits how far the disk can fill, and the reserve below the kill line is larger than that growth.
            info = self._info.get(job_id)
            while not stop_watch.wait(self.disk_poll):
                try:
                    low = self._low(self._measure(self._real_of(job_id), local), info["base"])
                except BaseException:                             # ANY failure (incl. a timeout of the helper's own cleanup)
                    low = True                                    # cannot tell in time -> fail closed
                if low:
                    disk_full.set()
                    try:
                        self.backend.cancel(job_id, proc)
                    except BaseException:
                        pass
                    finally:
                        _kill_group(proc)                         # the local client process always dies, whatever happened above
                    return
        threading.Thread(target=watch, daemon=True, name="stynpilot-job-disk").start()
        try:
            while True:
                chunk = proc.stdout.read1(8192)          # returns what is there now (live output), not after 8 KiB
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
            self._user_of.pop(job_id, None)
            self._info.pop(job_id, None)

    def _repair(self, job_id, local):
        """Files the sandbox account created with mode 0600 get an ACL mask of 0, which switches the owner's access off. Only the
        account that owns them can change that, so it repairs its OWN files, inside the same sandbox (protected paths still hidden),
        with stynpilot.acl_repair: no links, nothing it does not own, no protected names, and no ACL entries other than the owner's
        and the sandbox accounts' (it starts from ``setfacl -b``), so nothing is unmasked or widened."""
        row = self._db.execute("select workspace from jobs where id=?", (job_id,)).fetchone()
        user, info = self._user_of.get(job_id), self._info.get(job_id)
        if row is None or user is None or info is None or not os.path.isabs(row["workspace"]):
            return
        code = ("import sys; sys.path.insert(0, %r); from stynpilot import acl_repair; acl_repair.main()" % LIB)
        argv = [self.python, "-I", "-c", code, json.dumps({"owner": self.owner_name, "users": list(self.pool)})]
        try:
            proc = self.backend.start(secrets.token_hex(16), argv, row["workspace"],
                                      {"seconds": 60, "memory_mb": 128, "tasks": 16, "writes": True}, user, masked=info["masked"],
                                      io_devices=info["base"]["devices"])
            proc.stdout.read()
            proc.wait()
        except (OSError, JobError, runner.RunnerError):
            pass

    def _real_of(self, job_id):
        row = self._db.execute("select workspace from jobs where id=?", (job_id,)).fetchone()
        if row is None:
            raise JobError("unknown_job")
        return row["workspace"]

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
