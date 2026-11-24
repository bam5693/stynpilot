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
import signal
import sqlite3
import stat
import subprocess
import threading
import time
from pathlib import Path

from .. import redact, runner, safefs
from . import apt

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
    def start(self, job_id, argv, workspace, limits, run_user):
        cmd = runner.unit_command(job_id, argv, workspace, run_user=run_user, **limits)
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=_ENV,
                                start_new_session=True)

    def cancel(self, job_id, proc):
        subprocess.run(["systemctl", "stop", "stynpilot-job-" + job_id], capture_output=True, timeout=30, check=False, env=_ENV)
        _kill_group(proc)


class LocalBackend:
    """Root sandbox only: same argv, same fixed environment, real uid/gid drop, no systemd."""
    def start(self, job_id, argv, workspace, limits, run_user):
        pw = pwd.getpwnam(run_user)
        cmd = ["setpriv", "--reuid=%d" % pw.pw_uid, "--regid=%d" % pw.pw_gid, "--clear-groups", "--no-new-privs", "--"] + list(argv)
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
                 max_running=2, extra_deny=()):
        self.dir = Path(state_dir)
        (self.dir / "jobs").mkdir(parents=True, exist_ok=True, mode=0o700)
        self.owner_uid, self.home, self.run_user = owner_uid, os.path.realpath(home), run_user
        self.backend, self.runcmd, self.clock, self.max_running = backend or SystemdBackend(), run, clock, max_running
        self.extra_deny = tuple(str(p) for p in extra_deny) + (str(self.dir),)
        self._lock = threading.Lock()
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
    def _walk(self, root):
        """(granted paths, count skipped). Plain files and folders on the same file system only."""
        dev = os.lstat(root).st_dev
        granted, skipped, stack = [(root, True)], 0, [root]
        while stack:
            folder = stack.pop()
            for entry in os.scandir(folder):
                try:
                    info = entry.stat(follow_symlinks=False)
                    mode = info.st_mode
                    if info.st_dev != dev or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                        raise ValueError
                    if stat.S_ISREG(mode) and info.st_nlink > 1:
                        raise ValueError                       # the inode may also live outside the workspace
                    safefs.Policy.name_ok(entry.name)
                except (ValueError, OSError, safefs.FileDenied):
                    skipped += 1
                    continue
                is_dir = stat.S_ISDIR(mode)
                granted.append((entry.path, is_dir))
                if is_dir:
                    stack.append(entry.path)
                if len(granted) > MAX_ENTRIES:
                    raise JobError("workspace_too_large")
        return granted, skipped

    def _acl(self, paths, spec, *, remove=False):
        for default in (False, True):
            subset = [p for p, d in paths if d or not default]
            for i in range(0, len(subset), BATCH):
                argv = ["setfacl"] + (["-d"] if default else []) + (["-x", spec] if remove else ["-m", spec]) + ["--"] + subset[i:i + BATCH]
                if self.runcmd(argv, 120)[0] != 0:
                    raise JobError("could_not_set_permissions_on_the_workspace")

    def enroll(self, path):
        real = runner.check_workspace(path, home=self.home, extra_deny=self.extra_deny)
        with self._lock:
            if self._db.execute("select 1 from workspaces where path=?", (real,)).fetchone():
                raise JobError("already_enrolled")
            for other in self._db.execute("select path from workspaces"):
                o = other["path"]
                if real.startswith(o + "/") or o.startswith(real + "/"):
                    raise JobError("overlaps_an_enrolled_workspace")
        uid, _ = self.ensure_user()
        paths, skipped = self._walk(real)
        spec = "u:%s:rwX,u:%s:rwX" % (self.run_user, pwd.getpwuid(self.owner_uid).pw_name)
        self._acl(paths, spec)
        with self._lock:
            self._db.execute("insert into workspaces values(?,?,?)", (real, int(self.clock()), skipped))
        return {"workspace": real, "entries": len(paths), "skipped": skipped}

    def unenroll(self, path):
        with self._lock:
            if self._db.execute("select 1 from jobs j where j.workspace=? and j.state='running'", (path,)).fetchone():
                raise JobError("a_job_is_running_in_this_workspace")
            if not self._db.execute("select 1 from workspaces where path=?", (path,)).fetchone():
                raise JobError("not_enrolled")
        if os.path.isdir(path) and not os.path.islink(path):
            paths, _ = self._walk(path)
            self._acl(paths, "u:%s" % self.run_user, remove=True)
        with self._lock:
            self._db.execute("delete from workspaces where path=?", (path,))
        return {"workspace": path, "removed": True}

    def workspaces(self):
        return [dict(r) for r in self._db.execute("select * from workspaces order by path")]

    # -- jobs ---------------------------------------------------------------------------------------------
    def run(self, workspace, recipe_id, args):
        with self._lock:
            if not self._db.execute("select 1 from workspaces where path=?", (workspace,)).fetchone():
                raise JobError("workspace_not_enrolled")
        real = runner.check_workspace(workspace, home=self.home, extra_deny=self.extra_deny)     # still the same real folder
        if real != workspace:
            raise JobError("workspace_changed")
        argv = runner.build_argv(recipe_id, args, real)
        recipe = runner.RECIPES[recipe_id]
        limits = {"seconds": recipe.seconds, "memory_mb": recipe.memory_mb, "tasks": recipe.tasks, "writes": recipe.writes}
        self.ensure_user()
        job_id = secrets.token_hex(16)
        with self._lock:
            if len(self._live) >= self.max_running:
                raise JobError("too_many_jobs_running")
            self._db.execute("insert into jobs(id,workspace,recipe,argv,state,created) values(?,?,?,?,?,?)",
                             (job_id, real, recipe_id, json.dumps(argv), "running", int(self.clock())))
            try:
                proc = self.backend.start(job_id, argv, real, limits, self.run_user)
            except OSError:
                self._db.execute("update jobs set state='failed', ended=? where id=?", (int(self.clock()), job_id))
                raise JobError("could_not_start_the_job") from None
            thread = threading.Thread(target=self._pump, args=(job_id, proc, recipe.seconds), daemon=True, name="stynpilot-job")
            self._live[job_id] = (thread, proc)
            self._db.execute("update jobs set started=? where id=?", (int(self.clock()), job_id))
        thread.start()
        self._prune()
        return {"job_id": job_id, "argv": list(argv), "limits": limits}

    def _pump(self, job_id, proc, seconds):
        folder = self.dir / "jobs" / job_id
        folder.mkdir(mode=0o700)
        out = os.open(folder / "out.log", os.O_CREAT | os.O_WRONLY | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        written, truncated = 0, 0
        timed_out = threading.Event()
        timer = threading.Timer(seconds + 10, lambda: (timed_out.set(), self.backend.cancel(job_id, proc)))
        timer.start()
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
        finally:
            timer.cancel()
            os.close(out)
            proc.stdout.close()
        with self._lock:
            row = self._db.execute("select state from jobs where id=?", (job_id,)).fetchone()
            state = row["state"]
            if state == "running":
                state = "done" if code == 0 else ("timeout" if timed_out.is_set() else "failed")
            self._db.execute("update jobs set state=?, exit_code=?, ended=?, truncated=? where id=?",
                             (state, code, int(self.clock()), truncated, job_id))
            self._live.pop(job_id, None)

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


def _is_id(value):
    return type(value) is str and len(value) == 32 and all(c in "0123456789abcdef" for c in value)
