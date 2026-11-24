"""Second review round, REAL uid drops and namespaces, through the integrated paths:
 1 the disk watchdog has hard deadlines and covers bytes, inodes and per-job growth;
 2 credentials introduced while a job runs, incompletely scanned workspaces;
 3 workspace creation lives in the owner helper (installer-side code runs here with the home folder HIDDEN from it, like ProtectHome=yes);
 4 concurrent jobs in different workspaces; 5 the permission repair."""
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from stynpilot import projects_helper, runner  # noqa: E402
from stynpilot.broker.helper import HelperError, LocalHelper  # noqa: E402
from stynpilot.broker.jobs import JobError, JobRunner, LocalBackend, SystemdBackend  # noqa: E402

ROOT = unittest.skipUnless(os.geteuid() == 0 and shutil.which("setpriv") and shutil.which("setfacl") and shutil.which("unshare"), "needs root")
LIMITS = {"seconds": 60, "memory_mb": 256, "tasks": 64, "writes": True}
PY = "/usr/bin/python3"


def acl(path):
    return subprocess.run(["getfacl", "-p", "-c", str(path)], capture_output=True, text=True).stdout


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.made = [u for u in (runner.RUN_USER, runner.RUN_USER + "-2") if subprocess.run(["id", u], capture_output=True).returncode != 0]

    @classmethod
    def tearDownClass(cls):
        for u in cls.made:
            subprocess.run(["userdel", u], capture_output=True)

    def setUp(self):
        from nsbackend import NamespaceBackend
        self.NS = NamespaceBackend
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(os.path.realpath(tmp.name))
        os.chmod(self.root, 0o755)
        self.owner = pwd.getpwnam("nobody")
        self.home = self.root / "home"
        self.projects = self.home / "StyNpilot-Projects"
        os.makedirs(self.projects)
        for p in (self.home, self.projects):
            os.chown(p, self.owner.pw_uid, self.owner.pw_gid)
            os.chmod(p, 0o755)
        self.state = self.root / "state"
        self.jr = self.make(self.NS(str(self.home)))
        self.addCleanup(self._stop_all)

    def _stop_all(self):
        for jr in list(getattr(self, "runners", [])) + [self.jr]:
            for jid in list(jr._live):
                try:
                    jr.cancel(jid)
                    jr.wait(jid, 10)
                except JobError:
                    pass

    def make(self, backend, **kw):
        opts = dict(gate=False, projects_dir=str(self.projects), disk_start_free=0, disk_kill_free=0, disk_poll=0.2, disk_growth=1 << 60,
                    inode_start=0, inode_kill=0, inode_growth=1.0, measure_timeout=2.0)
        opts.update(kw)
        jr = JobRunner(self.state, owner_uid=self.owner.pw_uid, home=str(self.home), backend=backend, **opts)
        jr.setup()
        self.__dict__.setdefault("runners", []).append(jr)
        return jr

    def ws(self, name="app"):
        path = self.projects / name
        if not path.exists():
            os.makedirs(path)
            os.chown(path, self.owner.pw_uid, self.owner.pw_gid)
            os.chmod(path, 0o755)
        return path

    def owner_write(self, path, text="x", mode=0o644):
        """As the OWNER (a real uid drop), the way anything else on the machine would create a file."""
        code = "import os,sys\nfd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT,int(sys.argv[3],8))\nos.write(fd,sys.argv[2].encode())\nos.close(fd)\n"
        done = subprocess.run(["setpriv", "--reuid=%d" % self.owner.pw_uid, "--regid=%d" % self.owner.pw_gid, "--clear-groups", PY, "-I", "-c", code,
                               str(path), text, oct(mode)[2:]], capture_output=True)
        self.assertEqual(done.returncode, 0, done.stderr)

    def start(self, jr, ws, code, *args, **kw):
        return jr._start(str(ws), "t", [PY, "-I", "-c", code] + list(args), kw.pop("limits", LIMITS), 60, **kw)

    def text(self, jr, job):
        jr.wait(job["job_id"], 40)
        return jr.output(job["job_id"])["text"]


@ROOT
class Watchdog(Base):
    def test_a_hung_measurement_is_cut_off_at_its_deadline_and_the_job_is_killed_in_bounded_time(self):
        slow = self.root / "slowpython"
        slow.write_text("#!/bin/sh\nsleep 60\n")
        os.chmod(slow, 0o755)

        class Flaky(LocalHelper):
            hang = False

            def call(self, request, timeout=120):
                if Flaky.hang and request["op"] == "disk":
                    self.python = str(slow)
                return super().call(request, timeout)
        jr = self.make(LocalBackend(), helper=Flaky(self.owner.pw_uid, self.owner.pw_gid), measure_timeout=1.0)
        ws = self.ws()
        jr.enroll(str(ws))
        job = self.start(jr, ws, "import time; time.sleep(60)")
        began = time.time()
        Flaky.hang = True
        self.assertEqual(jr.wait(job["job_id"], 30)["state"], "disk_limit")
        self.assertLess(time.time() - began, 8, "poll + measurement deadline + kill must stay bounded")

    def test_the_helper_call_itself_has_a_hard_deadline(self):
        slow = self.root / "slowpython2"
        slow.write_text("#!/bin/sh\nsleep 60\n")
        os.chmod(slow, 0o755)
        helper = LocalHelper(self.owner.pw_uid, self.owner.pw_gid, python=str(slow))
        began = time.time()
        with self.assertRaises(HelperError) as e:
            helper.call({"op": "disk", "path": str(self.home)}, timeout=1)
        self.assertEqual(e.exception.code, "projects_helper_timed_out")
        self.assertLess(time.time() - began, 5)

    def test_the_systemd_helper_asks_systemd_for_the_deadline_and_stops_a_stuck_unit(self):
        from stynpilot.broker.helper import SystemdHelper
        seen = []

        def fake_run(cmd, **kw):
            seen.append((cmd, kw))
            if cmd[0] == "systemd-run":
                raise subprocess.TimeoutExpired(cmd, kw["timeout"])
            return subprocess.CompletedProcess(cmd, 0, b"", b"")
        with mock.patch("subprocess.run", fake_run):
            with self.assertRaises(HelperError) as e:
                SystemdHelper("nobody").call({"op": "disk", "path": "/x"}, timeout=4)
        self.assertEqual(e.exception.code, "projects_helper_timed_out")
        first = seen[0][0]
        self.assertIn("RuntimeMaxSec=4", first)
        self.assertLessEqual(seen[0][1]["timeout"], 8)
        kill = seen[1][0]
        self.assertEqual(kill[:2], ["systemctl", "kill"])
        self.assertTrue(kill[-1].startswith("stynpilot-projects-helper-"))

    def test_a_cleanup_that_itself_times_out_still_surfaces_only_as_a_helper_error(self):
        from stynpilot.broker.helper import SystemdHelper

        def fake_run(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw["timeout"])          # systemd-run hangs, and so does systemctl kill
        with mock.patch("subprocess.run", fake_run):
            with self.assertRaises(HelperError) as e:
                SystemdHelper("nobody").call({"op": "disk", "path": "/x"}, timeout=4)
        self.assertEqual(e.exception.code, "projects_helper_timed_out")

        def failing_cleanup(cmd, **kw):
            if cmd[0] == "systemd-run":
                raise subprocess.TimeoutExpired(cmd, kw["timeout"])
            raise OSError("no systemctl")
        with mock.patch("subprocess.run", failing_cleanup):
            with self.assertRaises(HelperError):
                SystemdHelper("nobody").call({"op": "disk", "path": "/x"}, timeout=4)

    def test_the_watchdog_kills_the_job_even_when_the_helper_and_its_cleanup_both_blow_up(self):
        class Exploding(LocalHelper):
            boom = False

            def call(self, request, timeout=120):
                if Exploding.boom and request["op"] == "disk":
                    raise subprocess.TimeoutExpired("systemctl", 5)     # the exact error that used to escape the thread
                return super().call(request, timeout)

        class BadCancel(LocalBackend):
            def cancel(self, job_id, proc):
                raise subprocess.TimeoutExpired("systemctl", 3)         # and the backend's own cancel fails too
        jr = self.make(BadCancel(), helper=Exploding(self.owner.pw_uid, self.owner.pw_gid))
        ws = self.ws()
        jr.enroll(str(ws))
        job = self.start(jr, ws, "import time; time.sleep(60)")
        began = time.time()
        Exploding.boom = True
        self.assertEqual(jr.wait(job["job_id"], 20)["state"], "disk_limit")
        self.assertLess(time.time() - began, 8)

    def test_the_reserve_covers_two_writers_termination_latency_and_buffered_writes(self):
        jr = self.jr
        need = jr.worst_overshoot()
        rate = runner.IO_WRITE_MBPS * (1 << 20)
        self.assertGreater(need, 2 * rate * (jr.disk_poll + jr.measure_timeout))        # two writers, poll + measurement
        self.assertGreater(need, 2 * rate * 16)                                          # + helper cleanup and termination latency
        self.assertGreater(need, 2 * 400 * (1 << 20))                                    # + buffered (dirty) pages per memory limit
        with self.assertRaises(ValueError):
            JobRunner(self.root / "bad", owner_uid=self.owner.pw_uid, home=str(self.home), backend=SystemdBackend(), gate=False,
                      disk_kill_free=1 << 30, helper=LocalHelper(self.owner.pw_uid, self.owner.pw_gid))
        import inspect
        shipped = inspect.signature(JobRunner.__init__).parameters["disk_kill_free"].default
        self.assertGreaterEqual(shipped, need)                                            # the shipped kill line is above it
        self.assertGreater(inspect.signature(JobRunner.__init__).parameters["disk_start_free"].default, shipped)

    def test_termination_under_systemd_is_bounded(self):
        calls = []

        def fake_run(argv, **kw):
            calls.append((argv, kw.get("timeout")))
            raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        proc = mock.Mock(pid=2 ** 22 + 5)
        with mock.patch("subprocess.run", fake_run):
            began = time.time()
            SystemdBackend().cancel("a" * 32, proc)
        self.assertLess(time.time() - began, 1)
        self.assertTrue(calls and all(t is not None and t <= 5 for _, t in calls))
        self.assertEqual(calls[0][0][:2], ["systemctl", "kill"])

    def test_bytes_written_by_one_job_beyond_its_growth_budget_stop_it(self):
        jr = self.make(LocalBackend(), disk_growth=40 << 20)
        ws = self.ws()
        jr.enroll(str(ws))
        code = "import time\nf=open('big.bin','wb')\nfor i in range(100):\n f.write(b'0'*(5<<20)); f.flush(); import os; os.fsync(f.fileno()); time.sleep(0.15)\n"
        job = self.start(jr, ws, code)
        self.assertEqual(jr.wait(job["job_id"], 40)["state"], "disk_limit")
        self.assertLess((ws / "big.bin").stat().st_size, 400 << 20)

    def test_inode_exhaustion_is_covered(self):
        info = os.statvfs(self.home)
        if info.f_files == 0:
            self.skipTest("this file system reports no inode count")
        jr = self.make(LocalBackend(), inode_start=1.1)               # more than 100% free is impossible: start must be refused
        ws = self.ws()
        jr.enroll(str(ws))
        with self.assertRaises(JobError) as e:
            self.start(jr, ws, "pass")
        self.assertEqual(e.exception.code, "not_enough_free_disk_space_to_start_a_job")
        low = {"free": 1 << 40, "ifree": 100, "itotal": 1000, "devices": ["8:0"]}
        base = {"free": 1 << 40, "ifree": 1000, "itotal": 1000, "devices": ["8:0"]}
        jr.inode_kill, jr.inode_growth = 0.02, 0.5
        self.assertTrue(jr._low(low, base))                           # 10% of inodes left and 90% consumed by this job
        self.assertFalse(jr._low(base, base))
        self.assertTrue(jr._low({**base, "ifree": 10}, {**base, "ifree": 12}))     # under the kill line outright

    def test_a_real_inode_burst_is_stopped_by_the_growth_budget(self):
        info = os.statvfs(self.home)
        if info.f_files == 0:
            self.skipTest("this file system reports no inode count")
        budget = 3000
        jr = self.make(LocalBackend(), inode_growth=budget / info.f_files)
        ws = self.ws()
        jr.enroll(str(ws))
        code = "import os,time\nos.mkdir('f')\nfor i in range(60000):\n open('f/%d' % i,'w').close()\n if i % 500 == 0: time.sleep(0.1)\n"
        job = self.start(jr, ws, code)
        self.assertEqual(jr.wait(job["job_id"], 60)["state"], "disk_limit")
        self.assertLess(len(os.listdir(ws / "f")), 40000)

    def test_a_disk_with_no_resolvable_device_refuses_jobs_where_limits_are_enforced(self):
        class Strict(LocalBackend):
            enforces_limits = True
        jr = self.make(Strict(), disk_kill_free=4 << 30)
        ws = self.ws()
        jr.enroll(str(ws))
        with mock.patch.object(JobRunner, "_measure", lambda self_, real, local: {"free": 1 << 40, "ifree": 1, "itotal": 0, "devices": []}):
            with self.assertRaises(JobError) as e:
                self.start(jr, ws, "pass")
        self.assertEqual(e.exception.code, "storage_write_rate_limit_unavailable_for_this_disk")

    def test_the_unit_caps_the_write_rate_of_every_disk_under_the_workspace(self):
        cmd = runner.unit_command("c" * 32, ["/usr/bin/true"], "/home/o/StyNpilot-Projects/app", seconds=10, memory_mb=64, tasks=8,
                                  io_devices=["259:0", "8:16"])
        props = [c for c in cmd if c.startswith("IOWriteBandwidthMax=")]
        self.assertEqual(props, ["IOWriteBandwidthMax=/dev/block/259:0 %dM" % runner.IO_WRITE_MBPS, "IOWriteBandwidthMax=/dev/block/8:16 %dM" % runner.IO_WRITE_MBPS])
        with self.assertRaises(runner.RunnerError):
            runner.unit_command("c" * 32, ["/usr/bin/true"], "/home/o/StyNpilot-Projects/app", seconds=10, memory_mb=64, tasks=8, io_devices=["/dev/sda"])

    def test_block_device_resolution_reads_the_mount_and_follows_partitions_and_stacks(self):
        info = self.root / "mountinfo"
        info.write_text("1 0 8:1 / / rw - ext4 /dev/sdz1 rw\n2 1 0:5 / /home/o rw - tmpfs none rw\n")
        self.assertEqual(projects_helper.block_devices("/home/o/x", str(info)), [])         # tmpfs: nothing to limit
        self.assertEqual(projects_helper.block_devices("/nonexistent/x", str(self.root / "missing")), [])


@ROOT
class RuntimeBoundary(Base):
    WAIT_AND_READ = textwrap.dedent("""
        import os, sys, time
        ws, names = sys.argv[1], sys.argv[2:]
        end = time.time() + 30
        while time.time() < end and names[0] not in os.listdir(ws):
            time.sleep(0.1)
        for n in names:
            try:
                open(os.path.join(ws, n), 'rb').read(1); print('READ', n)
            except OSError:
                print('DENIED', n)
    """)

    def test_files_created_while_a_job_runs_are_closed_to_it_whatever_their_name_or_mode_until_the_next_start(self):
        ws = self.ws()
        self.jr.enroll(str(ws))
        job = self.start(self.jr, ws, self.WAIT_AND_READ, str(ws), "notes.txt", ".env", "later.pem")
        time.sleep(1.0)
        for name in ("notes.txt", ".env", "later.pem"):
            self.owner_write(ws / name, "data", 0o644)
        out = self.text(self.jr, job)
        self.assertNotIn("READ", out, out)
        self.assertEqual(out.count("DENIED"), 3)
        # the next start looks at what exists now: the ordinary file opens, the credential-named ones are hidden
        job2 = self.start(self.jr, ws, "import sys\nfor n in sys.argv[1:]:\n try:\n  open(n,'rb').read(1); print('READ', n)\n except OSError:\n  print('DENIED', n)\n",
                          "notes.txt", ".env", "later.pem")
        out2 = self.text(self.jr, job2)
        self.assertIn("READ notes.txt", out2)
        self.assertIn("DENIED .env", out2)
        self.assertIn("DENIED later.pem", out2)

    def test_new_files_created_by_the_owner_have_no_other_access_at_all(self):
        ws = self.ws()
        self.jr.enroll(str(ws))
        self.owner_write(ws / "fresh.txt", "x", 0o666)
        self.assertEqual(os.stat(ws / "fresh.txt").st_mode & 0o007, 0)
        out = acl(ws)
        self.assertIn("default:other::---", out)
        self.assertNotIn("default:user:%s" % runner.RUN_USER, out)

    def test_a_workspace_that_cannot_be_scanned_completely_is_refused_not_partly_granted(self):
        ws = self.ws()
        self.jr.enroll(str(ws))
        hidden = ws / "locked"
        os.mkdir(hidden)
        os.chown(hidden, self.owner.pw_uid, self.owner.pw_gid)
        os.chmod(hidden, 0o000)                                       # the owner cannot list it: the scan cannot see inside
        with self.assertRaises(JobError) as e:
            self.start(self.jr, ws, "pass")
        self.assertEqual(e.exception.code, "scan_incomplete")
        os.chmod(hidden, 0o755)

    def test_a_workspace_nested_deeper_than_the_scan_limit_is_refused(self):
        ws = self.ws()
        self.jr.enroll(str(ws))
        deep = ws
        for i in range(projects_helper.MAX_DEPTH + 3):
            deep = deep / "d"
            os.mkdir(deep)
            os.chown(deep, self.owner.pw_uid, self.owner.pw_gid)
        with self.assertRaises(JobError) as e:
            self.start(self.jr, ws, "pass")
        self.assertEqual(e.exception.code, "workspace_too_deep")
        fresh = self.ws("second")
        deep2 = fresh
        for i in range(projects_helper.MAX_DEPTH + 3):
            deep2 = deep2 / "d"
            os.mkdir(deep2)
            os.chown(deep2, self.owner.pw_uid, self.owner.pw_gid)
        with self.assertRaises(JobError) as e2:
            self.jr.enroll(str(fresh))
        self.assertEqual(e2.exception.code, "workspace_too_deep")

    def test_unenrol_removes_every_grant_and_the_default_entries(self):
        ws = self.ws()
        (ws / "sub").mkdir()
        os.chown(ws / "sub", self.owner.pw_uid, self.owner.pw_gid)
        self.owner_write(ws / "sub" / "f.txt")
        self.jr.enroll(str(ws))
        self.assertIn("user:%s:" % runner.RUN_USER, acl(ws / "sub" / "f.txt"))
        self.jr.unenroll(str(ws))
        for p in (ws, ws / "sub", ws / "sub" / "f.txt"):
            self.assertNotIn(runner.RUN_USER, acl(p))
        self.assertNotIn("default:", acl(ws / "sub"))


@ROOT
class Concurrent(Base):
    SNOOP = textwrap.dedent("""
        import os, sys
        other_ws, name = sys.argv[1], sys.argv[2]
        print('uid', os.getuid())
        leaks = []
        for pid in os.listdir('/proc'):
            if pid.isdigit() and int(pid) != os.getpid():
                for tail in (other_ws + '/' + name,):
                    try:
                        open('/proc/%s/root%s' % (pid, tail), 'rb').read(1); leaks.append(pid)
                    except OSError:
                        pass
        try:
            open(other_ws + '/' + name, 'rb').read(1); leaks.append('direct')
        except OSError:
            pass
        print('LEAKS', len(leaks))
    """)
    SLEEP = "import os,time\nopen('mine.txt','w').write('secret of ' + os.getcwd())\nprint('READY', flush=True)\ntime.sleep(25)\n"

    def ready(self, jr, job):
        for _ in range(100):
            try:
                if "READY" in (jr.dir / "jobs" / job["job_id"] / "out.log").read_text():
                    return
            except OSError:
                pass
            time.sleep(0.1)
        self.fail("job did not start")

    def test_two_jobs_in_two_workspaces_run_as_different_accounts_and_cannot_reach_each_other(self):
        a, b = self.ws("alpha"), self.ws("beta")
        self.jr.enroll(str(a))
        self.jr.enroll(str(b))
        self.owner_write(a / "shared.txt", "alpha data")
        job_a = self.start(self.jr, a, self.SLEEP)
        self.ready(self.jr, job_a)
        job_b = self.start(self.jr, b, self.SNOOP, str(a), "mine.txt")
        self.assertNotEqual(job_a["run_user"], job_b["run_user"])
        out = self.text(self.jr, job_b)
        self.assertIn("LEAKS 0", out, out)
        job_b2 = self.start(self.jr, b, self.SLEEP)
        self.ready(self.jr, job_b2)
        self.assertNotEqual(job_a["run_user"], job_b2["run_user"])
        with self.assertRaises(JobError) as third:
            self.start(self.jr, a, "pass")                         # both accounts busy: no third job, no shared account
        self.assertEqual(third.exception.code, "too_many_jobs_running")
        self.jr.cancel(job_a["job_id"])
        self.jr.wait(job_a["job_id"], 15)
        self.assertIn(self.jr.status(self.start(self.jr, b, "pass")["job_id"])["state"], ("running", "done"))      # the slot is reusable

    def test_the_test_is_sensitive_one_shared_account_would_leak_through_proc(self):
        a, b = self.ws("alpha"), self.ws("beta")
        backend = self.NS(str(self.home))
        user = runner.RUN_USER
        self.jr.ensure_user()
        for w in (a, b):
            subprocess.run(["setfacl", "-m", "u:%s:rwx" % user, str(w)], check=True)
        first = backend.start("1" * 32, [PY, "-I", "-c", self.SLEEP], str(a), LIMITS, user, masked=[])
        try:
            time.sleep(1.5)
            second = backend.start("2" * 32, [PY, "-I", "-c", self.SNOOP, str(a), "mine.txt"], str(b), LIMITS, user, masked=[])
            out = second.stdout.read().decode()
            second.wait()
        finally:
            os.killpg(first.pid, 9)
        self.assertNotIn("LEAKS 0", out, "with ONE shared account the other job's files were reachable: the account split is what closes this\n" + out)


@ROOT
class Repair(Base):
    def test_repair_keeps_owner_access_to_0600_files_but_never_touches_protected_or_foreign_files_or_widens_entries(self):
        ws = self.ws()
        self.owner_write(ws / "theirs.txt", "owner file", 0o644)
        subprocess.run(["setpriv", "--reuid=%d" % self.owner.pw_uid, "--regid=%d" % self.owner.pw_gid, "--clear-groups", "setfacl", "-m", "u:daemon:r", str(ws / "theirs.txt")],
                       check=True)
        before_theirs = acl(ws / "theirs.txt")
        self.jr.enroll(str(ws))
        make = textwrap.dedent("""
            import os, subprocess
            for name, mode in (('plain.txt', 0o600), ('.env', 0o600), ('server.pem', 0o600)):
                fd = os.open(name, os.O_WRONLY | os.O_CREAT, mode); os.write(fd, b'x'); os.close(fd)
            os.mkdir('d', 0o700)
            fd = os.open('d/inner.txt', os.O_WRONLY | os.O_CREAT, 0o600); os.close(fd)
            subprocess.run(['setfacl', '-m', 'u:daemon:rwx,g::rwx', 'plain.txt'])
            os.symlink('/etc/passwd', 'link')
        """)
        job = self.start(self.jr, ws, make)
        self.assertEqual(self.jr.wait(job["job_id"], 40)["state"], "done")
        for name in ("plain.txt", "d/inner.txt"):
            code = "with open(%r,'r+') as f:\n f.read(); f.seek(0); f.write('edit')\n" % str(ws / name)
            done = subprocess.run(["setpriv", "--reuid=%d" % self.owner.pw_uid, "--regid=%d" % self.owner.pw_gid, "--clear-groups", PY, "-I", "-c", code], capture_output=True)
            self.assertEqual(done.returncode, 0, (name, done.stderr, acl(ws / name)))
        self.assertNotIn("daemon", acl(ws / "plain.txt"), "an unrelated entry the job added must not survive (and not be widened)")
        self.assertIn("mask::rwx", acl(ws / "plain.txt"))
        for protected in (".env", "server.pem"):
            self.assertIn("mask::---", acl(ws / protected), "a protected file must not be opened up by the repair: " + protected)
            self.assertNotIn("#effective:r", acl(ws / protected))
        self.assertEqual(acl(ws / "theirs.txt"), before_theirs, "files the sandbox does not own are untouched")
        self.assertTrue(os.path.islink(ws / "link"))
        self.assertIn("other::---", acl(ws / "plain.txt"))


@ROOT
class ProtectedHome(unittest.TestCase):
    """Installer-side code (JobRunner + Executor._runner_do/_runner_green: setup, enrol, self-test, run, unenrol) runs here in a mount
    namespace where the home folder is an EMPTY tmpfs, exactly what ProtectHome=yes does to the installer. Only the owner-side helper and
    the sandbox (separate mount namespaces that un-hide it, as systemd's own manager would) see the real folder. Any root-side access to the
    home would fail."""
    SCRIPT = textwrap.dedent('''
        import json, os, sys
        sys.path[:0] = [{tests!r}, {src!r}]
        from nsbackend import NamespaceBackend
        from stynpilot.broker.executor import Executor
        from stynpilot.broker.helper import LocalHelper
        from stynpilot.broker.jobs import JobRunner
        home, projects, state, sroot = {home!r}, {projects!r}, {state!r}, {sroot!r}
        out = {{"root_sees_home": sorted(os.listdir(home))}}

        class Hidden(LocalHelper):
            def call(self, request, timeout=120):
                import subprocess
                real = self.python
                self.python = "/bin/sh"
                try:
                    return self._call_unhidden(request, timeout)
                finally:
                    self.python = real

            def _call_unhidden(self, request, timeout):
                from stynpilot.broker import helper as h
                gid = self.owner_gid
                import json as j, subprocess
                inner = ["setpriv", "--reuid=%d" % self.owner_uid, "--regid=%d" % gid, "--clear-groups", "--no-new-privs", "--bounding-set=-all",
                         "--inh-caps=-all", "--", {py!r}, "-I", h.HELPER, j.dumps(request)]
                cmd = ["unshare", "--mount", "--propagation", "private", "sh", "-c", 'umount "$1" && shift && exec "$@"', "sh", home] + inner
                done = subprocess.run(cmd, capture_output=True, timeout=timeout, env={{"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}}, cwd="/")
                return h._parse(done)

        class Backend(NamespaceBackend):
            def start(self, job_id, argv, workspace, limits, run_user, masked=(), io_devices=()):
                real_popen = subprocess.Popen
                import subprocess as sp
                def popen(cmd, **kw):
                    kw["env"] = dict(kw["env"], NS_UNHIDE=home)
                    return real_popen(cmd, **kw)
                sp.Popen = popen
                try:
                    return super().start(job_id, argv, workspace, limits, run_user, masked=masked, io_devices=io_devices)
                finally:
                    sp.Popen = real_popen
        import subprocess
        owner_uid, owner_gid = {uid}, {gid}
        jr = JobRunner(state, owner_uid=owner_uid, home=home, backend=Backend(home), gate=True, version="9.9", projects_dir=projects,
                       selftest_root=sroot, python="/usr/bin/python3", helper=Hidden(owner_uid, owner_gid),
                       disk_start_free=0, disk_kill_free=0, inode_start=0, inode_kill=0, inode_growth=1.0)
        ex = Executor.__new__(Executor)
        ex.jobs = jr
        out["setup"] = ex._runner_do({{"action": "setup"}})
        out["enroll"] = ex._runner_do({{"action": "enroll", "name": "newproj"}})          # the folder does not exist yet: created by the helper
        try:
            started = ex._runner_green("run", {{"workspace": "newproj", "recipe": "git-status"}})
            out["job"] = jr.wait(started["job_id"], 60)["state"]
            out["job_text"] = jr.output(started["job_id"])["text"]
            out["unenroll"] = ex._runner_do({{"action": "unenroll", "name": "newproj"}})
        except Exception as error:
            out["error"] = repr(error)
        print("RESULT " + json.dumps(out))
    ''')

    def test_the_whole_installer_side_path_works_with_the_home_hidden_from_root(self):
        tests_dir = os.path.dirname(os.path.abspath(__file__))
        src = os.path.join(os.path.dirname(tests_dir), "src")
        made = [u for u in (runner.RUN_USER, runner.RUN_USER + "-2") if subprocess.run(["id", u], capture_output=True).returncode != 0]
        self.addCleanup(lambda: [subprocess.run(["userdel", u], capture_output=True) for u in made])
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            os.chmod(tmp, 0o755)
            owner = pwd.getpwnam("nobody")
            home = os.path.join(tmp, "home")
            os.makedirs(home)
            os.chown(home, owner.pw_uid, owner.pw_gid)
            Path(home, "diary.txt").write_text("private")
            script = self.SCRIPT.format(tests=tests_dir, src=src, home=home, projects=home + "/StyNpilot-Projects", state=tmp + "/state",
                                        sroot=tmp + "/run", py="/usr/bin/python3", uid=owner.pw_uid, gid=owner.pw_gid)
            # the real home is bind-mounted aside is NOT done: the helper and the sandbox un-hide it by unmounting the tmpfs in their own namespace
            wrapper = 'mount -t tmpfs -o mode=0755 none "$1" && shift && exec "$@"'
            done = subprocess.run(["unshare", "--mount", "--propagation", "private", "sh", "-c", wrapper, "sh", home, "/usr/bin/python3", "-c", script],
                                  capture_output=True, text=True, timeout=300)
            self.assertIn("RESULT ", done.stdout, done.stdout + done.stderr)
            out = json.loads(done.stdout.split("RESULT ", 1)[1].strip().splitlines()[0])
            self.assertEqual(out["root_sees_home"], [], "the installer-side process must not see the home folder")
            self.assertTrue(out["setup"]["ok"] and out["setup"]["selftest"]["ok"], out)
            self.assertTrue(out["enroll"]["ok"], out["enroll"])
            self.assertNotIn("error", out, out)
            # an empty folder is not a git repository: the recipe ran INSIDE the sandbox, in the new workspace, and said so
            self.assertIn("not a git repository", out["job_text"], out["job_text"])
            self.assertTrue(out["unenroll"]["ok"])
            self.assertTrue(os.path.isdir(home + "/StyNpilot-Projects/newproj"))
            self.assertEqual(os.stat(home + "/StyNpilot-Projects/newproj").st_uid, owner.pw_uid)


if __name__ == "__main__":
    unittest.main()
