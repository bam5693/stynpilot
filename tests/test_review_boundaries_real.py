"""Review blockers 2 and 3 with REAL namespaces and a REAL uid drop: protected files are hidden at the sandbox boundary (not just
skipped by the ACL), including world-readable ones and ones created after enrolment; a runaway job is stopped on disk exhaustion;
and the unit command carries the storage limits."""
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from stynpilot import runner  # noqa: E402
from stynpilot.broker.helper import LocalHelper  # noqa: E402
from stynpilot.broker.jobs import JobError, JobRunner, LocalBackend  # noqa: E402

READ = r"""
import os, sys
for p in sys.argv[1:]:
    try:
        d = open(p, "rb").read(5) if not os.path.isdir(p) else os.listdir(p)
        print("READ", os.path.basename(p), "got" if d else "empty")
    except OSError:
        print("DENIED", os.path.basename(p))
"""
ROOT = unittest.skipUnless(os.geteuid() == 0 and shutil.which("setpriv") and shutil.which("setfacl") and shutil.which("unshare"), "needs root")


@ROOT
class Boundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.made = subprocess.run(["id", runner.RUN_USER], capture_output=True).returncode != 0

    @classmethod
    def tearDownClass(cls):
        if cls.made:
            subprocess.run(["userdel", runner.RUN_USER], capture_output=True)

    def setUp(self):
        from nsbackend import NamespaceBackend
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(os.path.realpath(tmp.name))
        os.chmod(self.root, 0o755)
        self.owner = pwd.getpwnam("nobody")
        self.home = self.root / "home"
        self.projects = self.home / "StyNpilot-Projects"
        self.app = self.projects / "app"
        os.makedirs(self.app)
        for p in (self.home, self.projects, self.app):
            os.chown(p, self.owner.pw_uid, self.owner.pw_gid)
            os.chmod(p, 0o755)
        self.NS = NamespaceBackend
        self.state = self.root / "state"
        self.jr = self.make(NamespaceBackend(str(self.home)))

    def make(self, backend, **kw):
        jr = JobRunner(self.state, owner_uid=self.owner.pw_uid, home=str(self.home), backend=backend, gate=False,
                       projects_dir=str(self.projects), disk_start_free=0, disk_kill_free=0, disk_poll=0.2, **kw)
        jr.setup()
        return jr

    def put(self, rel, mode, text="SECRET"):
        p = self.app / rel
        os.makedirs(p.parent, exist_ok=True)
        for d in [p.parent]:
            os.chown(d, self.owner.pw_uid, self.owner.pw_gid)
            os.chmod(d, 0o755 if d == self.app else 0o777)
        p.write_text(text)
        os.chown(p, self.owner.pw_uid, self.owner.pw_gid)
        os.chmod(p, mode)
        return str(p)

    def run_read(self, jr, *paths):
        job = jr._start(str(self.app), "t", ["/usr/bin/python3", "-I", "-c", READ] + list(paths), {"seconds": 20, "memory_mb": 256, "tasks": 64, "writes": True}, 20)
        jr.wait(job["job_id"], 30)
        return jr.output(job["job_id"])["text"]

    # -- blocker 2 ------------------------------------------------------------------------------------------------
    def test_existing_credentials_are_hidden_whatever_their_permissions(self):
        files = {}
        for mode in (0o600, 0o644, 0o666):
            files[mode] = [self.put(".env", mode) if mode == 0o600 else self.put("m%o/.env" % mode, mode),
                           self.put("m%o/id_ed25519" % mode, mode), self.put("m%o/server.pem" % mode, mode),
                           self.put("m%o/credentials.json" % mode, mode)]
        self.put(".ssh/id_rsa", 0o666)
        self.jr.enroll(str(self.app))
        everything = [p for ps in files.values() for p in ps] + [str(self.app / ".ssh" / "id_rsa")]
        out = self.run_read(self.jr, *everything)
        self.assertNotIn("READ", out, out)
        self.assertEqual(out.count("DENIED"), len(everything), out)

    def test_credentials_created_after_enrolment_are_hidden_at_the_next_job(self):
        self.jr.enroll(str(self.app))
        late = self.put("later/.env.local", 0o666)
        self.assertNotIn("READ", self.run_read(self.jr, late))

    def test_the_test_is_sensitive_a_backend_that_does_not_mask_does_leak_world_readable_files(self):
        leaky = self.make(LocalBackend())
        leaky.enroll(str(self.app))
        world = self.put(".env", 0o666)
        out = self.run_read(leaky, world)
        self.assertIn("READ", out, out)                      # proves the masked result above is the masking, not luck

    def test_ordinary_files_stay_readable(self):
        plain = self.put("README.md", 0o644, "hello")
        self.jr.enroll(str(self.app))
        self.assertIn("READ README.md got", self.run_read(self.jr, plain))

    def test_the_trash_is_hidden_from_jobs_and_skipped_by_the_acl(self):
        trash = self.put(".stynpilot-trash/old.txt", 0o666)
        self.jr.enroll(str(self.app))
        self.assertNotIn("READ", self.run_read(self.jr, trash))
        acl = subprocess.run(["getfacl", "-p", "-c", str(self.app / ".stynpilot-trash")], capture_output=True, text=True).stdout
        self.assertNotIn(runner.RUN_USER, acl)

    def test_a_protected_name_that_cannot_be_hidden_safely_stops_the_job(self):
        self.put("odd name/.env", 0o666)
        self.put("space dir/x.pem", 0o666)
        self.jr.enroll(str(self.app))
        with self.assertRaises(JobError) as e:
            self.run_read(self.jr, str(self.app))
        self.assertEqual(e.exception.code, "a_protected_file_has_a_name_that_cannot_be_hidden_safely")

    def test_the_unit_names_every_protected_path_and_rejects_unsafe_ones(self):
        ws = "/home/o/StyNpilot-Projects/app"
        cmd = runner.unit_command("a" * 32, ["/usr/bin/true"], ws, seconds=10, memory_mb=64, tasks=8, masked=[ws + "/.env", ws + "/d/id_rsa"])
        prop = [c for c in cmd if c.startswith("InaccessiblePaths=")][0]
        self.assertIn("-" + ws + "/.env", prop.split())
        self.assertIn("-" + ws + "/d/id_rsa", prop.split())
        self.assertTrue(all(p.startswith("-") for p in prop[len("InaccessiblePaths="):].split()))
        for bad in (ws + "/a b", "/etc/passwd", ws + "/../x", ws + "/x y.pem"):
            with self.assertRaises(runner.RunnerError):
                runner.unit_command("a" * 32, ["/usr/bin/true"], ws, seconds=10, memory_mb=64, tasks=8, masked=[bad])

    # -- should-fix: host sockets ---------------------------------------------------------------------------------
    def test_a_reachable_host_unix_socket_is_hidden_and_the_probe_notices_when_it_is_not(self):
        import socket
        sock_dir = "/run/stynpilot-test"
        os.makedirs(sock_dir, exist_ok=True)
        path = sock_dir + "/x.sock"
        if os.path.exists(path):
            os.unlink(path)
        s = socket.socket(socket.AF_UNIX)
        s.bind(path)
        os.chmod(path, 0o666)
        os.chmod(sock_dir, 0o755)
        s.listen(1)
        self.addCleanup(lambda: (s.close(), shutil.rmtree(sock_dir, ignore_errors=True)))
        probe = ("import socket,sys\nc=socket.socket(socket.AF_UNIX)\n"
                 "try:\n c.connect(sys.argv[1]); print('CONNECTED')\nexcept OSError:\n print('REFUSED')\n")
        for backend, want in ((self.NS(str(self.home)), "REFUSED"), (self.NS(str(self.home), keep_run=True), "CONNECTED")):
            jr = self.make(backend)
            job = jr._start(str(self.app), "t", ["/usr/bin/python3", "-I", "-c", probe, path], {"seconds": 20, "memory_mb": 256, "tasks": 64, "writes": True}, 20, need_enrolled=False)
            jr.wait(job["job_id"], 30)
            self.assertIn(want, jr.output(job["job_id"])["text"])

    # -- blocker 3 ------------------------------------------------------------------------------------------------
    def test_the_unit_carries_the_storage_limits(self):
        cmd = runner.unit_command("b" * 32, ["/usr/bin/true"], "/home/o/StyNpilot-Projects/app", seconds=10, memory_mb=64, tasks=8)
        props = [c for c in cmd if "=" in c and not c.startswith("--")]
        self.assertIn("LimitFSIZE=%dM" % runner.FSIZE_MB, props)
        self.assertTrue(any(p.startswith("TemporaryFileSystem=/tmp:") and "size=%dM" % runner.TMP_MB in p for p in props))
        self.assertTrue(any(p.startswith("TemporaryFileSystem=/run:") for p in props))
        self.assertNotIn("PrivateTmp=yes", props)

    def test_a_job_is_refused_when_free_disk_is_below_the_reserve(self):
        jr = self.make(LocalBackend())
        jr.disk_start_free = 1 << 62
        jr.enroll(str(self.app))
        with self.assertRaises(JobError) as e:
            jr._start(str(self.app), "t", ["/usr/bin/python3", "-c", "pass"], {"seconds": 5, "memory_mb": 64, "tasks": 8, "writes": True}, 5)
        self.assertEqual(e.exception.code, "not_enough_free_disk_space_to_start_a_job")

    def test_a_running_job_is_killed_when_free_disk_falls_below_the_kill_line(self):
        jr = self.make(LocalBackend())
        jr.enroll(str(self.app))
        jr.disk_kill_free = 1 << 62
        job = jr._start(str(self.app), "t", ["/usr/bin/python3", "-c", "import time; time.sleep(30)"], {"seconds": 60, "memory_mb": 64, "tasks": 8, "writes": True}, 60)
        began = time.time()
        state = jr.wait(job["job_id"], 15)
        self.assertEqual(state["state"], "disk_limit")
        self.assertLess(time.time() - began, 10)

    def test_if_free_space_cannot_be_measured_the_job_is_stopped(self):
        jr = self.make(LocalBackend())
        jr.enroll(str(self.app))
        real_measure = jr._measure
        jr._measure = lambda real, local: real_measure(real, local)
        job = jr._start(str(self.app), "t", ["/usr/bin/python3", "-c", "import time; time.sleep(30)"], {"seconds": 60, "memory_mb": 64, "tasks": 8, "writes": True}, 60)

        def broken(real, local):
            raise JobError("projects_helper_failed")
        jr._measure = broken
        self.assertEqual(jr.wait(job["job_id"], 15)["state"], "disk_limit")

    # -- should-fix ------------------------------------------------------------------------------------------------
    def owner_can_edit(self, path):
        code = "with open(%r,'r+') as f:\n f.read(); f.seek(0); f.write('edit')\n" % path
        return subprocess.run(["setpriv", "--reuid=%d" % self.owner.pw_uid, "--regid=%d" % self.owner.pw_gid, "--clear-groups", "python3", "-I", "-c", code],
                              capture_output=True).returncode == 0

    def test_owner_keeps_access_to_mode_0600_files_and_folders_the_job_created(self):
        self.jr.enroll(str(self.app))
        make = "import os\nfd=os.open('a.txt',os.O_WRONLY|os.O_CREAT,0o600);os.write(fd,b'x');os.close(fd)\nos.mkdir('d',0o700)\nfd=os.open('d/b.txt',os.O_WRONLY|os.O_CREAT,0o600);os.write(fd,b'y');os.close(fd)\n"
        job = self.jr._start(str(self.app), "t", ["/usr/bin/python3", "-I", "-c", make], {"seconds": 20, "memory_mb": 256, "tasks": 64, "writes": True}, 20)
        self.jr.wait(job["job_id"], 30)
        self.assertTrue(self.owner_can_edit(str(self.app / "a.txt")))
        self.assertTrue(self.owner_can_edit(str(self.app / "d" / "b.txt")))
        self.assertTrue(os.listdir(self.app / "d"))

    def test_the_selftest_requires_limits_to_be_seen_where_the_backend_enforces_them(self):
        from stynpilot.broker.selftest import OPTIONAL, REQUIRED, _judge
        lines = ["PASS " + n for n in REQUIRED if n != "owner_edits_runner_files"]
        every = ["PASS " + n for n in OPTIONAL]
        self.assertTrue(_judge(lines, True)["ok"])
        self.assertTrue(_judge(lines + ["SKIP limits"], True)["ok"])
        self.assertFalse(_judge(lines + ["SKIP limits"], True, strict_limits=True)["ok"])
        self.assertFalse(_judge(lines, True, strict_limits=True)["ok"])
        self.assertFalse(_judge(lines + ["FAIL limit_io"], True)["ok"])
        self.assertTrue(_judge(lines + every, True, strict_limits=True)["ok"])
        self.assertFalse(_judge(lines + [l for l in every if "limit_tmp" not in l], True, strict_limits=True)["ok"])
        self.assertFalse(_judge([l for l in lines if "credentials_masked" not in l], True)["ok"])
        self.assertFalse(_judge([l for l in lines if "host_sockets_hidden" not in l], True)["ok"])

    def test_each_limit_is_its_own_check_with_safe_diagnostic_values_and_no_duplicates(self):
        from stynpilot.broker.selftest import REQUIRED, OPTIONAL, _judge
        lines = ["PASS " + n for n in REQUIRED if n != "owner_edits_runner_files"] + ["PASS " + n for n in OPTIONAL if n != "limit_io"]
        lines += ["FAIL limit_io", "DIAG limit_io 259:0:wbps=67108864 259:0:wbps=max", "DIAG limit_pids 64 64", "DIAG evil /etc/shadow x",
                  "DIAG limit_tmp 268439552 " + "9" * 300]
        verdict = _judge(lines, True, strict_limits=True)
        self.assertEqual(verdict["failed"], ["limit_io"])                       # named once, and only the check that failed
        self.assertEqual(verdict["diagnostics"]["limit_io"], {"expected": "259:0:wbps=67108864", "actual": "259:0:wbps=max"})
        self.assertNotIn("evil", verdict["diagnostics"])                         # only short safe tokens pass the filter
        self.assertNotIn("limit_tmp", verdict["diagnostics"])
        self.assertFalse(verdict["ok"])

    def test_setup_schedules_one_owner_service_restart_when_it_creates_the_folder_so_an_old_upgrade_worker_is_enough(self):
        from stynpilot.broker.jobs import SystemdBackend
        calls = []

        def run(argv, timeout):
            calls.append(argv)
            return (0, "") if argv[0] in ("systemd-run", "useradd", "setfacl") else (0, "")
        shutil.rmtree(self.projects)
        jr = JobRunner(self.root / "s2", owner_uid=self.owner.pw_uid, home=str(self.home), backend=SystemdBackend(), gate=False,
                       projects_dir=str(self.projects), run=run, helper=LocalHelper(self.owner.pw_uid, self.owner.pw_gid))
        with unittest_mock_which():
            info = jr.setup()
        self.assertTrue(os.path.isdir(self.projects))
        self.assertEqual(os.stat(self.projects).st_uid, self.owner.pw_uid)
        self.assertTrue(info["owner_service_restart_scheduled"])
        restart = [c for c in calls if c[0] == "systemd-run"][0]
        self.assertIn("--on-active=20", restart)
        self.assertIn("--machine=nobody@.host", restart)
        calls.clear()
        with unittest_mock_which():
            again = jr.setup()
        self.assertNotIn("owner_service_restart_scheduled", again)
        self.assertFalse([c for c in calls if c[0] == "systemd-run"])


def unittest_mock_which():
    from unittest import mock
    return mock.patch("shutil.which", lambda tool, path=None: "/usr/bin/" + tool)


class DevSevenWorker(unittest.TestCase):
    """The worker that performs the dev7 -> dev8 upgrade is dev7's own (the new one cannot run yet). It must be enough."""
    def test_dev7_worker_has_no_projects_folder_step_so_setup_must_cover_it(self):
        deb = Path(__file__).resolve().parent.parent / "dist" / "stynpilot_0.1.0~dev7_all.deb"
        if not deb.is_file() or not shutil.which("dpkg-deb"):
            self.skipTest("dev7 package not available")
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["dpkg-deb", "-x", str(deb), tmp], check=True)
            found = list(Path(tmp).rglob("upgrade_worker.py"))
            self.assertTrue(found)
            text = found[0].read_text()
            self.assertNotIn("StyNpilot-Projects", text)
            self.assertIn("daemon-reload", text)                  # it re-reads changed unit files, which is all the new units need
            self.assertIn('"restart", self.job["owner_unit"]', text.replace("systemctl(\"user\", \"restart\", ", '"restart", ') if False else text.replace('self.systemctl("user", "restart", self.job["owner_unit"])', '"restart", self.job["owner_unit"]'))


if __name__ == "__main__":
    unittest.main()


class DiagnosticFilter(unittest.TestCase):
    def test_a_soft_hard_limit_pair_with_a_slash_passes_but_paths_do_not(self):
        from stynpilot.broker.selftest import OPTIONAL, REQUIRED, _judge
        lines = ["PASS " + n for n in REQUIRED if n != "owner_edits_runner_files"] + ["PASS " + n for n in OPTIONAL]
        lines += ["DIAG limit_fsize 536870912 536870912/536870912", "DIAG limit_tmp 268439552 /etc/shadow", "DIAG limit_pids 64 a/b", "DIAG limit_io 1 -1/-1"]
        d = _judge(lines, True, strict_limits=True)["diagnostics"]
        self.assertEqual(d["limit_fsize"], {"expected": "536870912", "actual": "536870912/536870912"})
        self.assertNotIn("limit_tmp", d)
        self.assertNotIn("limit_pids", d)
        self.assertEqual(d["limit_io"]["actual"], "-1/-1")            # "unlimited" soft/hard pair stays visible
