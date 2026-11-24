"""Review blocker 1: the root installer never walks the owner's home; the owner-side helper does, race-safe. REAL uid drop."""
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from stynpilot import projects_helper, runner  # noqa: E402
from stynpilot.broker.jobs import JobError, JobRunner, LocalBackend  # noqa: E402

ROOT_ONLY = unittest.skipUnless(os.geteuid() == 0 and shutil.which("setpriv") and shutil.which("setfacl"), "needs root, setpriv, setfacl")


def acl(path):
    return subprocess.run(["getfacl", "-p", "-c", path], capture_output=True, text=True).stdout


@ROOT_ONLY
class Helper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.made = False
        try:
            pwd.getpwnam(runner.RUN_USER)
        except KeyError:
            subprocess.run(["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "--user-group", runner.RUN_USER], check=True)
            cls.made = True

    @classmethod
    def tearDownClass(cls):
        if cls.made:
            subprocess.run(["userdel", runner.RUN_USER], capture_output=True)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(os.path.realpath(tmp.name))
        os.chmod(self.root, 0o755)
        self.owner = pwd.getpwnam("nobody")
        self.home = self.root / "home"
        self.projects = self.home / "StyNpilot-Projects"
        self.app = self.projects / "app"
        self.outside = self.home / "outside.txt"
        os.makedirs(self.app)
        self.outside.write_text("owner's private file")
        for p in (self.home, self.projects, self.app, self.outside):
            os.chown(p, self.owner.pw_uid, self.owner.pw_gid)
        os.chmod(self.outside, 0o600)
        for p in (self.home, self.projects, self.app):
            os.chmod(p, 0o755)
        self.state = self.root / "state"
        self.jr = self.runner()
        self.jr.setup()

    def runner(self, projects=None):
        return JobRunner(self.state, owner_uid=self.owner.pw_uid, home=str(self.home), backend=LocalBackend(), gate=False,
                         projects_dir=str(projects or self.projects))

    def has_run_acl(self, path):
        return "user:%s:" % runner.RUN_USER in acl(str(path))

    # -- symlinked base paths are REJECTED, not canonicalised -------------------------------------------------------
    def test_a_symlinked_projects_folder_is_refused(self):
        real = self.home / "real-projects"
        os.makedirs(real / "app")
        for p in (real, real / "app"):
            os.chown(p, self.owner.pw_uid, self.owner.pw_gid)
        link = self.home / "linked"
        os.symlink(real, link)
        jr = self.runner(projects=link)
        with self.assertRaises(JobError) as e:
            jr.setup()
        self.assertIn("link", e.exception.code)
        self.assertFalse(self.has_run_acl(real / "app"))

    def test_a_symlinked_workspace_or_home_is_refused(self):
        target = self.home / "elsewhere"
        os.makedirs(target)
        os.chown(target, self.owner.pw_uid, self.owner.pw_gid)
        os.symlink(target, self.projects / "evil")
        with self.assertRaises(JobError):
            self.jr.enroll(str(self.projects / "evil"))
        self.assertFalse(self.has_run_acl(target))
        linked_home = self.root / "home-link"
        os.symlink(self.home, linked_home)
        jr = JobRunner(self.root / "state2", owner_uid=self.owner.pw_uid, home=str(linked_home), backend=LocalBackend(), gate=False,
                       projects_dir=str(linked_home / "StyNpilot-Projects"))
        with self.assertRaises(JobError):
            jr.setup()

    def test_a_workspace_that_becomes_a_link_after_enrolment_is_not_followed_by_unenrol(self):
        self.jr.enroll(str(self.app))
        shutil.rmtree(self.app)
        os.symlink(self.home, self.app)
        before = acl(str(self.home))
        try:
            self.jr.unenroll(str(self.app))
        except JobError:
            pass
        self.assertEqual(acl(str(self.home)), before)

    # -- races: a subfolder flipped to a link while the helper is walking ---------------------------------------------
    def _flipper(self, folder, stop):
        link_made = False
        while not stop.is_set():
            try:
                if link_made:
                    os.unlink(folder)
                    os.mkdir(folder)
                    os.chown(folder, self.owner.pw_uid, self.owner.pw_gid)
                else:
                    os.rmdir(folder)
                    os.symlink(self.home, folder)
                link_made = not link_made
            except OSError:
                pass

    def _populate(self, n=60):
        for i in range(n):
            d = self.app / ("d%02d" % i)
            os.makedirs(d)
            os.chown(d, self.owner.pw_uid, self.owner.pw_gid)
            (d / "f.txt").write_text("x")
            os.chown(d / "f.txt", self.owner.pw_uid, self.owner.pw_gid)

    def test_concurrent_replacement_during_enrol_and_unenrol_never_reaches_outside(self):
        self._populate()
        flip = self.app / "d30"
        stop = threading.Event()
        t = threading.Thread(target=self._flipper, args=(str(flip), stop), daemon=True)
        t.start()
        try:
            for _ in range(6):
                try:
                    self.jr.enroll(str(self.app))
                except JobError:
                    pass
                try:
                    self.jr.unenroll(str(self.app))
                except JobError:
                    pass
        finally:
            stop.set()
            t.join(5)
        for victim in (self.home, self.outside, self.projects):
            self.assertFalse(self.has_run_acl(victim), victim)

    def test_the_walk_itself_skips_a_folder_swapped_for_a_link_between_listing_and_opening(self):
        """Deterministic version of the race, in-process: swap exactly after the stat, before the open."""
        self._populate(3)
        real_open = os.open
        swapped = []

        def evil(path, flags, *a, **kw):
            if path == "d01" and not swapped and kw.get("dir_fd") is not None:
                swapped.append(1)
                full = self.app / "d01"
                shutil.rmtree(full)
                os.symlink(self.outside, full)
            return real_open(path, flags, *a, **kw)
        request = {"op": "enroll", "name": "app", "projects": str(self.projects), "home": str(self.home),
                   "run_user": runner.RUN_USER, "owner_user": "nobody"}
        os.setegid(self.owner.pw_gid)
        os.seteuid(self.owner.pw_uid)
        try:
            with mock.patch("os.open", evil):
                result = projects_helper.op_enroll(request)
        finally:
            os.seteuid(0)
            os.setegid(0)
        self.assertTrue(swapped)
        self.assertGreaterEqual(result["skipped"], 1)
        self.assertFalse(self.has_run_acl(self.outside))

    def test_the_helper_runs_without_privilege(self):
        out = self.jr.helper.call({"op": "check", "name": "app", "projects": str(self.projects), "home": str(self.home)})
        self.assertEqual(out["path"], str(self.app))
        # a root-owned folder cannot be touched by the owner-side helper at all
        rootdir = self.projects / "rootdir"
        os.mkdir(rootdir)
        os.chown(rootdir, 0, 0)
        with self.assertRaises(JobError):
            self.jr.enroll(str(rootdir))
        self.assertFalse(self.has_run_acl(rootdir))

    def test_enrol_cannot_race_job_start(self):
        """A job is never started in a workspace that is being enrolled or revoked: the row and the ACL change are one step."""
        self.jr.enroll(str(self.app))
        self.jr.unenroll(str(self.app))
        with self.assertRaises(JobError) as e:
            self.jr.run(str(self.app), "git-status", [])
        self.assertEqual(e.exception.code, "workspace_not_enrolled")


if __name__ == "__main__":
    unittest.main()
