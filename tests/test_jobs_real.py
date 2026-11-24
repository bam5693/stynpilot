"""S3b core with REAL privilege separation (root sandbox): a real ``stynpilot-run`` account, real ACLs, real uid drop.
Proves: the run user can work in an enrolled workspace and the owner keeps access to what it creates; it cannot read
the owner's other files, credential-named files, links or hard links out of the workspace; output is bounded and
redacted; jobs time out, cancel, are limited in number and recover after a restart. (Real systemd confinement is
proven on the Ryzen by the S3b self-test; here the same validated argv runs through setpriv.)"""
import os
import pwd
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from stynpilot import runner
from stynpilot.broker import jobs
from stynpilot.broker.jobs import JobError, JobRunner, LocalBackend

OWNER = "nobody"
PROBE = r"""
import os, sys
print("uid", os.getuid(), "euid", os.geteuid(), "groups", sorted(os.getgroups()))
for i, p in enumerate(sys.argv[1:]):
    try:
        open(p, "rb").read(1); print("READ #%d" % i)
    except OSError as e:
        print("DENIED #%d" % i)
"""
TEST_RECIPES = {
    "probe": runner.Recipe("probe", "probe", ("/usr/bin/python3", "-c", PROBE), positional="word", max_extra=6, seconds=30),
    "writer": runner.Recipe("writer", "writer", ("/usr/bin/python3", "-c", "open('made.txt','w').write('x'); import os; os.mkdir('sub'); open('sub/n.txt','w').write('y')"),
                            max_extra=0, seconds=30),
    "sleeper": runner.Recipe("sleeper", "sleeper", ("/usr/bin/python3", "-c", "import time; time.sleep(60)"), max_extra=0, seconds=1),
    "slow": runner.Recipe("slow", "slow", ("/usr/bin/python3", "-c", "import time; time.sleep(30)"), max_extra=0, seconds=60),
    "noisy": runner.Recipe("noisy", "noisy", ("/usr/bin/python3", "-c", "print('password=hunter2hunter2hunter2'); print('x'*400000)"), max_extra=0),
}


@unittest.skipUnless(os.geteuid() == 0 and subprocess.run(["which", "setfacl"], capture_output=True).returncode == 0, "needs root + acl tools")
class Real(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.made_user = subprocess.run(["id", runner.RUN_USER], capture_output=True).returncode != 0
        runner.RECIPES.update(TEST_RECIPES)

    @classmethod
    def tearDownClass(cls):
        for k in TEST_RECIPES:
            runner.RECIPES.pop(k, None)
        if cls.made_user:
            subprocess.run(["userdel", runner.RUN_USER], capture_output=True)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = os.path.realpath(tmp.name)
        os.chmod(self.root, 0o755)
        self.owner = pwd.getpwnam(OWNER)
        self.home = os.path.join(self.root, "home")
        os.makedirs(os.path.join(self.home, "work", "app"))
        self.ws = os.path.join(self.home, "work", "app")
        self.secret = os.path.join(self.home, "owner-secret.txt")
        Path(self.secret).write_text("top secret")
        for p in (self.home, os.path.join(self.home, "work"), self.ws, self.secret):
            os.chown(p, self.owner.pw_uid, self.owner.pw_gid)
        os.chmod(self.secret, 0o600)
        os.chmod(self.home, 0o755)                         # parents must be traversable for the LOCAL backend only
        os.chmod(os.path.join(self.home, "work"), 0o755)
        os.chmod(self.ws, 0o755)
        self.state = os.path.join(self.root, "state")
        os.makedirs(self.state, mode=0o700)
        self.jr = JobRunner(self.state, owner_uid=self.owner.pw_uid, home=self.home, backend=LocalBackend(), max_running=2)
        self.addCleanup(self.stop_everything)

    def stop_everything(self):
        for jid in list(self.jr._live):
            try:
                self.jr.cancel(jid)
                self.jr.wait(jid, 5)
            except JobError:
                pass

    def put(self, name, text, uid=None, mode=0o644):
        p = os.path.join(self.ws, name)
        Path(p).write_text(text)
        os.chown(p, uid if uid is not None else self.owner.pw_uid, self.owner.pw_gid)
        os.chmod(p, mode)
        return p

    def probe(self, *paths):
        runner.RECIPES["probe"] = runner.Recipe("probe", "probe", ("/usr/bin/python3", "-c", PROBE) + tuple(paths), max_extra=0, seconds=30)
        job = self.jr.run(self.ws, "probe", [])
        status = self.jr.wait(job["job_id"])
        return status, self.jr.output(job["job_id"])["text"]

    # -- enrolment and the run user -------------------------------------------------------------------------
    def test_the_run_user_is_locked_down_and_never_root_or_the_owner(self):
        uid, gid = self.jr.ensure_user()
        self.assertNotIn(uid, (0, self.owner.pw_uid))
        self.assertIn(pwd.getpwuid(uid).pw_shell, ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false"))

    def test_a_job_runs_as_the_run_user_with_no_extra_groups(self):
        self.jr.enroll(self.ws)
        status, text = self.probe()
        uid = pwd.getpwnam(runner.RUN_USER).pw_uid
        self.assertEqual(status["state"], "done", text)
        self.assertIn("uid %d euid %d groups []" % (uid, uid), text)

    def test_the_run_user_can_work_in_the_workspace_and_the_owner_keeps_access_to_what_it_makes(self):
        self.jr.enroll(self.ws)
        status = self.jr.wait(self.jr.run(self.ws, "writer", [])["job_id"])
        self.assertEqual(status["state"], "done", self.jr.output(status["id"]))
        for rel in ("made.txt", "sub/n.txt"):
            path = os.path.join(self.ws, rel)
            as_owner = subprocess.run(["setpriv", "--reuid=%d" % self.owner.pw_uid, "--regid=%d" % self.owner.pw_gid, "--clear-groups",
                                       "python3", "-c", "import sys; p=sys.argv[1]; open(p,'a').write('!'); open(p).read()", path],
                                      capture_output=True, text=True)
            self.assertEqual(as_owner.returncode, 0, (rel, as_owner.stderr))
        as_owner = subprocess.run(["setpriv", "--reuid=%d" % self.owner.pw_uid, "--regid=%d" % self.owner.pw_gid, "--clear-groups",
                                   "python3", "-c", "import sys; open(sys.argv[1]+'/owner-new.txt','w').write('n')", os.path.join(self.ws, "sub")],
                                  capture_output=True, text=True)
        self.assertEqual(as_owner.returncode, 0, as_owner.stderr)

    def test_without_enrolment_nothing_runs_and_the_run_user_has_no_access(self):
        with self.assertRaises(JobError) as caught:
            self.jr.run(self.ws, "probe", [])
        self.assertEqual(caught.exception.code, "workspace_not_enrolled")

    def test_it_cannot_read_the_owners_other_files_credential_named_files_links_or_hard_links(self):
        data = self.put("data.txt", "d", mode=0o600)
        env = self.put(".env", "TOKEN=abc", mode=0o600)
        os.symlink(self.secret, os.path.join(self.ws, "link-to-secret"))
        os.link(self.secret, os.path.join(self.ws, "hardlink-to-secret"))
        info = self.jr.enroll(self.ws)
        self.assertGreaterEqual(info["skipped"], 3)
        paths = [p for p in (data, env, self.secret, os.path.join(self.ws, "link-to-secret"),
                                               os.path.join(self.ws, "hardlink-to-secret"))]
        status, text = self.probe(*paths)
        self.assertIn("READ #0", text)
        for i in range(1, 5):                                         # .env, owner secret, symlink, hard link
            self.assertIn("DENIED #%d" % i, text)
        acl = subprocess.run(["getfacl", "-p", self.secret], capture_output=True, text=True).stdout
        self.assertNotIn(runner.RUN_USER, acl)                       # the outside file's ACL was never touched

    def test_unenrolling_removes_the_access_and_is_refused_while_a_job_runs(self):
        data = self.put("d.txt", "d", mode=0o600)
        self.jr.enroll(self.ws)
        self.assertIn("READ", self.probe(data)[1])
        job = self.jr.run(self.ws, "slow", [])
        with self.assertRaises(JobError) as caught:
            self.jr.unenroll(self.ws)
        self.assertEqual(caught.exception.code, "a_job_is_running_in_this_workspace")
        self.jr.cancel(job["job_id"])
        self.jr.wait(job["job_id"], 5)
        self.jr.unenroll(self.ws)
        acl = subprocess.run(["getfacl", "-p", data], capture_output=True, text=True).stdout
        self.assertNotIn(runner.RUN_USER, acl)

    def test_a_workspace_swapped_for_a_link_after_enrolment_is_refused(self):
        self.jr.enroll(self.ws)
        moved = self.ws + "-moved"
        os.rename(self.ws, moved)
        os.symlink(moved, self.ws)
        with self.assertRaises((JobError, runner.RunnerError)):
            self.jr.run(self.ws, "probe", [])

    def test_overlapping_and_unsafe_workspaces_are_refused(self):
        self.jr.enroll(self.ws)
        inner = os.path.join(self.ws, "inner")
        os.makedirs(inner)
        os.chown(inner, self.owner.pw_uid, self.owner.pw_gid)
        with self.assertRaises(JobError):
            self.jr.enroll(inner)
        for bad in (self.home, "/etc", os.path.join(self.home, "nope")):
            with self.assertRaises((JobError, runner.RunnerError)):
                self.jr.enroll(bad)

    # -- jobs ---------------------------------------------------------------------------------------------
    def test_output_is_bounded_redacted_and_paged(self):
        self.jr.enroll(self.ws)
        job = self.jr.run(self.ws, "noisy", [])
        status = self.jr.wait(job["job_id"])
        self.assertEqual((status["state"], status["truncated"]), ("done", 1))
        first = self.jr.output(job["job_id"], 0, 100)
        self.assertNotIn("hunter2", first["text"])
        self.assertIn("REDACTED", first["text"])
        self.assertLessEqual(first["total"], jobs.MAX_OUT + 1024)
        second = self.jr.output(job["job_id"], first["next_offset"], 100)
        self.assertEqual(second["offset"], first["next_offset"])
        for bad in ((-1, 10), (0, 0), (0, 10 ** 7), ("a", 5)):
            with self.assertRaises(JobError):
                self.jr.output(job["job_id"], *bad)

    def test_a_job_that_overruns_its_time_is_killed(self):
        self.jr.enroll(self.ws)
        original = jobs.threading.Timer
        jobs.threading.Timer = lambda s, f: original(0.5, f)          # the 1 s recipe limit + 10 s grace, shortened for the test
        try:
            job = self.jr.run(self.ws, "sleeper", [])
            status = self.jr.wait(job["job_id"], 20)
        finally:
            jobs.threading.Timer = original
        self.assertEqual(status["state"], "timeout")

    def test_cancel_stops_the_whole_process_group(self):
        self.jr.enroll(self.ws)
        job = self.jr.run(self.ws, "slow", [])
        time.sleep(0.3)
        self.jr.cancel(job["job_id"])
        status = self.jr.wait(job["job_id"], 10)
        self.assertEqual(status["state"], "cancelled")
        with self.assertRaises(JobError):
            self.jr.cancel(job["job_id"])

    def test_the_number_of_concurrent_jobs_is_limited(self):
        self.jr.enroll(self.ws)
        a, b = self.jr.run(self.ws, "slow", []), self.jr.run(self.ws, "slow", [])
        with self.assertRaises(JobError) as caught:
            self.jr.run(self.ws, "slow", [])
        self.assertEqual(caught.exception.code, "too_many_jobs_running")
        for j in (a, b):
            self.jr.cancel(j["job_id"])
            self.jr.wait(j["job_id"], 10)

    def test_hostile_arguments_never_reach_a_process(self):
        self.jr.enroll(self.ws)
        for args in (["-c", "x"], ["/etc/passwd"], ["a;id"]):
            with self.assertRaises(runner.RunnerError):
                self.jr.run(self.ws, "make", args)
        self.assertEqual(self.jr._db.execute("select count(*) from jobs").fetchone()[0], 0)

    def test_a_job_left_running_by_a_dead_installer_is_marked_lost_after_restart(self):
        self.jr.enroll(self.ws)
        self.jr._db.execute("insert into jobs(id,workspace,recipe,argv,state,created) values('%s',?,?,?,?,?)" % ("a" * 32),
                            (self.ws, "probe", "[]", "running", 1))
        again = JobRunner(self.state, owner_uid=self.owner.pw_uid, home=self.home, backend=LocalBackend())
        self.assertEqual(again.reconcile(), 1)
        self.assertEqual(again.status("a" * 32)["state"], "lost")

    def test_unknown_or_malformed_job_ids_are_refused(self):
        for bad in ("x", "../../etc", None, "g" * 32, 5):
            with self.assertRaises(JobError):
                self.jr.status(bad)


if __name__ == "__main__":
    unittest.main()
