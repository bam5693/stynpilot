"""The live confinement self-test and the gate it controls, with REAL privilege separation and REAL Linux namespaces
(tests/nsbackend.py). Shows the probe PASSES in a genuinely confined sandbox and FAILS (gate stays closed) in each
way the confinement can be missing. systemd's own unit properties are proven on the owner's machine by this same test."""
import json
import os
import pwd
import subprocess
import tempfile
import unittest

from stynpilot import runner
from stynpilot.broker import jobs
from stynpilot.broker.jobs import JobError, JobRunner, LocalBackend

from nsbackend import NamespaceBackend

OWNER = "nobody"
ROOT_OK = os.geteuid() == 0 and subprocess.run(["which", "setfacl", "unshare"], capture_output=True).returncode == 0


@unittest.skipUnless(ROOT_OK, "needs root, acl tools and namespaces")
class SelfTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.made_user = subprocess.run(["id", runner.RUN_USER], capture_output=True).returncode != 0

    @classmethod
    def tearDownClass(cls):
        if cls.made_user:
            subprocess.run(["userdel", runner.RUN_USER], capture_output=True)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = os.path.realpath(tmp.name)
        os.chmod(self.root, 0o755)
        self.owner = pwd.getpwnam(OWNER)
        self.home = os.path.join(self.root, "home")
        os.makedirs(os.path.join(self.home, ".ssh"))
        with open(os.path.join(self.home, "diary.txt"), "w") as f:
            f.write("private")
        for p in (self.home,):
            os.chown(p, self.owner.pw_uid, self.owner.pw_gid)
        os.chmod(self.home, 0o755)
        self.state = os.path.join(self.root, "state")
        os.makedirs(self.state, mode=0o700)
        self.sroot = os.path.join(self.root, "run")

    def runner_with(self, backend, **kw):
        jr = JobRunner(self.state, owner_uid=self.owner.pw_uid, home=self.home, backend=backend, version="9.9",
                       selftest_root=self.sroot, python="/usr/bin/python3", **kw)
        return jr

    def test_a_confined_sandbox_passes_and_opens_the_gate_for_this_version_only(self):
        jr = self.runner_with(NamespaceBackend(self.home, hidden=(self.state,)))
        jr.setup()
        with self.assertRaises(JobError) as gate:
            jr.require_ready()
        self.assertEqual(gate.exception.code, "sandbox_self_test_required")
        result = jr.selftest()
        self.assertTrue(result["ok"], result)
        for name in ("identity", "no_capabilities", "hidden_paths", "home_invisible", "network_isolated",
                     "writes_confined", "workspace_writable", "owner_edits_runner_files"):
            self.assertIn(name, result["passed"])
        self.assertEqual(result["failed"], [])
        jr.require_ready()                                          # gate is open
        newer = JobRunner(self.state, owner_uid=self.owner.pw_uid, home=self.home, backend=jr.backend, version="10.0")
        with self.assertRaises(JobError) as gate:
            newer.require_ready()                                   # a new version must re-run the test
        self.assertEqual(gate.exception.code, "sandbox_self_test_required")

    def test_an_unconfined_sandbox_fails_and_the_gate_stays_closed(self):
        jr = self.runner_with(LocalBackend())                       # same uid drop, but no network or filesystem isolation
        jr.setup()
        result = jr.selftest()
        self.assertFalse(result["ok"])
        self.assertIn("network_isolated", result["failed"])
        self.assertIn("home_invisible", result["failed"])
        self.assertIn("identity", result["passed"])
        with self.assertRaises(JobError) as gate:
            jr.require_ready()
        self.assertEqual(gate.exception.code, "sandbox_self_test_required")
        recorded = json.loads(open(os.path.join(self.state, "runner-selftest.json")).read())
        self.assertFalse(recorded["ok"])

    def test_missing_network_isolation_alone_is_caught(self):
        jr = self.runner_with(NamespaceBackend(self.home, hidden=(self.state,), network=True))
        jr.setup()
        result = jr.selftest()
        self.assertFalse(result["ok"])
        self.assertEqual(result["failed"], ["network_isolated"])

    def test_a_probe_that_cannot_run_fails_closed(self):
        jr = self.runner_with(NamespaceBackend(self.home, hidden=(self.state,)))
        jr.setup()
        # a probe that cannot run at all must also fail closed
        jr.python = "/nonexistent/python"
        result = jr.selftest()
        self.assertFalse(result["ok"])
        self.assertIn("probe_did_not_finish_cleanly", result["failed"])

    def test_unreadable_or_forged_results_keep_the_gate_closed(self):
        jr = self.runner_with(NamespaceBackend(self.home, hidden=(self.state,)))
        jr.setup()
        for text in ("not json", "[]", json.dumps({"ok": True, "version": "other"}), json.dumps({"ok": "yes", "version": "9.9"})):
            with open(os.path.join(self.state, "runner-selftest.json"), "w") as f:
                f.write(text)
            with self.assertRaises(JobError):
                jr.require_ready()

    def test_setup_is_required_first_and_run_is_refused_without_the_gate(self):
        jr = self.runner_with(NamespaceBackend(self.home, hidden=(self.state,)))
        with self.assertRaises(JobError) as e:
            jr.selftest()
        self.assertEqual(e.exception.code, "runner_not_set_up")
        with self.assertRaises(JobError) as e:
            jr.enroll(os.path.join(self.home, "x"))
        self.assertEqual(e.exception.code, "runner_not_set_up")
        jr.setup()
        with self.assertRaises(JobError) as e:
            jr.run(os.path.join(self.home, "x"), "git-status", [])
        self.assertEqual(e.exception.code, "sandbox_self_test_required")

    def test_projects_folder_rule_and_ownership(self):
        projects = os.path.join(self.home, "StyNpilot-Projects")
        jr = self.runner_with(NamespaceBackend(self.home), projects_dir=projects)
        info = jr.setup()
        self.assertEqual(os.stat(projects).st_uid, self.owner.pw_uid)
        self.assertEqual(os.stat(projects).st_mode & 0o777, 0o700)
        os.makedirs(os.path.join(projects, "app", "nested"))
        os.makedirs(os.path.join(self.home, "elsewhere"))
        for p in (os.path.join(projects, "app"), os.path.join(projects, "app", "nested"), os.path.join(self.home, "elsewhere")):
            os.chown(p, self.owner.pw_uid, self.owner.pw_gid)
        with self.assertRaises(JobError) as e:
            jr.enroll(os.path.join(self.home, "elsewhere"))
        self.assertEqual(e.exception.code, "workspace_must_be_a_folder_directly_inside_the_projects_folder")
        with self.assertRaises(JobError):
            jr.enroll(os.path.join(projects, "app", "nested"))
        self.assertEqual(jr.enroll(os.path.join(projects, "app"))["workspace"], os.path.join(projects, "app"))


if __name__ == "__main__":
    unittest.main()


class Preflight(unittest.TestCase):
    def test_setup_names_a_missing_tool_instead_of_half_working(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            jr = JobRunner(os.path.join(tmp, "s"), owner_uid=1000, home=tmp, backend=jobs.SystemdBackend())
            with mock.patch("shutil.which", side_effect=lambda t, path=None: None if t == "systemd-run" else "/usr/bin/" + t):
                with self.assertRaises(JobError) as e:
                    jr.setup()
            self.assertTrue(e.exception.code.startswith("missing_tool_systemd_run"))
            self.assertFalse(jr.enabled())
