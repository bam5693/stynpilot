"""S3b-2: the installer's door for the sandboxed runner. YELLOW changes (set up the runner, authorize a workspace, remove
one) need the owner's one-time proof bound to the exact request; GREEN calls (status, self-test, run, jobs, output,
cancel) need none but never touch what only the owner may change. Door logic runs everywhere with a recording stand-in;
the full path with REAL privilege separation and REAL namespaces runs as root."""
import os
import pwd
import subprocess
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from stynpilot.broker import apt
    from stynpilot.broker.executor import ExecutionDenied, Executor
    from stynpilot.broker.jobs import JobError, JobRunner
    from stynpilot.broker.proof import ProofVerifier, decision_nonce
except ImportError:          # pragma: no cover
    jwt = None

from stynpilot import runner
from stynpilot.identity import account_id
from stynpilot.requests import request_id

ISS, APP, SUB = "https://issuer.example.test/", "approval-app-client", "auth0|test-owner"
OWNER = account_id(verified_issuer=ISS, verified_subject=SUB)
DEVICE = "dtdev_TESTONLYliveDevice"


class Recording:
    """Stands in for the root-side JobRunner: records what the door let through."""
    projects_dir, version = "/home/o/StyNpilot-Projects", "1"

    def __init__(self):
        self.calls, self.is_enabled, self.state = [], False, {}

    def reconcile(self):
        return 0

    def enabled(self):
        return self.is_enabled

    def setup(self):
        self.calls.append("setup")
        self.is_enabled = True
        return {"runner_user": "stynpilot-run"}

    def selftest(self):
        self.calls.append("selftest")
        self.state = {"ok": True, "ran": True, "passed": ["identity"], "failed": [], "unverified": [], "version": "1", "at": 1}
        return self.state

    def selftest_state(self):
        return self.state

    def enroll(self, path):
        self.calls.append(("enroll", path))
        return {"entries": 1, "skipped": 0}

    def unenroll(self, path):
        self.calls.append(("unenroll", path))

    def workspaces(self):
        return [{"path": self.projects_dir + "/app", "enrolled_at": 5}]

    def run(self, path, recipe, args):
        self.calls.append(("run", path, recipe, tuple(args)))
        return {"job_id": "a" * 32, "argv": ["/usr/bin/git"], "limits": {}}


@unittest.skipIf(jwt is None, "needs PyJWT and cryptography")
class Door(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key(), as_dict=True)
        public.update(kid="k1", use="sig", alg="RS256")
        cls.jwks = {"keys": [public]}

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.jobs = Recording()
        self.jobs.projects_dir = str(self.tmp / "projects")
        os.mkdir(self.jobs.projects_dir)
        self.executor = Executor(state_dir=self.tmp / "broker", owner=OWNER, device=DEVICE,
                                 verifier=ProofVerifier(issuer=ISS, approval_client_id=APP, jwks=self.jwks),
                                 run=apt.real_run, require_root=False, owner_uid=os.getuid(), jobs=self.jobs)

    def payload(self, action="setup", name="", minutes=60, **kw):
        p = {"kind": "runner", "action": action, "name": name, "owner": OWNER, "device": DEVICE,
             "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        p.update(kw)
        return p

    def proof(self, payload, challenge, decision="approve"):
        rid, _ = request_id(payload)
        now = int(time.time())
        claims = {"iss": ISS, "aud": APP, "sub": SUB, "iat": now, "exp": now + 300, "auth_time": now - 5,
                  "nonce": decision_nonce(decision, rid, rid, challenge)}
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "k1"})

    def approve(self, payload):
        challenge = self.executor.challenge(payload, "approve")["challenge"]
        return self.executor.runner_admin(payload, self.proof(payload, challenge), challenge)

    def denied(self, code, fn, *args):
        with self.assertRaises(ExecutionDenied) as caught:
            fn(*args)
        self.assertEqual(caught.exception.code, code)

    # -- what the owner reads ---------------------------------------------------------------------------
    def test_the_owner_reads_exactly_what_each_request_does(self):
        text = "\n".join(self.executor.challenge(self.payload(), "approve")["summary"])
        for want in ("stynpilot-run", "no sudo", "StyNpilot-Projects", "self-test", "authorizes no project"):
            self.assertIn(want, text)
        self.jobs.is_enabled = True
        text = "\n".join(self.executor.challenge(self.payload("enroll", "my-app"), "approve")["summary"])
        for want in ("StyNpilot-Projects/my-app", "no network", "remove this authorization"):
            self.assertIn(want, text)
        text = "\n".join(self.executor.challenge(self.payload("unenroll", "my-app"), "approve")["summary"])
        self.assertIn("no longer be able", text)

    def test_malformed_or_mismatched_requests_are_refused_before_anyone_is_asked(self):
        bad = [self.payload("enroll", "../x"), self.payload("enroll", "a/b"), self.payload("enroll", ".hidden"),
               self.payload("enroll", ""), self.payload("enroll", "x" * 60), self.payload("setup", "name"),
               self.payload("delete", "x"), self.payload(extra=1), self.payload(owner="someone-else"),
               self.payload(device="dtdev_other")]
        for payload in bad:
            self.denied("runner_request_invalid", self.executor.challenge, payload, "approve")
        self.denied("plan_invalid_or_expired", self.executor.challenge, self.payload(minutes=-5), "approve")
        self.assertEqual(self.jobs.calls, [])

    # -- the proof ----------------------------------------------------------------------------------------
    def test_no_proof_wrong_proof_and_replay_change_nothing(self):
        payload = self.payload()
        challenge = self.executor.challenge(payload, "approve")["challenge"]
        with self.assertRaises(ExecutionDenied):
            self.executor.runner_admin(payload, "junk", challenge)
        other = self.payload("enroll", "app")
        with self.assertRaises(ExecutionDenied):
            self.executor.runner_admin(payload, self.proof(other, challenge), challenge)      # proof for another request
        self.assertEqual(self.jobs.calls, [])
        done = self.executor.runner_admin(payload, self.proof(payload, challenge), challenge)
        self.assertTrue(done["ok"])
        self.assertEqual(self.jobs.calls, ["setup", "selftest"])
        with self.assertRaises(ExecutionDenied):
            self.executor.runner_admin(payload, self.proof(payload, challenge), challenge)    # replay
        self.assertEqual(self.jobs.calls, ["setup", "selftest"])

    def test_a_denial_is_final_and_runs_nothing(self):
        payload = self.payload()
        challenge = self.executor.challenge(payload, "deny")["challenge"]
        self.executor.deny(payload, self.proof(payload, challenge, "deny"), challenge)
        self.assertEqual(self.jobs.calls, [])
        self.denied("already_decided_or_used", self.executor.challenge, payload, "approve")

    def test_a_workspace_cannot_be_authorized_before_setup(self):
        self.denied("runner_not_set_up", self.executor.challenge, self.payload("enroll", "app"), "approve")
        self.approve(self.payload())
        result = self.approve(self.payload("enroll", "app", minutes=61))
        self.assertEqual(result["workspace"], "app")
        self.assertEqual(self.jobs.calls[-1], ("enroll", self.jobs.projects_dir + "/app"))

    # -- GREEN calls ----------------------------------------------------------------------------------------
    def test_green_calls_need_no_proof_and_take_only_names_never_paths(self):
        self.approve(self.payload())
        self.assertTrue(self.executor.runner_call("status", {})["enabled"])
        self.assertEqual(self.executor.runner_call("workspaces", {})["workspaces"][0]["name"], "app")
        started = self.executor.runner_call("run", {"workspace": "app", "recipe": "git-status", "args": []})
        self.assertEqual(self.jobs.calls[-1], ("run", self.jobs.projects_dir + "/app", "git-status", ()))
        self.assertEqual(started["job_id"], "a" * 32)
        for bad in ("../etc", "/etc", "a/b", "", None, 5, ".x"):
            self.denied("workspace_name_invalid", self.executor.runner_call, "run", {"workspace": bad, "recipe": "git-status"})
        self.denied("runner_call_invalid", self.executor.runner_call, "run", {"workspace": "app", "recipe": 5})
        self.denied("runner_call_invalid", self.executor.runner_call, "run", {"workspace": "app", "recipe": "x", "args": [1]})
        self.denied("runner_call_unknown", self.executor.runner_call, "enroll", {"workspace": "app"})
        self.denied("runner_call_unknown", self.executor.runner_call, "setup", {})
        self.denied("runner_call_invalid", self.executor.runner_call, "status", [])

    def test_the_runner_is_unavailable_when_it_was_never_wired(self):
        bare = Executor(state_dir=self.tmp / "b2", owner=OWNER, device=DEVICE, verifier=self.executor.verifier,
                        run=apt.real_run, require_root=False, owner_uid=os.getuid())
        self.denied("runner_not_available", bare.runner_call, "status", {})
        self.denied("runner_not_available", bare.challenge, self.payload(), "approve")


ROOT_OK = os.geteuid() == 0 and subprocess.run(["which", "setfacl", "unshare"], capture_output=True).returncode == 0


@unittest.skipUnless(ROOT_OK and jwt is not None, "needs root, acl tools and namespaces")
class Real(Door):
    """The same door, but with the real JobRunner, a real run user, real ACLs and real namespaces."""
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.made_user = subprocess.run(["id", runner.RUN_USER], capture_output=True).returncode != 0

    @classmethod
    def tearDownClass(cls):
        if cls.made_user:
            subprocess.run(["userdel", runner.RUN_USER], capture_output=True)

    def setUp(self):
        from nsbackend import NamespaceBackend
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(os.path.realpath(tmp.name))
        os.chmod(self.tmp, 0o755)
        self.owner = pwd.getpwnam("nobody")
        self.home = str(self.tmp / "home")
        os.makedirs(self.home)
        os.chown(self.home, self.owner.pw_uid, self.owner.pw_gid)
        with open(os.path.join(self.home, "diary.txt"), "w") as f:
            f.write("private")
        state = self.tmp / "broker"
        self.jobs = JobRunner(state, owner_uid=self.owner.pw_uid, home=self.home, backend=NamespaceBackend(self.home, hidden=(str(state),)),
                              projects_dir=os.path.join(self.home, "StyNpilot-Projects"), version="9.9",
                              selftest_root=str(self.tmp / "run"), python="/usr/bin/python3")
        self.executor = Executor(state_dir=state, owner=OWNER, device=DEVICE,
                                 verifier=ProofVerifier(issuer=ISS, approval_client_id=APP, jwks=self.jwks),
                                 run=apt.real_run, require_root=False, owner_uid=self.owner.pw_uid, jobs=self.jobs)

    # The recording-based tests above do not apply here; the real path is one story.
    for _name in [n for n in dir(Door) if n.startswith("test_")]:
        locals()[_name] = None
    del _name

    def test_the_whole_story_with_real_isolation(self):
        # nothing runs before setup, and the first approval also runs the live self-test
        self.denied("runner_not_set_up", self.executor.runner_call, "run", {"workspace": "app", "recipe": "git-status"})
        setup = self.approve(self.payload())
        self.assertTrue(setup["ok"] and setup["selftest"]["ok"], setup)
        self.assertEqual(os.stat(os.path.join(self.home, "StyNpilot-Projects")).st_uid, self.owner.pw_uid)
        status = self.executor.runner_call("status", {})
        self.assertTrue(status["gate_open"])
        self.assertIn("git-status", status["recipes"])
        # authorizing a project creates the folder, owned by the owner
        enrolled = self.approve(self.payload("enroll", "app"))
        self.assertTrue(enrolled["ok"], enrolled)
        ws = os.path.join(self.home, "StyNpilot-Projects", "app")
        self.assertEqual(os.stat(ws).st_uid, self.owner.pw_uid)
        # a recipe runs in the sandbox and its output is readable
        subprocess.run(["git", "init", "-q", ws], check=True, capture_output=True)
        subprocess.run(["chown", "-R", "nobody", ws], check=True)
        started = self.executor.runner_call("run", {"workspace": "app", "recipe": "git-status", "args": []})
        done = None
        for _ in range(100):
            done = self.executor.runner_call("job_status", {"job_id": started["job_id"]})
            if done["state"] != "running":
                break
            time.sleep(0.1)
        out = self.executor.runner_call("job_output", {"job_id": started["job_id"]})
        self.assertEqual(done["state"], "done", out)
        self.assertEqual(done["workspace"], "app")
        self.assertIn("jobs", self.executor.runner_call("jobs", {"workspace": "app"}))
        # removing the authorization closes the workspace again
        gone = self.approve(self.payload("unenroll", "app"))
        self.assertTrue(gone["ok"])
        self.denied("workspace_not_enrolled", self.executor.runner_call, "run", {"workspace": "app", "recipe": "git-status"})

    def test_a_failed_selftest_leaves_the_runner_set_up_but_every_job_refused(self):
        self.jobs.python = "/nonexistent/python"
        setup = self.approve(self.payload())
        self.assertTrue(setup["ok"])
        self.assertFalse(setup["selftest"]["ok"])
        self.approve(self.payload("enroll", "app"))
        self.denied("sandbox_self_test_required", self.executor.runner_call, "run", {"workspace": "app", "recipe": "git-status"})


if __name__ == "__main__":
    unittest.main()
