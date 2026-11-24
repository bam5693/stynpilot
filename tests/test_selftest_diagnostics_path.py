"""The self-test's diagnostics must survive the WHOLE path an assistant sees: probe output -> verdict -> installer's _safe_selftest ->
GREEN socket answer -> MCP tool response, sanitized at each boundary. These run the real _judge, the real Executor and the real MCP tools."""
import os
import tempfile
import unittest
from pathlib import Path

import test_runner_tools as rt

DEVICE, OWNER, create_server = rt.DEVICE, rt.OWNER, rt.create_server

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from stynpilot.broker import apt
    from stynpilot.broker.executor import Executor
    from stynpilot.broker.proof import ProofVerifier
    from stynpilot.broker.selftest import OPTIONAL, REQUIRED, _judge
except ImportError:          # pragma: no cover
    Executor = None


class StubJobs:
    projects_dir, version = "/home/o/StyNpilot-Projects", "0.1.0.dev12"

    def __init__(self, verdict):
        self.verdict, self.is_enabled = verdict, True

    def reconcile(self):
        return 0

    def enabled(self):
        return self.is_enabled

    def workspaces(self):
        return []

    def selftest(self):
        return self.verdict

    def selftest_state(self):
        return self.verdict


def live_like_verdict(extra_state=None):
    """What the Ryzen would produce: every limit read, one of them wrong."""
    lines = ["PASS " + n for n in REQUIRED if n != "owner_edits_runner_files"] + ["PASS " + n for n in OPTIONAL if n != "limit_io"]
    lines += ["FAIL limit_io", "DIAG cgroup_path - :system.slice:stynpilot-job-x.service", "DIAG limit_pids 64 64",
              "DIAG limit_io 259:0:wbps=67108864 259:0:wbps=max", "DIAG limit_tmp 268439552 268435456", "DIAG evil /etc/shadow x"]
    verdict = _judge(lines, True, strict_limits=True)
    verdict.update({"ran": True, "version": "0.1.0.dev12", "at": 1})
    verdict.update(extra_state or {})
    return verdict


@unittest.skipIf(create_server is None or Executor is None, "needs the MCP SDK and cryptography")
class DiagnosticsReachTheAssistant(unittest.TestCase):
    def setUp(self):
        self.h = rt.RunnerToolTests("test_the_new_tools_are_listed_and_none_can_approve_or_run_a_free_command")
        self.h.setUp()                                   # the real MCP server with the real runner tools
        self.addCleanup(self.h.doCleanups)
        self.broker, self.call, self.d, self.authorize = self.h.broker, self.h.call, self.h.d, self.h.authorize
        self.keep = tempfile.TemporaryDirectory()
        self.addCleanup(self.keep.cleanup)
        self.install(live_like_verdict())

    @staticmethod
    def jwks():
        public = jwt.algorithms.RSAAlgorithm.to_jwk(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key(), as_dict=True)
        public.update(kid="k1", use="sig", alg="RS256")
        return {"keys": [public]}

    def install(self, verdict):
        self.executor = Executor(state_dir=Path(self.keep.name) / ("b%d" % id(verdict)), owner=OWNER, device=DEVICE,
                                 verifier=ProofVerifier(issuer="https://i.example.test/", approval_client_id="x", jwks=self.jwks()),
                                 run=apt.real_run, require_root=False, owner_uid=os.getuid(), jobs=StubJobs(verdict))
        self.broker.runner = lambda call, args=None: self.executor.runner_call(call, dict(args or {}))      # the GREEN socket, for real

    def check(self, selftest):
        self.assertEqual(selftest["failed"], ["limit_io"])
        self.assertEqual(selftest["unverified"], [])
        self.assertFalse(selftest["ok"])
        d = selftest["diagnostics"]
        self.assertEqual(d["limit_io"], {"expected": "259:0:wbps=67108864", "actual": "259:0:wbps=max"})
        self.assertEqual(d["limit_pids"], {"expected": "64", "actual": "64"})
        self.assertEqual(d["cgroup_path"]["actual"], ":system.slice:stynpilot-job-x.service")
        self.assertNotIn("evil", d)
        self.assertNotIn("/etc", str(selftest))

    def test_runner_status_carries_the_diagnostics_and_the_gate_stays_closed(self):
        out = self.call("runner_status", self.d())
        self.assertTrue(out["ok"], out)
        self.assertFalse(out["result"]["gate_open"])
        self.check(out["result"]["selftest"])

    def test_runner_selftest_carries_the_diagnostics(self):
        self.authorize()
        out = self.call("runner_selftest", self.d())
        self.assertTrue(out["ok"], out)
        self.check(out["result"])

    def test_the_installer_revalidates_what_the_state_file_holds(self):
        poisoned = live_like_verdict({"diagnostics": {"limit_io": {"expected": "ok", "actual": "x" * 500},
                                                      "limit_pids": {"expected": "64", "actual": "$(reboot)"},
                                                      "../../etc": {"expected": "1", "actual": "1"},
                                                      "limit_tmp": {"expected": "1", "actual": "2"}}})
        self.install(poisoned)
        d = self.call("runner_status", self.d())["result"]["selftest"]["diagnostics"]
        self.assertEqual(d, {"limit_tmp": {"expected": "1", "actual": "2"}})

    def test_under_systemd_a_limit_that_could_not_be_seen_is_unverified_and_still_closes_the_gate(self):
        lines = ["PASS " + n for n in REQUIRED if n != "owner_edits_runner_files"] + ["SKIP limits"]
        verdict = _judge(lines, True, strict_limits=True)
        self.assertFalse(verdict["ok"])                                          # gate closed
        self.assertEqual(verdict["unverified"], sorted(OPTIONAL))                # and honestly reported as not seen
        self.assertEqual(verdict["failed"], sorted(OPTIONAL))
        relaxed = _judge(lines, True, strict_limits=False)                       # without systemd the old rule still holds
        self.assertTrue(relaxed["ok"])
        self.assertEqual(relaxed["unverified"], sorted(OPTIONAL))
        verdict.update({"ran": True, "version": "0.1.0.dev12", "at": 1})
        self.install(verdict)
        got = self.call("runner_status", self.d())["result"]
        self.assertFalse(got["gate_open"])
        self.assertEqual(got["selftest"]["unverified"], sorted(OPTIONAL))


if __name__ == "__main__":
    unittest.main()
