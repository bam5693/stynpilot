"""dev5: the upgrade worker checks that the local MCP endpoint really answers (not just that services are active)."""
import http.server
import json
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

from stynpilot import upgrade_worker
from stynpilot.upgrade_worker import endpoint_answers

import test_dev4_upgrade as _up

_Base, OLD, NEW = _up.WorkerTests, "0.1.0~dev3", "0.1.0~dev4"

TARGET = {"port": 8765, "host": "mcp.example.test"}


class Server:
    """A stand-in MCP endpoint whose answer the test chooses."""
    def __init__(self, status=401, challenge='Bearer scope="health.read"'):
        outer = self
        self.status, self.challenge, self.seen = status, challenge, []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.seen.append((self.path, self.headers.get("Host")))
                self.send_response(outer.status)
                if outer.challenge:
                    self.send_header("WWW-Authenticate", outer.challenge)
                self.end_headers()

            def log_message(self, *a):
                pass
        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class EndpointCheck(unittest.TestCase):
    def test_answers_only_for_a_401_bearer_challenge(self):
        for status, challenge, expected in ((401, 'Bearer scope="x"', True), (401, None, False), (200, None, False),
                                            (500, 'Bearer', False), (404, None, False), (403, 'Bearer', False)):
            server = Server(status, challenge)
            self.addCleanup(server.stop)
            self.assertIs(endpoint_answers({"port": server.port, "host": "mcp.example.test"}), expected, (status, challenge))
        self.assertEqual(server.seen[0], ("/mcp", "mcp.example.test"))

    def test_a_closed_port_or_junk_target_is_simply_not_answering(self):
        self.assertFalse(endpoint_answers({"port": 1, "host": "h"}, timeout=1))
        self.assertFalse(endpoint_answers({"port": "x", "host": "h"}))
        self.assertFalse(endpoint_answers({}))


class WorkerEndpointGate(unittest.TestCase):
    setUp = _Base.setUp
    run_job = _Base.run_job
    installs = _Base.installs

    def job(self, fn, **more):
        more.setdefault("endpoint", TARGET)
        more.setdefault("baseline_endpoint_ok", True)
        return self.run_job(endpoint_fn=fn, **more)

    def test_endpoint_answering_after_the_upgrade_passes(self):
        result = self.job(lambda target: True)
        self.assertTrue(result["ok"], result)

    def test_endpoint_that_comes_up_a_little_late_still_passes(self):
        calls = []
        result = self.job(lambda target: calls.append(1) or len(calls) >= 3)
        self.assertTrue(result["ok"], result)

    def test_a_dead_endpoint_on_the_new_version_rolls_back_and_the_old_one_is_verified(self):
        result = self.job(lambda target: self.system.version != NEW)       # works on dev3, dead on dev4
        self.assertEqual((result["ok"], result["rolled_back"], result["needs_owner_intervention"]), (False, True, False))
        self.assertEqual(result["stopped"], "health_check_failed")
        self.assertEqual(self.system.version, OLD)

    def test_an_endpoint_that_was_not_answering_before_is_not_blamed_on_the_upgrade(self):
        result = self.job(lambda target: False, baseline_endpoint_ok=False)
        self.assertTrue(result["ok"], result)

    def test_no_endpoint_configured_means_no_check(self):
        self.assertTrue(self.job(lambda target: False, endpoint=None)["ok"])

    def test_if_the_old_version_cannot_answer_either_the_owner_is_asked(self):
        result = self.job(lambda target: False)                            # baseline said it answered; now nothing does
        self.assertEqual((result["ok"], result["rolled_back"], result["needs_owner_intervention"]), (False, False, True))


class PrepareEndpointTarget(_up.UpgradeTests):
    """Reuses the upgrade fixtures; the inherited upgrade tests are switched off here (they run in their own file)."""
    def owner_config(self, text):
        home = self.tmp / "home"
        (home / ".config/stynpilot").mkdir(parents=True, exist_ok=True)
        (home / ".config/stynpilot/owner.json").write_text(text)
        return mock.patch("stynpilot.broker.upgrade.pwd.getpwuid", lambda uid: SimpleNamespace(pw_dir=str(home)))

    def test_target_comes_from_the_owner_settings(self):
        with self.owner_config(json.dumps({"mcp_port": 8123, "mcp_public_host": "mcp.example.test"})):
            self.assertEqual(self.executor.upgrader._endpoint_target(), {"port": 8123, "host": "mcp.example.test"})

    def test_bad_or_missing_settings_mean_no_target(self):
        for text in ("not json", "{}", json.dumps({"mcp_port": "80", "mcp_public_host": "h"}),
                     json.dumps({"mcp_port": 70000, "mcp_public_host": "h"}),
                     json.dumps({"mcp_port": 80, "mcp_public_host": ""})):
            with self.owner_config(text):
                self.assertIsNone(self.executor.upgrader._endpoint_target(), text)
        with mock.patch("stynpilot.broker.upgrade.pwd.getpwuid", side_effect=KeyError):
            self.assertIsNone(self.executor.upgrader._endpoint_target())


for _name in [n for n in dir(_up.UpgradeTests) if n.startswith("test_")]:
    setattr(PrepareEndpointTarget, _name, None)

del _Base, _up           # not test classes of this module

if __name__ == "__main__":
    unittest.main()
