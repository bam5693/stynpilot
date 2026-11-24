"""dev3: the OAuth challenge names the scopes, and a request tool called without workspace.propose gets a standard
insufficient_scope challenge. Nothing is admitted by this layer; every check below the wrapper is unchanged."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from starlette.testclient import TestClient
    from stynpilot.server import run
except Exception:                                    # pragma: no cover - MCP SDK extra not installed
    run = None

import test_propose_tools as t
from stynpilot.ledger import InstallLedger
from stynpilot.requests import RequestStore
from stynpilot.server.clients import EnrolledClients, RevocationFile
from stynpilot.server.router import LocalOwnership, ReadRouter

HOST = "ryzen.example.ts.net"
ACCEPT = {"accept": "application/json, text/event-stream", "content-type": "application/json"}


def call(name, args=None, rid=1):
    return {"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": {"name": name, "arguments": args or {}}}


@unittest.skipIf(run is None, "MCP SDK not installed")
class ChallengeTests(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        tokens = t.Tokens()
        tokens.audience = "https://%s/mcp" % HOST
        self.tokens = tokens
        router = ReadRouter(tokens=tokens, ownership=LocalOwnership(grants=t.Grants(), owner_id=t.OWNER, device_id=t.DEVICE),
                            read_health=lambda: {"cpu_usage_percent": 1.0})
        rev = RevocationFile(tmp / "r.json")
        rev.provision()
        clients = EnrolledClients([{"client_id": "chatgpt-connector", "name": "chatgpt", "kind": "chatgpt"}], revocations=rev)
        self.propose = dict(clients=clients, store=RequestStore(tmp / "q.sqlite3"), ledger=InstallLedger(tmp / "i.sqlite3"),
                            resolve_apt=lambda names: [], approval_url="https://x.example.test/app")
        self.client = self.make(self.propose)

    def make(self, propose):
        app = run.build_app(router=ReadRouter(tokens=self.tokens, ownership=LocalOwnership(
            grants=t.Grants(), owner_id=t.OWNER, device_id=t.DEVICE), read_health=lambda: {"cpu_usage_percent": 1.0}),
            public_host=HOST, port=18443, propose=propose)
        client = TestClient(app, base_url="https://%s" % HOST)
        client.__enter__()                              # runs the app's lifespan (the MCP session manager)
        self.addCleanup(client.__exit__, None, None, None)
        return client

    def post(self, body, token="readonly", client=None, headers=None, raw=None):
        h = {**ACCEPT, **({"authorization": "Bearer " + token} if token else {}), **(headers or {})}
        c = client or self.client
        return c.post("/mcp", content=raw if raw is not None else json.dumps(body), headers=h)

    def test_the_401_challenge_names_both_scopes_and_the_metadata_url(self):
        r = self.post(call("computer_health", {"device_id": t.DEVICE}), token=None)
        self.assertEqual(r.status_code, 401)
        header = r.headers["www-authenticate"]
        self.assertIn('scope="health.read workspace.propose"', header)
        self.assertIn("resource_metadata=", header)
        self.assertEqual(header.count("scope="), 1)

    def test_read_only_build_names_only_the_read_scope_and_never_steps_up(self):
        client = self.make(None)
        r = self.post(call("computer_health", {"device_id": t.DEVICE}), token=None, client=client)
        self.assertIn('scope="health.read"', r.headers["www-authenticate"])
        self.assertNotIn("workspace.propose", r.headers["www-authenticate"])

    def test_request_tools_without_the_scope_get_a_standard_step_up_challenge(self):
        for name in ("commander_request_software_install", "commander_software_install_status",
                     "commander_request_software_rollback"):
            with self.subTest(name):
                r = self.post(call(name, {"device_id": t.DEVICE}))
                self.assertEqual(r.status_code, 403)
                header = r.headers["www-authenticate"]
                self.assertIn('error="insufficient_scope"', header)
                self.assertIn('scope="health.read workspace.propose"', header)
                self.assertEqual(r.json()["error"], "insufficient_scope")

    def test_green_tools_are_never_stepped_up(self):
        for name in ("computer_health", "commander_software_search", "commander_software_catalog"):
            with self.subTest(name):
                r = self.post(call(name, {"device_id": t.DEVICE, "query": "ncdu"}))
                self.assertNotIn(r.status_code, (401, 403))

    def test_a_token_with_the_scope_passes_through_to_the_tool(self):
        r = self.post(call("commander_software_install_status", {"device_id": t.DEVICE, "request_id": "a" * 64}),
                      token="claude")
        self.assertNotIn(r.status_code, (401, 403))

    def test_a_batch_with_one_request_tool_is_stepped_up(self):
        r = self.post([call("computer_health", {"device_id": t.DEVICE}, 1),
                       call("commander_request_software_install", {"device_id": t.DEVICE}, 2)])
        self.assertEqual(r.status_code, 403)

    def test_unverifiable_tokens_still_get_the_plain_401_not_a_step_up(self):
        for token in ("nobody", None):
            with self.subTest(token):
                r = self.post(call("commander_request_software_install", {"device_id": t.DEVICE}), token=token)
                self.assertEqual(r.status_code, 401)
                self.assertNotIn("insufficient_scope", r.headers["www-authenticate"])

    def test_doubtful_requests_pass_through_unchanged(self):
        # malformed JSON, a body over the limit, and a foreign Host are not ours to answer: the SDK decides
        self.assertNotEqual(self.post(None, raw="{not json").status_code, 403)
        big = json.dumps(call("commander_request_software_install", {"pad": "x" * (run.MAX_STEP_UP_BODY + 10)}))
        self.assertNotEqual(self.post(None, raw=big).status_code, 403)
        r = self.post(call("commander_request_software_install", {"device_id": t.DEVICE}), headers={"host": "evil.test"})
        self.assertNotEqual(r.status_code, 403)

    def test_the_metadata_document_is_unchanged(self):
        r = self.client.get("/.well-known/oauth-protected-resource/mcp")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["scopes_supported"], ["health.read", "workspace.propose"])


if __name__ == "__main__":
    unittest.main()
