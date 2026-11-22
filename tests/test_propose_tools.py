"""The YELLOW request tools through the real MCP server: two assistants, one owner, no approvals."""
import asyncio
import json
import tempfile
import time
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from stynpilot.identity import TokenDenied
from stynpilot.requests import RequestStore
from stynpilot.server.clients import EnrolledClients
from stynpilot.server.router import LocalOwnership, ReadRouter

try:
    from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
    from mcp.server.auth.provider import AccessToken
    from stynpilot.server.app import create_server
except ImportError:          # pragma: no cover - optional dependencies
    create_server = None

OWNER = "acct_" + "a" * 40
DEVICE = "dtdev_TESTONLYliveDevice"
AUDIENCE = "https://ryzen.example.test/mcp"
BOTH = frozenset({"health.read", "workspace.propose"})


@dataclass(frozen=True)
class Who:
    account: str
    scopes: frozenset
    client: str | None = None


class Tokens:
    issuer, audience = "https://issuer.example.test/", AUDIENCE
    valid = {
        "chatgpt": Who(OWNER, BOTH, "chatgpt-connector"),
        "claude": Who(OWNER, BOTH, "claude-connector"),
        "anon": Who(OWNER, BOTH, None),
        "reviewer": Who(OWNER, BOTH | {"workspace.review"}, "chatgpt-connector"),
        "readonly": Who(OWNER, frozenset({"health.read"}), "claude-connector"),
        "stranger": Who("acct_" + "b" * 40, BOTH, "chatgpt-connector"),
    }

    def authorize(self, header, required_scope):
        who = self.valid.get(header.removeprefix("Bearer "))
        if who is None or required_scope not in who.scopes:
            raise TokenDenied("denied")
        return who


class Grants:
    def __init__(self):
        self.scopes = BOTH

    def get(self, *, owner_id, device_id):
        if (owner_id, device_id) != (OWNER, DEVICE):
            return None
        return SimpleNamespace(owner_id=OWNER, device_id=DEVICE, revoked=False, scopes=self.scopes,
                               expires_at=time.time() + 3600)


@unittest.skipIf(create_server is None, "MCP SDK not installed")
class ProposeToolTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.grants = Grants()
        router = ReadRouter(tokens=Tokens(), ownership=LocalOwnership(grants=self.grants, owner_id=OWNER, device_id=DEVICE),
                            read_health=lambda: {"cpu_usage_percent": 1.0})
        self.clients = EnrolledClients([{"client_id": "chatgpt-connector", "name": "chatgpt", "kind": "chatgpt"},
                                        {"client_id": "claude-connector", "name": "claude", "kind": "claude"}])
        self.store = RequestStore(Path(tmp.name) / "state" / "requests.sqlite3")
        self.server = create_server(router=router, resource_url=AUDIENCE, propose=dict(
            clients=self.clients, store=self.store, resolve_apt={"htop": "3.3.0-4build1"}.get,
            approval_url="https://ryzen.example.test/app",
            clock=lambda: datetime.now(timezone.utc)))

    def call(self, name, arguments, token="chatgpt"):
        who = Tokens.valid.get(token)
        scopes = sorted(who.scopes) if who else ["health.read"]
        marker = auth_context_var.set(AuthenticatedUser(AccessToken(token=token, client_id="x", scopes=scopes)))
        try:
            result = asyncio.run(self.server.call_tool(name, arguments))
        finally:
            auth_context_var.reset(marker)
        if isinstance(result, tuple) and isinstance(result[1], dict) and "ok" in result[1]:
            return result[1]
        content = result[0] if isinstance(result, tuple) else result
        return json.loads(content[0].text)

    def install(self, token="chatgpt", software="htop"):
        return self.call("commander_request_software_install", {"device_id": DEVICE, "software": software}, token)

    def test_tools_listed_and_none_can_approve(self):
        names = sorted(t.name for t in asyncio.run(self.server.list_tools()))
        self.assertEqual(names, sorted(["computer_health", "commander_software_catalog",
                                        "commander_request_software_install", "commander_software_install_status",
                                        "commander_request_software_rollback"]))
        self.assertFalse(any(word in n for n in names for word in ("approve", "review", "execute", "run")))

    def test_chatgpt_asks_claude_checks_and_nobody_approves(self):
        filed = self.install()
        self.assertTrue(filed["ok"], filed)
        receipt = filed["result"]
        self.assertEqual((receipt["state"], receipt["requested_by"], receipt["approved_by_ai"]),
                         ("pending", "chatgpt", False))
        self.assertEqual(receipt["owner_approval_url"], "https://ryzen.example.test/app")
        self.assertIn("Package htop, exact version 3.3.0-4build1.", receipt["summary"])
        status = self.call("commander_software_install_status",
                           {"device_id": DEVICE, "request_id": receipt["request_id"]}, "claude")
        self.assertEqual(status["result"]["state"], "pending")
        self.assertEqual(self.install("claude")["result"]["request_id"], receipt["request_id"])   # same plan, one request

    def test_every_refusal(self):
        cases = {
            "anon": "client_identity_missing",
            "reviewer": "assistant_session_must_not_have_review_scope",
            "readonly": "not_authorized",
            "stranger": "device_unavailable_or_not_authorized",
            "nobody": "not_authorized",
        }
        for token, code in cases.items():
            with self.subTest(token):
                self.assertEqual(self.install(token), {"ok": False, "error": code})
        self.assertEqual(self.install(software="forgejo"), {"ok": False, "error": "already_installed_by_previous_build"})
        self.assertEqual(self.install(software="rm -rf /"), {"ok": False, "error": "unknown_software"})
        self.assertEqual(self.call("commander_request_software_install",
                                   {"device_id": DEVICE.replace("O", "0"), "software": "htop"}),
                         {"ok": False, "error": "device_unavailable_or_not_authorized"})
        self.grants.scopes = frozenset({"health.read"})            # owner hasn't granted propose to this device
        self.assertEqual(self.install(), {"ok": False, "error": "device_not_granted_propose"})
        import sqlite3
        with sqlite3.connect(self.store.path) as db:                # no refused call filed anything
            self.assertEqual(db.execute("SELECT COUNT(*) FROM requests").fetchone()[0], 0)

    def test_revoked_assistant_is_refused_while_the_other_keeps_working(self):
        self.clients.revoke("claude-connector")
        self.assertEqual(self.install("claude"), {"ok": False, "error": "client_not_enrolled_or_revoked"})
        self.assertTrue(self.install("chatgpt")["ok"])

    def test_rollback_request(self):
        filed = self.call("commander_request_software_rollback",
                          {"device_id": DEVICE, "software": "forgejo", "rollback_id": "ab" * 16})
        self.assertTrue(filed["ok"], filed)
        self.assertEqual((filed["result"]["kind"], filed["result"]["state"]), ("rollback", "pending"))
        for bad in ("", "../x", "AB" * 16, "short"):
            with self.subTest(bad=bad):
                self.assertEqual(self.call("commander_request_software_rollback",
                                           {"device_id": DEVICE, "software": "forgejo", "rollback_id": bad}),
                                 {"ok": False, "error": "invalid_rollback_id"})

    def test_catalog_listing_is_read_only_and_needs_no_propose(self):
        listing = self.call("commander_software_catalog", {}, "readonly")
        self.assertEqual({item["id"] for item in listing["software"]}, {"forgejo", "htop"})


if __name__ == "__main__":
    unittest.main()
