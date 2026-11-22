"""Router checks (stdlib) and the real MCP server tools (needs [server] extras)."""
import asyncio
import json
import time
import unittest
from dataclasses import dataclass
from types import SimpleNamespace

from stynpilot.identity import TokenDenied
from stynpilot.server.router import AccessDenied, LocalOwnership, ReadRouter

try:
    from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
    from mcp.server.auth.provider import AccessToken
    from stynpilot.server.app import create_server
except ImportError:          # pragma: no cover - optional dependencies
    create_server = None

DEVICE = "dtdev_TESTONLYfakeDevice01"  # fictional; never a real ID in this public repo
AUDIENCE = "https://ryzen.example.test/mcp"


@dataclass(frozen=True)
class Who:
    account: str
    scopes: frozenset
    client: str | None = None


class Tokens:
    issuer, audience = "https://issuer.example.test/", AUDIENCE

    def __init__(self):
        self.valid = {"good": Who("acct_owner", frozenset({"health.read"}), "chatgpt-connector"),
                      "claude": Who("acct_owner", frozenset({"health.read"}), "claude-connector"),
                      "anon": Who("acct_owner", frozenset({"health.read"}))}

    def authorize(self, header, required_scope):
        who = self.valid.get(header.removeprefix("Bearer "))
        if who is None or required_scope not in who.scopes:
            raise TokenDenied("denied")
        return who


class Grants:
    def __init__(self):
        self.grant = SimpleNamespace(owner_id="acct_owner", device_id=DEVICE, revoked=False,
                                     scopes=frozenset({"health.read"}), expires_at=time.time() + 3600)

    def get(self, *, owner_id, device_id):
        return self.grant if (owner_id, device_id) == ("acct_owner", DEVICE) else None


class RouterTests(unittest.TestCase):
    def setUp(self):
        self.grants, self.reads = Grants(), []
        self.ownership = LocalOwnership(grants=self.grants, owner_id="acct_owner", device_id=DEVICE)

        def status(software):
            self.reads.append(software)
            if software != "forgejo":
                raise KeyError("unknown_software")
            return {"state": "running"}
        self.router = ReadRouter(tokens=Tokens(), ownership=self.ownership,
                                 read_health=lambda: {"cpu_usage_percent": 3.0, "memory_used_percent": 400.0},
                                 read_service_status=status)

    def test_health_keeps_only_in_range_metrics(self):
        self.assertEqual(self.router.health(authorization_header="Bearer good", device_id=DEVICE),
                         {"cpu_usage_percent": 3.0})

    def test_status_for_owner(self):
        self.assertEqual(self.router.service_status(authorization_header="Bearer good", device_id=DEVICE,
                                                    software="forgejo"), {"state": "running"})

    def test_every_refusal_happens_before_anything_is_read(self):
        cases = {
            "confusable lookalike ID": ("Bearer good", DEVICE.replace("O", "0")),
            "stolen token": ("Bearer stolen", DEVICE),
            "bad device shape": ("Bearer good", "../../etc"),
        }
        for label, (header, device) in cases.items():
            with self.subTest(label), self.assertRaises(AccessDenied):
                self.router.service_status(authorization_header=header, device_id=device, software="forgejo")
        for field, value in (("revoked", True), ("expires_at", time.time() - 1), ("scopes", frozenset())):
            with self.subTest(field):
                setattr(self.grants.grant, field, value)
                with self.assertRaises(AccessDenied):
                    self.router.service_status(authorization_header="Bearer good", device_id=DEVICE, software="forgejo")
                self.grants = Grants()
                self.ownership.grants = self.grants
        self.assertEqual(self.reads, [])

    def test_revoked_during_read_is_caught_on_recheck(self):
        def status(software):
            self.grants.grant.revoked = True
            return {"state": "running"}
        self.router.read_service_status = status
        with self.assertRaises(AccessDenied):
            self.router.service_status(authorization_header="Bearer good", device_id=DEVICE, software="forgejo")


@unittest.skipIf(create_server is None, "MCP SDK not installed")
class ServerTests(unittest.TestCase):
    def setUp(self):
        grants = Grants()
        ownership = LocalOwnership(grants=grants, owner_id="acct_owner", device_id=DEVICE)
        self.router = ReadRouter(tokens=Tokens(), ownership=ownership,
                                 read_health=lambda: {"cpu_usage_percent": 1.0},
                                 read_service_status=lambda s: {"state": "running_setup_required"}
                                 if s == "forgejo" else (_ for _ in ()).throw(KeyError(s)))
        self.server = create_server(router=self.router, resource_url=AUDIENCE)

    def call(self, name, arguments, token="good", scopes=("health.read",)):
        marker = auth_context_var.set(AuthenticatedUser(AccessToken(token=token, client_id="x", scopes=list(scopes))))
        try:
            result = asyncio.run(self.server.call_tool(name, arguments))
        finally:
            auth_context_var.reset(marker)
        if isinstance(result, tuple) and isinstance(result[1], dict) and "ok" in result[1]:
            return result[1]
        content = result[0] if isinstance(result, tuple) else result
        return json.loads(content[0].text)

    def test_tools_are_listed_read_only(self):
        tools = {t.name: t for t in asyncio.run(self.server.list_tools())}
        self.assertEqual(sorted(tools), ["computer_health", "software_service_status"])
        for tool in tools.values():
            self.assertTrue(tool.annotations.readOnlyHint)
            self.assertFalse(tool.annotations.destructiveHint)
            self.assertNotIn("approve", tool.name)

    def test_calls(self):
        self.assertEqual(self.call("computer_health", {"device_id": DEVICE})["metrics"], {"cpu_usage_percent": 1.0})
        self.assertEqual(self.call("software_service_status", {"device_id": DEVICE, "software": "forgejo"})
                         ["status"]["state"], "running_setup_required")
        self.assertEqual(self.call("software_service_status", {"device_id": DEVICE, "software": "nope"}),
                         {"ok": False, "error": "unknown_software"})
        refused = {"ok": False, "error": "device_unavailable_or_not_authorized"}
        self.assertEqual(self.call("computer_health", {"device_id": DEVICE}, scopes=("openid",)), refused)
        self.assertEqual(self.call("computer_health", {"device_id": DEVICE}, token="stolen"), refused)

    def test_sdk_identity_keeps_client_and_owner_apart(self):
        from stynpilot.server.app import UNIDENTIFIED_CLIENT, _SDKTokenVerifier
        verify = _SDKTokenVerifier(self.router).verify_token
        chatgpt, claude, anon = (asyncio.run(verify(t)) for t in ("good", "claude", "anon"))
        self.assertEqual((chatgpt.client_id, chatgpt.subject), ("chatgpt-connector", "acct_owner"))
        self.assertEqual((claude.client_id, claude.subject), ("claude-connector", "acct_owner"))
        self.assertEqual(anon.client_id, UNIDENTIFIED_CLIENT)
        self.assertIsNone(asyncio.run(verify("stolen")))
        # Both AI clients may read the same owner's device.
        self.assertTrue(self.call("computer_health", {"device_id": DEVICE}, token="claude")["ok"])

    def test_no_status_tool_without_reader_and_resource_must_match(self):
        plain = ReadRouter(tokens=Tokens(), ownership=self.router.ownership, read_health=dict)
        self.assertEqual([t.name for t in asyncio.run(create_server(router=plain, resource_url=AUDIENCE).list_tools())],
                         ["computer_health"])
        for resource in (AUDIENCE + "/", "https://other.test/mcp", "http://ryzen.example.test/mcp"):
            with self.subTest(resource), self.assertRaises(ValueError):
                create_server(router=plain, resource_url=resource)


if __name__ == "__main__":
    unittest.main()
