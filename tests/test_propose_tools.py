"""The YELLOW request tools through the real MCP server: two assistants, one owner, no approvals."""
import asyncio
import json
import os
import tempfile
import time
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from datetime import timedelta

from stynpilot.identity import TokenDenied
from stynpilot.ledger import InstallLedger
from stynpilot.requests import RequestStore
from stynpilot.server.clients import EnrolledClients, RevocationFile
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
        self.state = Path(tmp.name) / "state"
        self.enrolled = [{"client_id": "chatgpt-connector", "name": "chatgpt", "kind": "chatgpt"},
                         {"client_id": "claude-connector", "name": "claude", "kind": "claude"}]
        revocations = RevocationFile(self.state / "revoked-clients.json")
        revocations.provision()
        self.clients = EnrolledClients(self.enrolled, revocations=revocations)
        self.now = [datetime(2026, 11, 22, 17, 0, 5, tzinfo=timezone.utc)]
        self.store = RequestStore(self.state / "requests.sqlite3", clock=lambda: self.now[0].timestamp())
        self.ledger = InstallLedger(self.state / "installs.sqlite3", clock=lambda: self.now[0].timestamp())
        self.server = create_server(router=router, resource_url=AUDIENCE, propose=dict(
            clients=self.clients, store=self.store, ledger=self.ledger, resolve_apt=lambda names: [{"name": "htop", "version": "3.3.0-4build1"}, {"name": "libnl-3-200", "version": "3.7.0-0.3build1.1"}],
            approval_url="https://ryzen.example.test/app", clock=lambda: self.now[0]))

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

    def rollback(self, rollback_id, software="htop", token="chatgpt"):
        return self.call("commander_request_software_rollback",
                         {"device_id": DEVICE, "software": software, "rollback_id": rollback_id}, token)

    def test_rollback_only_for_a_recorded_install_with_a_verified_backup(self):
        """PR #10 review: a rollback ID must be a real StyNpilot install of that software on that device."""
        self.ledger.record(rollback_id="ab" * 16, software="htop", owner=OWNER, device=DEVICE,
                           request_id="c" * 64, snapshot_id="snap-1", snapshot_verified=True)
        self.ledger.record(rollback_id="cd" * 16, software="htop", owner=OWNER, device=DEVICE,
                           request_id="d" * 64, snapshot_id="snap-2", snapshot_verified=False)
        self.ledger.record(rollback_id="ef" * 16, software="htop", owner="acct_" + "b" * 40, device=DEVICE,
                           request_id="e" * 64, snapshot_id="snap-3", snapshot_verified=True)
        filed = self.rollback("ab" * 16)
        self.assertTrue(filed["ok"], filed)
        self.assertEqual((filed["result"]["kind"], filed["result"]["state"]), ("rollback", "pending"))
        self.assertIn("Roll back htop", filed["result"]["summary"][0])
        self.assertNotIn("verified restorable", " ".join(filed["result"]["summary"]))
        cases = {
            "invalid_rollback_id": ("", "../x", "AB" * 16, "short"),
            "unknown_rollback_id": ("99" * 16, "ef" * 16),            # nonexistent; another owner's install
            "no_verified_backup": ("cd" * 16,),
        }
        for code, ids in cases.items():
            for value in ids:
                with self.subTest(code=code, value=value):
                    self.assertEqual(self.rollback(value), {"ok": False, "error": code})
        self.assertEqual(self.rollback("ab" * 16, software="forgejo"),
                         {"ok": False, "error": "rollback_id_is_for_other_software"})
        self.assertEqual(self.rollback("99" * 16, software="forgejo"), {"ok": False, "error": "unknown_rollback_id"})

    # --- PR #10 review: one logical request, however many seconds or assistants later ------
    def test_asking_again_later_returns_the_original_request_and_expiry(self):
        first = self.install("chatgpt")["result"]
        for minutes, token in ((0.1, "chatgpt"), (5, "claude"), (59, "chatgpt")):
            with self.subTest(minutes=minutes, token=token):
                self.now[0] = datetime(2026, 11, 22, 17, 0, 5, tzinfo=timezone.utc) + timedelta(minutes=minutes)
                again = self.install(token)["result"]
                self.assertEqual(again["request_id"], first["request_id"])
                self.assertEqual(again["expires_at"], first["expires_at"])       # never silently extended
                self.assertEqual(again["requested_by"], "chatgpt")               # provenance kept
        import sqlite3
        with sqlite3.connect(self.store.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM requests").fetchone()[0], 1)
        self.now[0] = datetime(2026, 11, 22, 18, 1, tzinfo=timezone.utc)           # the first one expired
        fresh = self.install("claude")["result"]
        self.assertNotEqual(fresh["request_id"], first["request_id"])
        self.assertEqual(fresh["requested_by"], "claude")

    # --- PR #10 review: assistants may read each other's status, never more ---------------
    def test_assistants_can_read_each_others_status_but_revoked_or_strangers_cannot(self):
        rid = self.install("chatgpt")["result"]["request_id"]
        args = {"device_id": DEVICE, "request_id": rid}
        status = self.call("commander_software_install_status", args, "claude")["result"]
        self.assertEqual((status["state"], status["requested_by"]), ("pending", "chatgpt"))
        self.assertNotIn("payload", status)
        self.assertNotIn("steps", json.dumps(status))
        self.assertEqual(self.call("commander_software_install_status", args, "stranger"),
                         {"ok": False, "error": "device_unavailable_or_not_authorized"})
        self.clients.revoke("claude-connector")
        self.assertEqual(self.call("commander_software_install_status", args, "claude"),
                         {"ok": False, "error": "client_not_enrolled_or_revoked"})

    def test_deleting_the_revocation_file_never_restores_a_revoked_client(self):
        from stynpilot.server.clients import ClientDenied
        path = self.state / "revoked-clients.json"
        self.clients.revoke("claude-connector")
        os.unlink(path)                                              # attacker/accident deletes the list
        for registry in (self.clients, EnrolledClients(self.enrolled, revocations=RevocationFile(path))):   # live and after restart
            for who in ("claude", "chatgpt"):                        # everyone refused, nobody silently restored
                with self.assertRaises(ClientDenied) as caught:
                    registry.proposer(Tokens.valid[who])
                self.assertEqual(caught.exception.code, "client_state_unreadable")
        self.assertEqual(self.call("commander_software_install_status", {"device_id": DEVICE, "request_id": "a" * 64}, "claude"),
                         {"ok": False, "error": "client_state_unreadable"})
        self.assertFalse(path.exists())                              # a refused check must not re-create it
        # Owner recovery: provision again, then the revocation has to be made again on purpose.
        fresh = RevocationFile(path)
        self.assertTrue(fresh.provision())
        self.assertFalse(fresh.provision())                          # never overwrites an existing list
        registry = EnrolledClients(self.enrolled, revocations=fresh)
        self.assertEqual(registry.proposer(Tokens.valid["claude"]).name, "claude")
        registry.revoke("claude-connector")
        self.assertEqual(RevocationFile(path).revoked(), frozenset({"claude-connector"}))

    # --- PR #10 review: revocation survives a restart and fails closed ---------------------
    def test_revocation_survives_restart_and_bad_state_refuses_everyone(self):
        self.clients.revoke("claude-connector")
        restarted = EnrolledClients(self.enrolled, revocations=RevocationFile(self.state / "revoked-clients.json"))
        from stynpilot.server.clients import ClientDenied
        claude = Tokens.valid["claude"]
        with self.assertRaises(ClientDenied) as caught:
            restarted.proposer(claude)
        self.assertEqual(caught.exception.code, "client_not_enrolled_or_revoked")
        self.assertEqual(restarted.proposer(Tokens.valid["chatgpt"]).name, "chatgpt")
        path = self.state / "revoked-clients.json"
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        for breakage in ("world-readable", "corrupt", "wrong shape"):
            with self.subTest(breakage):
                if breakage == "world-readable":
                    os.chmod(path, 0o644)
                elif breakage == "corrupt":
                    os.chmod(path, 0o600)
                    path.write_text("{not json")
                else:
                    path.write_text(json.dumps({"revoked": "claude-connector"}))
                with self.assertRaises(ClientDenied) as caught:
                    restarted.proposer(Tokens.valid["chatgpt"])               # even the unrevoked one
                self.assertEqual(caught.exception.code, "client_state_unreadable")
                self.assertEqual(self.install("chatgpt"), {"ok": False, "error": "client_state_unreadable"})
        path.unlink()
        restarted.revocations.provision()                              # explicit owner recovery step
        restarted.reinstate("claude-connector")
        self.assertEqual(restarted.proposer(claude).name, "claude")

    def test_catalog_listing_is_read_only_and_needs_no_propose(self):
        listing = self.call("commander_software_catalog", {}, "readonly")
        self.assertEqual({item["id"] for item in listing["software"]}, {"forgejo", "htop"})


if __name__ == "__main__":
    unittest.main()
