"""Enrolled clients, the owner's request queue and the catalog (standard library only)."""
import os
import tempfile
import time
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from stynpilot import catalog, service_status
from stynpilot.requests import MAX_PENDING_PER_CLIENT, RequestError, RequestStore
from stynpilot.server.clients import ClientDenied, EnrolledClients, Proposer

OWNER, DEVICE = "acct_" + "a" * 40, "dtdev_TESTONLYliveDevice"
NOW = datetime(2026, 11, 22, 17, 0, tzinfo=timezone.utc)


@dataclass(frozen=True)
class Who:
    account: str
    scopes: frozenset
    client: str | None


def who(client="chatgpt-connector", scopes=("health.read", "workspace.propose")):
    return Who(OWNER, frozenset(scopes), client)


CLIENTS = [{"client_id": "chatgpt-connector", "name": "chatgpt", "kind": "chatgpt"},
           {"client_id": "claude-connector", "name": "claude", "kind": "claude"}]


class ClientTests(unittest.TestCase):
    def test_enrolled_client_may_propose(self):
        p = EnrolledClients(CLIENTS).proposer(who())
        self.assertEqual((p.client, p.name, p.kind, p.account), ("chatgpt-connector", "chatgpt", "chatgpt", OWNER))

    def test_refusals(self):
        clients = EnrolledClients(CLIENTS)
        cases = {
            "client_identity_missing": [who(client=None), who(client="unidentified-client")],
            "assistant_session_must_not_have_review_scope": [who(scopes=("health.read", "workspace.propose", "workspace.review"))],
            "insufficient_scope": [who(scopes=("health.read",))],
            "client_not_enrolled_or_revoked": [who(client="someone-else")],
        }
        for code, examples in cases.items():
            for example in examples:
                with self.subTest(code), self.assertRaises(ClientDenied) as caught:
                    clients.proposer(example)
                self.assertEqual(caught.exception.code, code)

    def test_revoking_one_assistant_leaves_the_other_working(self):
        clients = EnrolledClients(CLIENTS)
        clients.revoke("claude-connector")
        with self.assertRaises(ClientDenied):
            clients.proposer(who("claude-connector"))
        self.assertEqual(clients.proposer(who("chatgpt-connector")).name, "chatgpt")
        clients.reinstate("claude-connector")
        self.assertEqual(clients.proposer(who("claude-connector")).name, "claude")

    def test_bad_enrollment_lists(self):
        for bad in ([], [dict(CLIENTS[0], kind="robot")], [CLIENTS[0], CLIENTS[0]],
                    [dict(CLIENTS[0], client_id="unidentified-client")], [dict(CLIENTS[0], extra=1)]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                EnrolledClients(bad)


class RequestStoreTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.now = [1000.0]
        self.path = Path(tmp.name) / "private" / "requests.sqlite3"
        self.store = RequestStore(self.path, clock=lambda: self.now[0])
        self.chatgpt = Proposer("chatgpt-connector", "chatgpt", "chatgpt", OWNER)
        self.claude = Proposer("claude-connector", "claude", "claude", OWNER)

    def submit(self, payload, proposer=None, expires=5000.0):
        return self.store.submit(kind="install", software="htop", device=DEVICE, owner=OWNER,
                                 proposer=proposer or self.chatgpt, payload=payload,
                                 summary=["Install htop."], expires=expires)

    def test_same_plan_is_one_request_and_a_changed_plan_is_a_new_one(self):
        first, created = self.submit({"p": 1})
        again, created_again = self.submit({"p": 1}, proposer=self.claude)
        other, _ = self.submit({"p": 2})
        self.assertTrue(created)
        self.assertFalse(created_again)
        self.assertEqual(first["request_id"], again["request_id"])
        self.assertNotEqual(first["request_id"], other["request_id"])
        self.assertEqual((first["state"], first["requested_by"], first["approved_by_ai"]), ("pending", "chatgpt", False))
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_status_for_the_same_owner_only(self):
        rid = self.submit({"p": 1})[0]["request_id"]
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["state"], "pending")
        for owner, device, value in ((("acct_" + "b" * 40), DEVICE, rid), (OWNER, "dtdev_TESTONLYother000", rid),
                                     (OWNER, DEVICE, "0" * 64), (OWNER, DEVICE, "not-an-id")):
            with self.subTest(owner=owner[:8], device=device[-6:], value=value[:6]), self.assertRaises(RequestError):
                self.store.status(value, owner=owner, device=device)

    def test_requests_expire(self):
        rid = self.submit({"p": 1}, expires=1500.0)[0]["request_id"]
        self.now[0] = 1600.0
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["state"], "expired")
        with self.assertRaises(RequestError):
            self.submit({"p": 9}, expires=1500.0)

    def test_one_assistant_cannot_flood_the_owner(self):
        for n in range(MAX_PENDING_PER_CLIENT):
            self.submit({"p": n})
        with self.assertRaises(RequestError) as caught:
            self.submit({"p": "one too many"})
        self.assertEqual(caught.exception.code, "too_many_pending_requests")
        self.assertTrue(self.submit({"p": "other assistant"}, proposer=self.claude)[1])

    def test_store_has_no_ai_facing_way_to_approve(self):
        for name in dir(self.store):
            self.assertNotRegex(name.lower(), "approve|decide|grant|execute|run")

    def test_refuses_shared_file(self):
        os.chmod(self.path, 0o644)
        with self.assertRaises(RequestError):
            RequestStore(self.path)


class CatalogTests(unittest.TestCase):
    def test_apt_entry_becomes_one_exact_validated_plan(self):
        plan, summary = catalog.install_plan("htop", owner=OWNER, device=DEVICE,
                                             resolve_apt={"htop": "3.3.0-4build1"}.get, now=NOW)
        content = plan.content()
        self.assertEqual(content["steps"], [{"kind": "apt", "packages": [{"name": "htop", "version": "3.3.0-4build1"}]}])
        self.assertEqual((content["owner"], content["device"]), (OWNER, DEVICE))
        self.assertEqual(content["expires_at"], "2026-11-22T18:00:00Z")
        self.assertEqual(len(plan.plan_sha256), 64)
        self.assertIn("Package htop, exact version 3.3.0-4build1.", summary)

    def test_refusals(self):
        cases = {"unknown_software": dict(software="nmap", resolve_apt=str),
                 "already_installed_by_previous_build": dict(software="forgejo", resolve_apt=str),
                 "version_resolution_unavailable": dict(software="htop", resolve_apt=None),
                 "package_not_available": dict(software="htop", resolve_apt=lambda n: None)}
        for code, kw in cases.items():
            with self.subTest(code), self.assertRaises(catalog.CatalogError) as caught:
                catalog.install_plan(owner=OWNER, device=DEVICE, now=NOW, **kw)
            self.assertEqual(caught.exception.code, code)

    def test_listing_exposes_nothing_injectable(self):
        for item in catalog.listing():
            self.assertEqual(set(item), {"id", "title", "kind", "note"})

    def test_forgejo_status_facts_match_the_catalog(self):
        """The drift test promised in PR #7: the status checker and catalog can never disagree."""
        recipe, status = catalog.entry("forgejo")["legacy_recipe"], service_status.SERVICES["forgejo"]
        self.assertEqual((status["binary"], status["unit_name"], status["unit_path"], status["user"]),
                         (recipe["binary"], recipe["unit_name"], recipe["unit_path"], recipe["user"]))
        self.assertEqual((status["host"], status["port"]), recipe["listen"])
        self.assertEqual(status["catalog_version"], catalog.entry("forgejo")["version"])


if __name__ == "__main__":
    unittest.main()
