"""G5 approval flow against the REAL root executor (fake machine): what the owner is shown, explicit
approve/deny, PKCE/state/CSRF, one decision per request, and status/result wiring."""
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

try:
    import jwt
    from stynpilot.approval import ApprovalError, ApprovalFlow, pkce_challenge
    from stynpilot.broker.executor import ExecutionDenied
    from stynpilot.broker.proof import render_summary
except ImportError:          # pragma: no cover
    jwt = None

import test_broker as tb
from test_broker import APP, DEVICE, ISS, OWNER, SUB
from stynpilot.requests import RequestStore, request_id


class SimpleNamespaceError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class ApprovalTests(unittest.TestCase):
    setUpClass = classmethod(tb.BrokerTests.setUpClass.__func__)
    plan = tb.BrokerTests.plan
    proof = tb.BrokerTests.proof
    other_expiry = staticmethod(tb.BrokerTests.other_expiry)

    def setUp(self):
        tb.BrokerTests.setUp(self)
        self.store = RequestStore(self.tmp / "state" / "requests.sqlite3")
        self.code_verifiers, self.token_nonce = [], None
        self.flow = self.make_flow()

    def make_flow(self, store=None):
        return ApprovalFlow(store=store or self.store, broker=self.executor, exchange=self.exchange,
                            authorize={"endpoint": "https://issuer.example.test/authorize", "client_id": APP,
                                       "redirect_uri": "https://computer.example.test/approve/callback"})

    def exchange(self, code, verifier):
        """Stand-in for Auth0: checks PKCE and signs a fresh-login ID token with the nonce it was given."""
        self.assertEqual(pkce_challenge(verifier), self.last_params["code_challenge"])
        now = int(time.time())
        nonce = self.token_nonce or self.last_params["nonce"]
        return jwt.encode({"iss": ISS, "aud": APP, "sub": SUB, "iat": now, "exp": now + 300, "auth_time": now,
                           "nonce": nonce}, self.key, algorithm="RS256", headers={"kid": "k1"})

    def file(self, kind="install", payload=None):
        payload = payload or self.plan()
        proposer = SimpleNamespace(client="chatgpt-connector", name="chatgpt")
        receipt, _ = self.store.submit(kind=kind, software="htop", device=DEVICE, owner=OWNER, proposer=proposer,
                                       payload=payload, summary=["ask"], expires=time.time() + 3000)
        return payload, receipt["request_id"]

    @staticmethod
    def brief(outcome):
        return {k: v for k, v in outcome.items() if k != "request_id"}

    def decide(self, rid, decision, **tamper):
        shown = self.flow.page(rid)
        started = self.flow.choose(shown["view"], tamper.get("csrf", shown["csrf"]), decision)
        self.last_params = started["params"]
        return shown, started, lambda: self.flow.finish(started["params"]["state"], "auth0-code")

    # --- what the owner sees ----------------------------------------------------------------------
    def test_page_shows_the_root_written_summary_with_the_backup_limits(self):
        payload, rid = self.file()
        shown = self.flow.page(rid)
        self.assertEqual(shown["summary"], render_summary(payload))             # from the root, not the AI request
        text = " ".join(shown["summary"])
        self.assertIn("htop", text)
        self.assertIn("not a full system snapshot", text)
        self.assertEqual(shown["choices"], ["approve", "deny"])
        self.assertEqual(self.machine.changes(), [])

    def test_only_pending_requests_can_be_shown(self):
        payload, rid = self.file()
        self.store.transition(rid, "pending", "denied")
        with self.assertRaises(ApprovalError) as caught:
            self.flow.page(rid)
        self.assertEqual(caught.exception.code, "request_not_pending")
        with self.assertRaises(ApprovalError):
            self.flow.page("f" * 64)

    # --- approve ----------------------------------------------------------------------------------
    def test_explicit_approve_runs_the_install_and_status_shows_done(self):
        payload, rid = self.file()
        shown, started, finish = self.decide(rid, "approve")
        p = started["params"]
        self.assertEqual((p["code_challenge_method"], p["prompt"], p["max_age"], p["response_type"]),
                         ("S256", "login", "0", "code"))
        self.assertEqual(self.machine.changes(), [])                            # nothing before the sign-in comes back
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["state"], "pending")
        outcome = finish()
        self.assertEqual(self.brief(outcome), {"state": "done", "ok": True})
        self.assertIn("htop", self.machine.installed)
        status = self.store.status(rid, owner=OWNER, device=DEVICE)
        self.assertEqual(status["state"], "done")
        self.assertTrue(status["result"]["rollback_id"])
        self.assertNotIn("proof", json.dumps(status))
        self.assertIs(status["approved_by_ai"], False)

    def test_a_plain_login_or_a_token_for_the_other_decision_is_not_approval(self):
        for label, nonce in (("plain login", "whatever-the-login-page-sent"), ("deny's nonce", None)):
            with self.subTest(label):
                self.setUp()
                payload, rid = self.file()
                shown = self.flow.page(rid)
                started = self.flow.choose(shown["view"], shown["csrf"], "approve")
                self.last_params = started["params"]
                if nonce is None:                                               # token minted for the DENY challenge
                    nonce = self.executor.runs and self.deny_nonce(payload)
                self.token_nonce = nonce
                outcome = self.flow.finish(started["params"]["state"], "code")
                self.assertEqual(self.brief(outcome), {"state": "failed", "ok": False})
                self.assertEqual(self.machine.changes(), [])
                self.assertNotIn("htop", self.machine.installed)
                result = self.store.status(rid, owner=OWNER, device=DEVICE)["result"]
                self.assertEqual((result["stopped"], result["changed_anything"]),
                                 ("proof_is_for_a_different_decision", False))

    def deny_nonce(self, payload):
        from stynpilot.broker.proof import decision_nonce
        rid = request_id(payload)[0]
        return decision_nonce("deny", rid, rid, self.executor.challenge(payload, "deny")["challenge"])

    # --- deny -------------------------------------------------------------------------------------
    def test_deny_never_installs_and_cannot_be_turned_into_approval(self):
        payload, rid = self.file()
        shown, started, finish = self.decide(rid, "deny")
        self.assertEqual(self.brief(finish()), {"state": "denied", "recorded_by_installer": True})
        self.assertEqual(self.machine.changes(), [])
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["state"], "denied")
        with self.assertRaises(ApprovalError):                                  # no second chance on the same request
            self.flow.page(rid)
        with self.assertRaises(ExecutionDenied):                                # installer refuses it too
            self.executor.challenge(payload, "approve")

    # --- sign-in hygiene: state, CSRF, single use ------------------------------------------------------
    def test_csrf_state_and_single_use_checks(self):
        payload, rid = self.file()
        shown = self.flow.page(rid)
        for bad in ("", "wrong", None):
            with self.assertRaises(ApprovalError) as caught:
                self.flow.choose(shown["view"], bad, "approve")
            self.assertEqual(caught.exception.code, "csrf_check_failed")
        with self.assertRaises(ApprovalError) as caught:
            self.flow.choose("no-such-view", shown["csrf"], "approve")
        self.assertEqual(caught.exception.code, "page_expired")
        with self.assertRaises(ApprovalError):
            self.flow.choose(shown["view"], shown["csrf"], "maybe")
        started = self.flow.choose(shown["view"], shown["csrf"], "approve")
        with self.assertRaises(ApprovalError) as caught:                        # second click on the same page
            self.flow.choose(shown["view"], shown["csrf"], "deny")
        self.assertEqual(caught.exception.code, "already_chosen")
        for bad_state in ("", "forged", None):
            with self.assertRaises(ApprovalError) as caught:
                self.flow.finish(bad_state, "code")
            self.assertEqual(caught.exception.code, "unknown_or_used_state")
        self.last_params = started["params"]
        self.assertEqual(self.flow.finish(started["params"]["state"], "code")["state"], "done")
        with self.assertRaises(ApprovalError) as caught:                        # replayed callback
            self.flow.finish(started["params"]["state"], "code")
        self.assertEqual(caught.exception.code, "unknown_or_used_state")
        self.assertEqual(len([c for c in self.machine.changes() if c[1] == "install"]), 1)

    def test_sign_in_failure_changes_nothing_and_the_request_stays_pending(self):
        payload, rid = self.file()
        shown = self.flow.page(rid)
        started = self.flow.choose(shown["view"], shown["csrf"], "approve")
        self.flow.exchange = lambda code, verifier: (_ for _ in ()).throw(RuntimeError("auth0 down"))
        with self.assertRaises(ApprovalError) as caught:
            self.flow.finish(started["params"]["state"], "code")
        self.assertEqual(caught.exception.code, "sign_in_failed")
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["state"], "pending")
        self.assertEqual(self.machine.changes(), [])

    def test_two_approval_pages_for_one_request_decide_only_once(self):
        payload, rid = self.file()
        first = self.flow.page(rid)
        second = self.flow.page(rid)
        a = self.flow.choose(first["view"], first["csrf"], "approve")
        b = self.flow.choose(second["view"], second["csrf"], "approve")
        self.last_params = a["params"]
        self.assertEqual(self.flow.finish(a["params"]["state"], "c")["state"], "done")
        self.last_params = b["params"]
        with self.assertRaises(ApprovalError) as caught:
            self.flow.finish(b["params"]["state"], "c")
        self.assertEqual(caught.exception.code, "request_not_pending")
        self.assertEqual(len([c for c in self.machine.changes() if c[1] == "install"]), 1)

    # --- results, restarts and interrupted runs ----------------------------------------------------------
    def test_installer_that_needs_the_owner_is_reflected_in_the_request_status(self):
        payload, rid = self.file()
        self.machine.fail_state_while_installed = "htop"
        self.machine.fail_remove = True
        shown, started, finish = self.decide(rid, "approve")
        self.assertEqual(self.brief(finish()), {"state": "needs_owner_intervention", "ok": False})
        status = self.store.status(rid, owner=OWNER, device=DEVICE)
        self.assertEqual(status["state"], "needs_owner_intervention")
        self.assertIs(status["result"]["needs_owner_intervention"], True)

    def test_installer_refusal_before_any_change_shows_failed(self):
        payload, rid = self.file()
        shown, started, finish = self.decide(rid, "approve")
        self.machine.origin["htop"] = "Evil"
        self.assertEqual(self.brief(finish()), {"state": "failed", "ok": False})
        status = self.store.status(rid, owner=OWNER, device=DEVICE)
        self.assertEqual((status["state"], status["result"]["changed_anything"]), ("failed", False))

    # --- reconciliation with the installer's own record -----------------------------------------------
    def drop_connection_after(self, method):
        """A broker whose call completes at the root but whose reply never arrives."""
        executor = self.executor

        class Dropping:
            challenge = staticmethod(executor.challenge)
            status = staticmethod(executor.status)
            deny = staticmethod(executor.deny)
            rollback = staticmethod(executor.rollback)
            install = staticmethod(executor.install)

        def dropped(*args, **kwargs):
            getattr(executor, method)(*args, **kwargs)                 # it ran at the root...
            raise SimpleNamespaceError("installer_unavailable")        # ...but we never heard back
        setattr(Dropping, method, staticmethod(dropped))
        self.flow.broker = Dropping

    def test_connection_drop_after_the_root_finished_is_reconciled_not_reported_as_nothing_changed(self):
        payload, rid = self.file()
        shown, started, finish = self.decide(rid, "approve")
        self.drop_connection_after("install")
        self.assertEqual(self.brief(finish()), {"state": "done", "ok": True})
        status = self.store.status(rid, owner=OWNER, device=DEVICE)
        self.assertEqual(status["state"], "done")
        self.assertTrue(status["result"]["rollback_id"])
        self.assertIn("htop", self.machine.installed)

    def test_connection_drop_when_the_root_state_is_unknown_asks_the_owner_to_verify(self):
        payload, rid = self.file()
        shown, started, finish = self.decide(rid, "approve")

        class Gone:
            @staticmethod
            def install(*a):
                raise SimpleNamespaceError("installer_unavailable")

            @staticmethod
            def status(*a):
                raise SimpleNamespaceError("installer_unavailable")
        self.flow.broker = Gone
        self.assertEqual(self.brief(finish()), {"state": "needs_owner_intervention", "ok": False})
        result = self.store.status(rid, owner=OWNER, device=DEVICE)["result"]
        self.assertEqual((result["stopped"], result["changed_anything"]), ("installer_unreachable_owner_must_verify", None))

    def test_connection_drop_before_the_root_received_it_is_reported_as_nothing_ran(self):
        payload, rid = self.file()
        shown, started, finish = self.decide(rid, "approve")
        executor = self.executor

        class NeverArrived:
            status = staticmethod(executor.status)

            @staticmethod
            def install(*a):
                raise SimpleNamespaceError("installer_unavailable")
        self.flow.broker = NeverArrived
        self.assertEqual(self.brief(finish()), {"state": "failed", "ok": False})
        result = self.store.status(rid, owner=OWNER, device=DEVICE)["result"]
        self.assertEqual((result["stopped"], result["changed_anything"]), ("installer_never_received_it", False))

    def in_flight(self, rid):
        self.store.transition(rid, "pending", "approved")
        self.store.transition(rid, "approved", "running")

    def test_restart_reconciles_a_run_the_root_finished_while_the_owner_service_was_down(self):
        payload, rid = self.file()
        challenge, token = self.approval_for(payload)
        self.assertTrue(self.executor.install(payload, token, challenge)["ok"])           # root completed
        self.in_flight(rid)                                                              # owner service died before noting it
        restarted = self.make_flow(RequestStore(self.tmp / "state" / "requests.sqlite3"))
        self.assertEqual(restarted.recover(), [rid])
        status = restarted.store.status(rid, owner=OWNER, device=DEVICE)
        self.assertEqual(status["state"], "done")
        self.assertTrue(status["result"]["rollback_id"])
        self.assertEqual(restarted.recover(), [])

    def approval_for(self, payload):
        challenge = self.executor.challenge(payload, "approve")["challenge"]
        return challenge, self.proof(payload, challenge)

    def test_restart_marks_a_run_the_root_never_saw_as_failed_and_an_unknown_one_for_the_owner(self):
        payload, rid = self.file()
        self.in_flight(rid)                                                              # root has no record at all
        restarted = self.make_flow(RequestStore(self.tmp / "state" / "requests.sqlite3"))
        self.assertEqual(restarted.recover(), [rid])
        status = restarted.store.status(rid, owner=OWNER, device=DEVICE)
        self.assertEqual((status["state"], status["result"]["stopped"]), ("failed", "installer_never_received_it"))
        self.setUp()
        payload, rid = self.file()
        challenge, _ = self.approval_for(payload)
        self.executor.runs.consume(challenge=challenge, request_id=rid, decision="approve", proof="p" * 64, kind="install")
        self.in_flight(rid)                                                              # root says "running": crashed mid-way
        restarted = self.make_flow(RequestStore(self.tmp / "state" / "requests.sqlite3"))
        restarted.recover()
        self.assertEqual(restarted.store.status(rid, owner=OWNER, device=DEVICE)["state"], "needs_owner_intervention")

    def test_restart_with_the_installer_unreachable_marks_requests_for_the_owner(self):
        payload, rid = self.file()
        self.in_flight(rid)
        flow = self.make_flow()

        class Gone:
            @staticmethod
            def status(*a):
                raise SimpleNamespaceError("installer_unavailable")
        flow.broker = Gone
        flow.recover()
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["state"], "needs_owner_intervention")

    # --- the summary is the root's, and tampering in transit is detected ------------------------------------
    def test_a_summary_altered_in_transit_is_not_shown(self):
        payload, rid = self.file()
        real = self.executor

        class Tampering:
            @staticmethod
            def challenge(payload, decision):
                reply = dict(real.challenge(payload, decision))
                reply["summary"] = ["Install a harmless clock widget."] + reply["summary"][1:]
                return reply
        self.flow.broker = Tampering
        with self.assertRaises(ApprovalError) as caught:
            self.flow.page(rid)
        self.assertEqual(caught.exception.code, "summary_altered_in_transit")

    def test_the_ai_facing_service_has_no_way_to_approve_or_render_the_page(self):
        root = Path(__file__).resolve().parent.parent / "src" / "stynpilot" / "server"
        for source in root.glob("*.py"):
            if source.name == "run.py":        # the owner-side launcher: it alone starts the separate approval listener
                continue
            text = source.read_text()
            for forbidden in ("import approval", "..approval", "stynpilot.approval", "approval_web", "BrokerClient",
                              "broker.service", ".transition(", "ApprovalFlow"):
                self.assertNotIn(forbidden, text, "%s mentions %s" % (source.name, forbidden))

    def test_illegal_state_moves_are_refused(self):
        payload, rid = self.file()
        from stynpilot.requests import RequestError
        for from_state, to_state in (("pending", "done"), ("denied", "approved"), ("done", "running")):
            with self.assertRaises(RequestError):
                self.store.transition(rid, from_state, to_state)

    def test_rollback_goes_through_the_same_flow(self):
        payload, rid = self.file()
        shown, started, finish = self.decide(rid, "approve")
        installed = finish()
        result = self.store.status(rid, owner=OWNER, device=DEVICE)["result"]
        back = {"kind": "rollback", "software": "htop", "rollback_id": result["rollback_id"], "request_id": rid,
                "snapshot_id": result["rollback_id"], "owner": OWNER, "device": DEVICE,
                "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3000))}
        _, rid2 = self.file(kind="rollback", payload=back)
        shown, started, finish = self.decide(rid2, "approve")
        self.assertEqual(self.brief(finish()), {"state": "done", "ok": True})
        self.assertNotIn("htop", self.machine.installed)

    def test_authorize_settings_are_validated(self):
        for bad in ({}, {"endpoint": "http://x", "client_id": "a", "redirect_uri": "https://y"},
                    {"endpoint": "https://x", "client_id": "", "redirect_uri": "https://y"},
                    {"endpoint": "https://x", "client_id": "a", "redirect_uri": "http://evil.example"}):
            with self.assertRaises(ValueError):
                ApprovalFlow(store=self.store, broker=self.executor, exchange=self.exchange, authorize=bad)


if __name__ == "__main__":
    unittest.main()
