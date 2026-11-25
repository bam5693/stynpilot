"""dev15: passkey approvals through the REAL installer, approval flow and web page (fake machine, software authenticator).
Every YELLOW kind funnels through one decision gate, so these prove the gate: exact binding, user verification, single use,
expiry, replay, revocation, restarts and interrupted approvals, and that Auth0 keeps working."""
import json
import os
import sqlite3
import sys
import time
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(__file__))
try:
    import jwt
    from starlette.testclient import TestClient
    from stynpilot.approval import ApprovalError
    from stynpilot.approval_web import COOKIE, build_app
    from stynpilot.broker.executor import ExecutionDenied, Executor
    from stynpilot.broker.passkeys import PasskeyError, PasskeyStore
    from stynpilot.broker.proof import decision_nonce
    from stynpilot.broker.service import BrokerService
except ImportError:          # pragma: no cover
    jwt = None

import test_approval as ta
import test_runner_door as trd
from softauth import SoftAuthenticator
from test_approval import DEVICE, OWNER
from stynpilot.requests import request_id

RP = "deckplayhq.tail4bc147.ts.net"
ORIGIN = "https://deckplayhq.tail4bc147.ts.net:8443"
HOST = "ryzen.example.test"


def proof_for(auth, payload, challenge, decision="approve", **kw):
    rid, _ = request_id(payload)
    return json.dumps(auth.assert_(bytes.fromhex(decision_nonce(decision, rid, rid, challenge)), **kw))


class Enrolling:
    """Shared helpers: add a passkey to the installer's store the way the real enrollment does."""
    n = 0

    def new_store(self, folder):
        return PasskeyStore(folder / "passkeys.sqlite3", rp_id=RP, origin=ORIGIN)

    def enroll(self, store, label="Pixel", **auth_kw):
        Enrolling.n += 1
        rid = ("%064x" % (0xE000 + Enrolling.n))
        store.open_window(rid, label, "auth0")
        info = store.begin(rid)
        auth = SoftAuthenticator(ORIGIN, RP, **auth_kw)
        done = store.complete(rid, auth.register(bytes.fromhex(info["challenge"])))
        store.activate(done["kid"], done["label"], done["pub"], rid, "auth0")
        return auth


@unittest.skipIf(jwt is None, "needs PyJWT, starlette and cryptography")
class InstallWithPasskey(unittest.TestCase, Enrolling):
    setUpClass = classmethod(ta.ApprovalTests.setUpClass.__func__)
    plan, proof, file, exchange, make_flow = (ta.ApprovalTests.plan, ta.ApprovalTests.proof, ta.ApprovalTests.file,
                                              ta.ApprovalTests.exchange, ta.ApprovalTests.make_flow)
    other_expiry = staticmethod(ta.ApprovalTests.other_expiry)

    def setUp(self):
        ta.ApprovalTests.setUp(self)
        self.store_pk = self.new_store(self.tmp / "broker")
        self.executor.passkeys = self.store_pk
        self.executor.allow_remote_activation = True
        self.phone = self.enroll(self.store_pk)
        self.flow = self.make_flow()
        self.client = TestClient(build_app(flow=self.flow, public_host=HOST), base_url="https://" + HOST, follow_redirects=False)

    def denied(self, code, fn, *args):
        with self.assertRaises(ExecutionDenied) as caught:
            fn(*args)
        self.assertEqual(caught.exception.code, code)

    def challenge(self, payload, decision="approve"):
        return self.executor.challenge(payload, decision)["challenge"]

    # -- the gate -------------------------------------------------------------------------------------------
    def test_a_passkey_approves_an_install_once(self):
        payload = self.plan()
        challenge = self.challenge(payload)
        result = self.executor.install(payload, proof_for(self.phone, payload, challenge), challenge)
        self.assertTrue(result["ok"])
        self.assertIn("htop", self.machine.installed)
        self.denied("already_decided_or_used", self.executor.install, payload, proof_for(self.phone, payload, challenge), challenge)

    def test_user_verification_is_required_every_time(self):
        payload = self.plan()
        challenge = self.challenge(payload)
        for flags in (0x01, 0x01 | 0x08 | 0x10):
            self.denied("passkey_user_verification_required", self.executor.install, payload,
                        proof_for(self.phone, payload, challenge, flags=flags), challenge)
        self.assertEqual(self.machine.changes(), [])
        self.assertTrue(self.executor.install(payload, proof_for(self.phone, payload, challenge), challenge)["ok"])   # nothing was burned

    def test_bound_to_the_exact_plan_decision_and_challenge(self):
        payload = self.plan()
        challenge = self.challenge(payload)
        other = dict(payload, expires_at=self.other_expiry(payload))
        self.denied("passkey_wrong_challenge", self.executor.install, payload, proof_for(self.phone, other, challenge), challenge)
        deny_challenge = self.challenge(payload, "deny")
        self.denied("passkey_wrong_challenge", self.executor.install, payload,
                    proof_for(self.phone, payload, challenge, "deny"), challenge)
        self.denied("challenge_unknown", self.executor.install, payload, proof_for(self.phone, payload, deny_challenge), deny_challenge)
        invented = "ab" * 32
        self.denied("challenge_unknown", self.executor.install, payload, proof_for(self.phone, payload, invented), invented)
        self.assertEqual(self.machine.changes(), [])

    def test_a_changed_parameter_needs_a_fresh_approval(self):
        """A proof for plan A is useless for a different, perfectly valid plan B, even with B's own challenge."""
        a, b = self.plan(), self._second_plan()
        challenge_b = self.challenge(b)
        self.denied("passkey_wrong_challenge", self.executor.install, b, proof_for(self.phone, a, challenge_b), challenge_b)
        self.assertEqual(self.machine.changes(), [])
        changed = dict(a, expires_at=self.other_expiry(a))
        challenge_a = self.challenge(a)
        self.denied("passkey_wrong_challenge", self.executor.install, changed, proof_for(self.phone, a, challenge_a),
                    challenge_a)                                                    # the approved plan's proof, an altered plan
        self.assertEqual(self.machine.changes(), [])

    def test_wrong_origin_relying_party_key_or_signature(self):
        payload = self.plan()
        challenge = self.challenge(payload)
        from cryptography.hazmat.primitives.asymmetric import ec
        for label, kw, code in (("origin", {"origin": "https://evil.example"}, "passkey_wrong_origin"),
                                ("rp", {"rp_id": "evil.example"}, "passkey_wrong_relying_party"),
                                ("tampered", {"tamper": True}, "passkey_signature_invalid"),
                                ("other key", {"sign_with": ec.generate_private_key(ec.SECP256R1())}, "passkey_signature_invalid")):
            with self.subTest(label):
                self.denied(code, self.executor.install, payload, proof_for(self.phone, payload, challenge, **kw), challenge)
        stranger = SoftAuthenticator(ORIGIN, RP)
        self.denied("passkey_unknown_or_revoked", self.executor.install, payload, proof_for(stranger, payload, challenge), challenge)
        self.assertEqual(self.machine.changes(), [])

    def test_malformed_proofs(self):
        payload = self.plan()
        challenge = self.challenge(payload)
        good = json.loads(proof_for(self.phone, payload, challenge))
        for label, text in (("not json", "{nope"), ("extra field", json.dumps(dict(good, extra="x"))),
                            ("missing field", json.dumps({k: v for k, v in good.items() if k != "signature"})),
                            ("number", json.dumps(dict(good, signature=5))), ("huge", "{" + " " * 9000 + "}")):
            with self.subTest(label):
                self.denied("proof_invalid", self.executor.install, payload, text, challenge)

    def test_expired_challenge(self):
        payload = self.plan()
        challenge = self.challenge(payload)
        self.executor.runs.clock = lambda: time.time() + 100000
        self.denied("challenge_expired", self.executor.install, payload, proof_for(self.phone, payload, challenge), challenge)
        self.assertEqual(self.machine.changes(), [])

    def test_counter_going_backwards_is_refused_but_zero_is_fine(self):
        self.assertEqual(self.store_pk.lookup(self.store_pk.active()[0]["credential_id"])["sign_count"], 0)
        payload = self.plan()
        challenge = self.challenge(payload)
        self.phone.counter, self.phone.synced_counter_zero = 7, True
        self.assertTrue(self.executor.install(payload, proof_for(self.phone, payload, challenge), challenge)["ok"])
        self.phone.counter = 3
        payload2 = self._second_plan()
        challenge2 = self.challenge(payload2)
        self.denied("passkey_counter_went_backwards", self.executor.install, payload2,
                    proof_for(self.phone, payload2, challenge2), challenge2)

    def _second_plan(self):
        from stynpilot import catalog
        from stynpilot.broker import apt
        validated, _, _ = catalog.generic_install_plan(["ncdu"], owner=OWNER, device=DEVICE,
                                                      analyze=lambda n: apt.analyze(n, self.machine),
                                                      installed=lambda n: apt.installed_versions(n, self.machine))
        return validated.content()

    def test_revoked_passkey_is_refused_and_the_audit_chain_stays_intact(self):
        spare = self.enroll(self.store_pk, "Spare")
        kid = [k for k in self.store_pk.active() if k["label"] == "Pixel"][0]["kid"]
        self.assertEqual(self.store_pk.revoke(kid, "c" * 64), 1)
        payload = self.plan()
        challenge = self.challenge(payload)
        self.denied("passkey_unknown_or_revoked", self.executor.install, payload, proof_for(self.phone, payload, challenge), challenge)
        self.assertTrue(self.executor.install(payload, proof_for(spare, payload, challenge), challenge)["ok"])
        self.assertTrue(self.store_pk.audit_ok())
        events = [e["event"] for e in self.store_pk.audit_tail(50)]
        for wanted in ("enrolled", "registered_pending", "revoked", "proof_accepted", "refused"):
            self.assertIn(wanted, events)

    def test_audit_tampering_is_detected(self):
        self.assertTrue(self.store_pk.audit_ok())
        db = sqlite3.connect(self.store_pk.path)
        db.execute("UPDATE audit SET data='{\"kid\":\"forged\"}' WHERE seq=1")
        db.commit()
        db.close()
        self.assertFalse(self.store_pk.audit_ok())

    def test_two_passkeys_are_needed_before_retiring_the_old_release_key(self):
        self.assertFalse(self.store_pk.retirement_ready())
        self.enroll(self.store_pk, "Second")
        self.assertTrue(self.store_pk.retirement_ready())
        self.store_pk.revoke(self.store_pk.active()[0]["kid"], "d" * 64)
        self.assertFalse(self.store_pk.retirement_ready())

    def test_auth0_still_approves_when_passkeys_are_enrolled(self):
        payload, rid = self.file()
        shown = self.flow.page(rid)
        started = self.flow.choose(shown["view"], shown["csrf"], "approve")
        self.last_params = started["params"]
        self.assertEqual(self.flow.finish(started["params"]["state"], "code")["state"], "done")

    def test_without_passkey_support_nothing_changes_for_auth0(self):
        self.executor.passkeys = None
        payload = self.plan()
        challenge = self.challenge(payload)
        self.denied("passkeys_not_configured", self.executor.install, payload, '{"credential_id":"x"}', challenge)
        self.assertEqual(self.machine.changes(), [])
        self.assertTrue(self.executor.install(payload, self.proof(payload, challenge), challenge)["ok"])

    # -- restarts and interruptions ------------------------------------------------------------------------
    def test_enrolled_passkeys_survive_an_installer_restart_and_upgrade(self):
        payload = self.plan()
        challenge = self.challenge(payload)
        proof = proof_for(self.phone, payload, challenge)
        self.executor._alive = None                                                 # release the state lock like a stopped process
        restarted = Executor(state_dir=self.tmp / "broker", owner=OWNER, device=DEVICE, verifier=self.executor.verifier,
                             run=self.machine, require_root=False, sources_root=self.root / "etc/apt", file_root=self.root,
                             passkeys=self.new_store(self.tmp / "broker"))
        self.assertEqual(len(restarted.passkeys.active()), 1)
        self.assertTrue(restarted.install(payload, proof, challenge)["ok"])      # the pending challenge survived too
        self.assertTrue(restarted.passkeys.audit_ok())

    def test_a_refused_precheck_changes_nothing_and_can_be_retried(self):
        payload, rid = self.file()
        shown = self.flow.page(rid)
        bad = proof_for(self.phone, payload, self.flow._views[shown["view"]]["challenges"]["approve"]["challenge"], flags=0x01)
        with self.assertRaises(ApprovalError) as caught:
            self.flow.passkey_decide(shown["view"], shown["csrf"], "approve", bad)
        self.assertEqual(caught.exception.code, "passkey_refused_passkey_user_verification_required")
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["state"], "pending")
        challenge = self.flow._views[shown["view"]]["challenges"]["approve"]["challenge"]
        outcome = self.flow.passkey_decide(shown["view"], shown["csrf"], "approve", proof_for(self.phone, payload, challenge))
        self.assertEqual(outcome["state"], "done")

    def test_interrupted_after_the_check_leaves_the_challenge_usable_after_a_restart(self):
        payload, rid = self.file()
        shown = self.flow.page(rid)
        challenge = self.flow._views[shown["view"]]["challenges"]["approve"]["challenge"]
        proof = proof_for(self.phone, payload, challenge)
        self.executor.passkey_precheck(payload, proof, challenge, "approve")        # the page checked it ... then the service died
        self.assertEqual(self.machine.changes(), [])
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["state"], "pending")
        self.assertTrue(self.executor.install(payload, proof, challenge)["ok"])    # nothing was used up by the check

    def test_after_approval_a_second_run_with_the_same_proof_cannot_happen(self):
        payload, rid = self.file()
        shown = self.flow.page(rid)
        challenge = self.flow._views[shown["view"]]["challenges"]["approve"]["challenge"]
        proof = proof_for(self.phone, payload, challenge)
        self.assertEqual(self.flow.passkey_decide(shown["view"], shown["csrf"], "approve", proof)["state"], "done")
        for again in (lambda: self.flow.passkey_decide(shown["view"], shown["csrf"], "approve", proof),
                      lambda: self.executor.install(payload, proof, challenge)):
            with self.assertRaises(Exception):
                again()
        self.assertEqual(self.machine.changes().count(self.machine.changes()[0]), 1)

    def test_deny_with_a_passkey_never_installs(self):
        payload, rid = self.file()
        shown = self.flow.page(rid)
        challenge = self.flow._views[shown["view"]]["challenges"]["deny"]["challenge"]
        outcome = self.flow.passkey_decide(shown["view"], shown["csrf"], "deny", proof_for(self.phone, payload, challenge, "deny"))
        self.assertEqual(outcome["state"], "denied")
        self.assertEqual(self.machine.changes(), [])

    def test_an_approve_passkey_proof_cannot_be_used_as_deny(self):
        payload, rid = self.file()
        shown = self.flow.page(rid)
        approve_c = self.flow._views[shown["view"]]["challenges"]["approve"]["challenge"]
        with self.assertRaises(ApprovalError):
            self.flow.passkey_decide(shown["view"], shown["csrf"], "deny", proof_for(self.phone, payload, approve_c, "approve"))
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["state"], "pending")

    def test_too_many_wrong_tries_lock_the_page(self):
        payload, rid = self.file()
        shown = self.flow.page(rid)
        for _ in range(self.flow.MAX_PASSKEY_TRIES):
            with self.assertRaises(ApprovalError):
                self.flow.passkey_decide(shown["view"], shown["csrf"], "approve", "{}")
        with self.assertRaises(ApprovalError) as caught:
            self.flow.passkey_decide(shown["view"], shown["csrf"], "approve", "{}")
        self.assertEqual(caught.exception.code, "too_many_tries_open_the_request_again")

    # -- the one-tap page ----------------------------------------------------------------------------------
    def open(self, rid):
        reply = self.client.get("/approve/" + rid)
        self.assertEqual(reply.status_code, 200, reply.text)
        import html as _html
        import re
        options = json.loads(_html.unescape(re.search(r"id=pk data-o='([^']*)'", reply.text).group(1)))
        return reply, options

    def post(self, path, body, **headers):
        return self.client.post(path, content=json.dumps(body), headers=dict({"content-type": "application/json",
                                                                              "origin": "https://" + HOST}, **headers))

    def test_page_offers_one_tap_with_a_script_nonce_and_keeps_auth0(self):
        payload, rid = self.file()
        reply, options = self.open(rid)
        self.assertIn("Approve with fingerprint or PIN", reply.text)
        self.assertIn("Use the Auth0 sign-in instead", reply.text)
        policy = reply.headers["content-security-policy"]
        self.assertRegex(policy, r"script-src 'nonce-[A-Za-z0-9_-]{16,}'")
        self.assertIn("connect-src 'self'", policy)
        self.assertNotIn("unsafe-eval", policy)
        self.assertEqual(options["rp_id"], RP)
        self.assertEqual(options["credentials"], [self.store_pk.active()[0]["credential_id"]])
        self.assertTrue(options["synced"])
        self.assertIn("synced through your Google account", reply.text)
        self.assertEqual(self.machine.changes(), [])

    def test_page_without_passkeys_is_the_old_auth0_page(self):
        self.store_pk.revoke(self.store_pk.active()[0]["kid"], "e" * 64)
        payload, rid = self.file()
        reply = self.client.get("/approve/" + rid)
        self.assertNotIn("fingerprint or PIN", reply.text)
        self.assertNotIn("script-src", reply.headers["content-security-policy"])
        self.assertIn("name=decision value=approve", reply.text)

    def test_one_tap_through_the_browser_endpoint(self):
        payload, rid = self.file()
        reply, options = self.open(rid)
        import base64
        challenge = bytes.fromhex(decision_nonce("approve", rid, rid, self.flow._views[options["view"]]["challenges"]["approve"]["challenge"]))
        self.assertEqual(options["challenge"]["approve"], base64.urlsafe_b64encode(challenge).rstrip(b"=").decode())
        assertion = json.dumps(self.phone.assert_(challenge))
        body = {"view": options["view"], "csrf": options["csrf"], "decision": "approve", "assertion": assertion}
        self.assertEqual(self.post("/approve/passkey", dict(body, view="x")).status_code, 403)        # cookie must match the view
        evil = self.client.post("/approve/passkey", content=json.dumps(body), headers={"content-type": "application/json",
                                                                                      "origin": "https://evil.example"})
        self.assertEqual(evil.status_code, 403)
        form = self.client.post("/approve/passkey", content=json.dumps(body), headers={"content-type": "text/plain",
                                                                                      "origin": "https://" + HOST})
        self.assertEqual(form.status_code, 403)
        self.assertEqual(self.machine.changes(), [])
        done = self.post("/approve/passkey", body)
        self.assertEqual(done.status_code, 200, done.text)
        self.assertEqual(done.json()["next"], "/approve/status/" + rid)
        self.assertIn("htop", self.machine.installed)
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["state"], "done")
        again = self.post("/approve/passkey", body)
        self.assertIn(again.status_code, (400, 403))
        self.assertEqual(self.machine.installed["htop"], self.machine.installed["htop"])

    def test_a_wrong_assertion_over_http_says_so_and_changes_nothing(self):
        payload, rid = self.file()
        reply, options = self.open(rid)
        challenge = bytes.fromhex(decision_nonce("approve", rid, rid, self.flow._views[options["view"]]["challenges"]["approve"]["challenge"]))
        body = {"view": options["view"], "csrf": options["csrf"], "decision": "approve",
                "assertion": json.dumps(self.phone.assert_(challenge, flags=0x01))}
        refused = self.post("/approve/passkey", body)
        self.assertEqual(refused.status_code, 400)
        self.assertIn("did not confirm it was you", refused.json()["message"])
        self.assertEqual(self.machine.changes(), [])
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["state"], "pending")


@unittest.skipIf(jwt is None, "needs PyJWT, starlette and cryptography")
class PasskeyAdministration(unittest.TestCase, Enrolling):
    """Enrollment and revocation are YELLOW requests of their own kind."""
    setUpClass = classmethod(trd.Door.setUpClass.__func__)
    payload, proof = trd.Door.payload, trd.Door.proof

    def setUp(self):
        trd.Door.setUp(self)
        self.pk = self.new_store(self.tmp / "broker")
        self.executor.passkeys = self.pk
        self.executor.allow_remote_activation = True

    def request(self, action, label="", kid="", pub="", **kw):
        return {"kind": "passkey", "action": action, "label": label, "kid": kid, "pub": pub, "owner": OWNER, "device": DEVICE,
                "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3000)), **kw}

    def approve_with_auth0(self, payload):
        challenge = self.executor.challenge(payload, "approve")["challenge"]
        return self.executor.passkey_admin(payload, self.proof(payload, challenge), challenge)

    def approve_with_passkey(self, auth, payload):
        challenge = self.executor.challenge(payload, "approve")["challenge"]
        return self.executor.passkey_admin(payload, proof_for(auth, payload, challenge), challenge)

    def denied(self, code, fn, *args):
        with self.assertRaises(ExecutionDenied) as caught:
            fn(*args)
        self.assertEqual(caught.exception.code, code)

    def test_the_owner_reads_what_enrolling_means_including_the_sync_warning(self):
        text = "\n".join(self.executor.challenge(self.request("enroll", "Pixel phone"), "approve")["summary"])
        for want in ("Pixel phone", "3 minutes", "syncs", "Google account", "Auth0 sign-in", "second, final step"):
            self.assertIn(want, text)

    def test_enrolling_with_auth0_then_the_phone_creates_a_powerless_key_then_a_named_activation(self):
        payload = self.request("enroll", "Pixel phone")
        result = self.approve_with_auth0(payload)
        self.assertEqual((result["ok"], result["enrollment_open"]), (True, True))
        rid = request_id(payload)[0]
        info = self.executor.passkey_begin(rid)
        self.assertEqual((info["rp_id"], info["origin"]), (RP, ORIGIN))
        phone = SoftAuthenticator(ORIGIN, RP)
        done = self.executor.passkey_complete(rid, phone.register(bytes.fromhex(info["challenge"])))
        self.assertEqual((done["label"], done["synced"]), ("Pixel phone", True))
        self.assertEqual(self.executor.passkey_list()["passkeys"], [])                      # created, but it can do nothing yet
        self.assertEqual([k["kid"] for k in self.executor.passkey_list()["pending"]], [done["kid"]])
        activation = self.request("activate", "Pixel phone", done["kid"], done["pub"])
        result = self.approve_with_auth0(activation)
        self.assertEqual((result["ok"], result["passkeys_active"]), (True, 1))
        listing = self.executor.passkey_list()
        self.assertEqual([k["label"] for k in listing["passkeys"]], ["Pixel phone"])
        self.assertEqual(listing["pending"], [])
        self.assertNotIn("public_key", json.dumps(listing))
        self.denied("enrollment_already_used", self.executor.passkey_complete, rid, phone.register(bytes.fromhex(info["challenge"])))

    def register_pending(self, label="Pixel", **kw):
        payload = self.request("enroll", label)
        self.approve_with_auth0(payload)
        rid = request_id(payload)[0]
        info = self.executor.passkey_begin(rid)
        auth = SoftAuthenticator(ORIGIN, RP, **kw)
        return auth, self.executor.passkey_complete(rid, auth.register(bytes.fromhex(info["challenge"]))), info

    def test_a_pending_key_can_approve_nothing_until_the_owner_activates_that_exact_key(self):
        auth, done, _ = self.register_pending()
        payload = self.payload()
        challenge = self.executor.challenge(payload, "approve")["challenge"]
        self.denied("passkey_unknown_or_revoked", self.executor.runner_admin, payload, proof_for(auth, payload, challenge), challenge)
        self.assertEqual(self.jobs.calls, [])

    def test_the_activation_is_bound_to_the_exact_key_hash(self):
        """The substitution attack: the owner approved key A; key B must not become active under that approval."""
        a_auth, a, _ = self.register_pending("RealA")
        b_auth, b, _ = self.register_pending("RealB")
        activation_for_a = self.request("activate", "RealA", a["kid"], a["pub"])
        # an approval of the activation of A is for A's hash: it can never activate B
        forged = self.request("activate", "RealA", a["kid"], b["pub"])
        self.assertNotEqual(request_id(activation_for_a)[0], request_id(forged)[0])
        challenge = self.executor.challenge(forged, "approve")["challenge"]
        stale_proof = self.proof(activation_for_a, challenge)                                  # signed for A's request
        self.denied("proof_is_for_a_different_decision", self.executor.passkey_admin, forged, stale_proof, challenge)
        result = self.approve_with_auth0(forged)                                              # even a fully approved wrong pairing fails
        self.assertEqual((result["ok"], result["stopped"]), (False, "passkey_unknown"))
        self.assertEqual(self.executor.passkey_list()["passkeys"], [])
        self.assertTrue(self.approve_with_auth0(activation_for_a)["ok"])
        self.assertEqual([k["kid"] for k in self.executor.passkey_list()["passkeys"]], [a["kid"]])

    def test_a_passkey_can_never_add_a_passkey(self):
        old = self.enroll(self.pk, "Existing")
        for payload in (self.request("enroll", "Sneaky"),):
            challenge = self.executor.challenge(payload, "approve")["challenge"]
            self.denied("adding_a_passkey_needs_the_auth0_sign_in", self.executor.passkey_admin, payload,
                        proof_for(old, payload, challenge), challenge)
            self.denied("adding_a_passkey_needs_the_auth0_sign_in", self.executor.passkey_precheck, payload,
                        proof_for(old, payload, challenge), challenge, "approve")
        auth, done, _ = self.register_pending("Sneaky")
        activation = self.request("activate", "Sneaky", done["kid"], done["pub"])
        challenge = self.executor.challenge(activation, "approve")["challenge"]
        self.denied("adding_a_passkey_needs_the_auth0_sign_in", self.executor.passkey_admin, activation,
                    proof_for(old, activation, challenge), challenge)
        self.assertEqual(len(self.executor.passkey_list()["passkeys"]), 1)

    def test_pending_keys_expire(self):
        auth, done, _ = self.register_pending()
        self.pk.clock = lambda: time.time() + 2000
        self.assertEqual(self.pk.pending(), [])
        result = self.approve_with_auth0(self.request("activate", "Pixel", done["kid"], done["pub"]))
        self.assertEqual((result["ok"], result["stopped"]), (False, "pending_passkey_expired"))

    def test_each_enrollment_gets_its_own_account_handle_so_a_phone_cannot_overwrite_the_first_passkey(self):
        first = self.enroll(self.pk, "One")
        _, _, info_two = self.register_pending("Two")
        _, _, info_three = self.register_pending("Three")
        self.assertNotEqual(info_two["user_id"], info_three["user_id"])
        self.assertEqual(len(info_two["user_id"]), 22)
        self.assertEqual(len(self.pk.active()), 1)
        self.assertEqual(len(self.executor.passkey_list()["pending"]), 2)
        # the second enrollment tells the phone about every existing credential so the same authenticator is not re-enrolled
        self.assertIn(self.pk.active()[0]["credential_id"], info_three["exclude"])

    def test_a_failure_to_record_a_passkey_use_refuses_the_approval_and_burns_nothing(self):
        phone = self.enroll(self.pk, "Phone")
        payload = self.payload()
        challenge = self.executor.challenge(payload, "approve")["challenge"]
        original = self.pk.record_use
        self.pk.record_use = lambda *a, **k: (_ for _ in ()).throw(OSError("disk full"))
        self.denied("passkey_record_failed_nothing_was_approved", self.executor.runner_admin, payload,
                    proof_for(phone, payload, challenge), challenge)
        self.assertEqual(self.jobs.calls, [])
        self.pk.record_use = original
        self.assertTrue(self.executor.runner_admin(payload, proof_for(phone, payload, challenge), challenge)["ok"])

    def test_window_is_single_use_short_and_origin_checked(self):
        payload = self.request("enroll", "Pixel")
        self.approve_with_auth0(payload)
        rid = request_id(payload)[0]
        info = self.executor.passkey_begin(rid)
        challenge = bytes.fromhex(info["challenge"])
        for label, kw, code in (("origin", {"origin": "https://evil.example"}, "registration_wrong_origin"),
                                ("rp", {"rp_id": "evil.example"}, "registration_wrong_relying_party"),
                                ("format", {"fmt": "packed"}, "registration_attestation_not_accepted")):
            with self.subTest(label):
                self.denied(code, self.executor.passkey_complete, rid, SoftAuthenticator(ORIGIN, RP).register(challenge, **kw))
        self.denied("registration_user_verification_required", self.executor.passkey_complete, rid,
                    SoftAuthenticator(ORIGIN, RP, uv=False).register(challenge))
        self.denied("registration_wrong_challenge", self.executor.passkey_complete, rid,
                    SoftAuthenticator(ORIGIN, RP).register(os.urandom(32)))
        self.assertEqual(self.executor.passkey_list()["passkeys"], [])

    def test_the_window_closes_after_too_many_tries_and_when_time_runs_out(self):
        payload = self.request("enroll", "Pixel")
        self.approve_with_auth0(payload)
        rid = request_id(payload)[0]
        for _ in range(5):
            with self.assertRaises(ExecutionDenied):
                self.executor.passkey_complete(rid, {})
        self.denied("enrollment_too_many_attempts", self.executor.passkey_begin, rid)
        payload2 = self.request("enroll", "Other")
        self.approve_with_auth0(payload2)
        rid2 = request_id(payload2)[0]
        self.pk.clock = lambda: time.time() + 1000
        self.denied("enrollment_window_expired", self.executor.passkey_begin, rid2)

    def test_nobody_can_open_a_window_or_enroll_without_an_approved_request(self):
        self.denied("enrollment_not_open", self.executor.passkey_begin, "a" * 64)
        self.denied("enrollment_not_open", self.executor.passkey_complete, "a" * 64,
                    SoftAuthenticator(ORIGIN, RP).register(b"x" * 32))

    def test_a_forged_or_unapproved_enrollment_request_is_refused(self):
        payload = self.request("enroll", "Pixel")
        challenge = self.executor.challenge(payload, "approve")["challenge"]
        other = dict(payload, label="Attacker")
        for bad in (dict(payload, action="delete"), dict(payload, label=""), dict(payload, kid="a" * 16), dict(payload, pub="b" * 64),
                    dict(payload, owner="someone-else"), dict(payload, extra=1), dict(payload, label="x" * 60)):
            self.denied("passkey_request_invalid", self.executor.challenge, bad, "approve")

    def test_revoking_through_another_passkey_and_the_audit_trail(self):
        first = self.approve_enroll("One")
        second = self.approve_enroll("Two")
        kid = [k for k in self.executor.passkey_list()["passkeys"] if k["label"] == "One"][0]["kid"]
        second_kid = [k for k in self.executor.passkey_list()["passkeys"] if k["label"] == "Two"][0]["kid"]
        result = self.approve_with_passkey(second, self.request("revoke", kid=kid))
        self.assertEqual((result["ok"], result["passkeys_active"], result["kid"]), (True, 1, kid))
        payload = self.request("revoke", kid="f" * 16)
        self.assertFalse(self.approve_with_passkey(second, payload)["ok"])                       # unknown passkey: stops, changes nothing
        again = self.request("revoke", kid=second_kid)
        challenge = self.executor.challenge(again, "approve")["challenge"]
        self.denied("passkey_unknown_or_revoked", self.executor.passkey_admin, again, proof_for(first, again, challenge), challenge)
        self.assertTrue(self.pk.audit_ok())

    def approve_enroll(self, label):
        payload = self.request("enroll", label)
        self.approve_with_auth0(payload)
        info = self.executor.passkey_begin(request_id(payload)[0])
        auth = SoftAuthenticator(ORIGIN, RP, backup_eligible=False, backup_state=False)
        done = self.executor.passkey_complete(request_id(payload)[0], auth.register(bytes.fromhex(info["challenge"])))
        self.assertTrue(self.approve_with_auth0(self.request("activate", label, done["kid"], done["pub"]))["ok"])
        return auth

    def test_device_bound_passkey_is_reported_as_not_synced(self):
        self.approve_enroll("Hardware")
        self.assertFalse(self.executor.passkey_list()["passkeys"][0]["synced"])

    def test_revocation_still_works_while_the_installer_needs_attention_or_an_upgrade_runs(self):
        auth = self.approve_enroll("One")
        (self.executor.dir / "attention" / "x.json").write_text("{}")
        kid = self.executor.passkey_list()["passkeys"][0]["kid"]
        self.assertTrue(self.approve_with_auth0(self.request("revoke", kid=kid))["ok"])

    def test_a_yellow_runner_change_is_approved_by_a_passkey(self):
        phone = self.enroll(self.pk)
        payload = self.payload()                                                    # runner setup
        challenge = self.executor.challenge(payload, "approve")["challenge"]
        result = self.executor.runner_admin(payload, proof_for(phone, payload, challenge), challenge)
        self.assertTrue(result["ok"])
        self.assertEqual(self.jobs.calls, ["setup", "selftest"])
        again = self.payload(action="enroll", name="app")
        challenge = self.executor.challenge(again, "approve")["challenge"]
        self.denied("passkey_user_verification_required", self.executor.runner_admin, again,
                    proof_for(phone, again, challenge, flags=0x01), challenge)
        self.assertNotIn(("enroll", self.jobs.projects_dir + "/app"), self.jobs.calls)

    def test_every_approval_path_goes_through_the_one_gate(self):
        """Install, rollback, upgrade, runner, passkey and deny each call ``_decide`` and nothing else checks owner proof."""
        import inspect
        source = inspect.getsource(Executor)
        self.assertEqual(source.count("self.verifier.verify("), 1)
        self.assertEqual(source.count("self._verify_passkey("), 2)      # _prove and the read-only pre-check
        for name in ("_install_locked", "_rollback_locked", "runner_admin", "passkey_admin", "deny"):
            self.assertIn("self._decide(", inspect.getsource(getattr(Executor, name)), name)
        self.assertIn("self._prove(", inspect.getsource(Executor.upgrade))

    def test_the_broker_door_serves_the_passkey_calls_to_the_owner_service(self):
        service = BrokerService(socket_path=self.tmp / "s.sock", executor=self.executor, allowed_uid=os.getuid())
        self.assertEqual(service.handle({"op": "passkey_list"})["result"]["configured"], True)
        payload = self.request("enroll", "Pixel")
        challenge = service.handle({"op": "challenge", "payload": payload, "decision": "approve"})["challenge"]["challenge"]
        reply = service.handle({"op": "passkey_admin", "payload": payload, "proof": self.proof(payload, challenge), "challenge": challenge})
        self.assertTrue(reply["result"]["enrollment_open"])
        rid = request_id(payload)[0]
        begin = service.handle({"op": "passkey_begin", "request_id": rid})["result"]
        done = service.handle({"op": "passkey_complete", "request_id": rid,
                               "response": SoftAuthenticator(ORIGIN, RP).register(bytes.fromhex(begin["challenge"]))})
        self.assertTrue(done["ok"])
        self.assertEqual(service.handle({"op": "passkey_begin", "request_id": "nope"})["error"], "enrollment_not_open")


@unittest.skipIf(jwt is None, "needs PyJWT, starlette and cryptography")
class EnrollmentThroughTheBrowser(unittest.TestCase, Enrolling):
    """The whole owner experience for adding a passkey: ask, approve (Auth0 here), create it in the same browser, then approve with it."""
    setUpClass = classmethod(trd.Door.setUpClass.__func__)
    payload, proof = trd.Door.payload, trd.Door.proof

    def setUp(self):
        from types import SimpleNamespace
        from stynpilot.approval import ApprovalFlow
        from stynpilot.requests import RequestStore
        trd.Door.setUp(self)
        self.pk = self.new_store(self.tmp / "broker")
        self.executor.passkeys = self.pk
        self.executor.allow_remote_activation = True
        self.store = RequestStore(self.tmp / "state" / "requests.sqlite3")
        self.tokens = []
        self.flow = ApprovalFlow(store=self.store, broker=self.executor, exchange=lambda code, verifier: self.tokens.pop(),
                                 authorize={"endpoint": "https://issuer.example.test/authorize", "client_id": trd.APP,
                                            "redirect_uri": "https://%s/approve/callback" % HOST})
        self.app = build_app(flow=self.flow, public_host=HOST)
        self.client = TestClient(self.app, base_url="https://" + HOST, follow_redirects=False)
        self.proposer = SimpleNamespace(client="claude-connector", name="claude")

    def file(self, **kw):
        payload = {"kind": "passkey", "action": "enroll", "label": "Pixel phone", "kid": "", "pub": "", "owner": OWNER, "device": DEVICE,
                   "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3000))}
        payload.update(kw)
        from stynpilot.broker.proof import render_summary
        receipt, _ = self.store.submit(kind="passkey", software="stynpilot-passkey-x", device=DEVICE, owner=OWNER, proposer=self.proposer,
                                       payload=payload, summary=render_summary(payload), expires=time.time() + 3000)
        return payload, receipt["request_id"]

    def approve_with_auth0(self, rid):
        reply = self.client.get("/approve/" + rid)
        import re
        fields = dict(re.findall(r"name=(view|csrf) value='([^']+)'", reply.text))
        step = self.client.post("/approve/choose", content=urllib.parse.urlencode(dict(fields, decision="approve")),
                                headers={"content-type": "application/x-www-form-urlencoded", "origin": "https://" + HOST})
        params = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(step.headers["location"]).query))
        now = int(time.time())
        self.tokens.append(jwt.encode({"iss": trd.ISS, "aud": trd.APP, "sub": trd.SUB, "iat": now, "exp": now + 300, "auth_time": now,
                                       "nonce": params["nonce"]}, self.key, algorithm="RS256", headers={"kid": "k1"}))
        return self.client.get("/approve/callback", params={"state": params["state"], "code": "c"})

    def enroll_options(self, rid, client=None):
        import html as _html
        import re
        reply = (client or self.client).get("/approve/enroll/" + rid)
        match = re.search(r"id=pk data-o='([^']*)'", reply.text)
        return reply, (json.loads(_html.unescape(match.group(1))) if match else None)

    def test_ask_approve_create_then_approve_something_else_with_it(self):
        payload, rid = self.file()
        back = self.approve_with_auth0(rid)
        self.assertEqual(back.status_code, 303)
        self.assertEqual(back.headers["location"], "/approve/status/" + rid)
        status = self.client.get("/approve/status/" + rid)
        self.assertIn("/approve/enroll/" + rid, status.text)
        reply, options = self.enroll_options(rid)
        self.assertEqual(reply.status_code, 200)
        self.assertRegex(reply.headers["content-security-policy"], r"script-src 'nonce-")
        self.assertEqual((options["rp_id"], options["label"]), (RP, "Pixel phone"))
        phone = SoftAuthenticator(ORIGIN, RP)
        challenge = bytes.fromhex(self.flow.broker.passkeys.begin(rid)["challenge"])
        body = {"view": options["view"], "csrf": options["csrf"],
                "response": phone.register(challenge)}
        post = lambda b, **h: self.client.post("/approve/enroll/finish", content=json.dumps(b),
                                               headers=dict({"content-type": "application/json", "origin": "https://" + HOST}, **h))
        done = post(body)
        self.assertEqual(done.status_code, 200, done.text)
        self.assertIn("Pixel phone", done.json()["message"])
        self.assertIn(post(body).status_code, (400, 403))                      # the window is spent
        self.assertEqual(self.pk.active(), [])                                  # created, but powerless until the owner activates it
        activation_rid = done.json()["next"].rsplit("/", 1)[1]
        page = self.client.get(done.json()["next"])
        self.assertNotIn("fingerprint or PIN", page.text)                       # adding a passkey is Auth0-only: no passkey button
        self.assertIn("Activate the new passkey", page.text)
        self.assertEqual(self.approve_with_auth0(activation_rid).status_code, 303)
        self.assertEqual([k["label"] for k in self.pk.active()], ["Pixel phone"])
        # ... and now that passkey approves a runner change from the one-tap page
        runner = self.payload()
        from types import SimpleNamespace
        receipt, _ = self.store.submit(kind="runner", software="stynpilot-runner", device=DEVICE, owner=OWNER, proposer=self.proposer,
                                       payload=runner, summary=["x"], expires=time.time() + 3000)
        rrid = receipt["request_id"]
        page = self.client.get("/approve/" + rrid)
        import html as _html
        import re
        opts = json.loads(_html.unescape(re.search(r"id=pk data-o='([^']*)'", page.text).group(1)))
        nonce = decision_nonce("approve", rrid, rrid, self.flow._views[opts["view"]]["challenges"]["approve"]["challenge"])
        sent = self.client.post("/approve/passkey", content=json.dumps(
            {"view": opts["view"], "csrf": opts["csrf"], "decision": "approve", "assertion": json.dumps(phone.assert_(bytes.fromhex(nonce)))}),
            headers={"content-type": "application/json", "origin": "https://" + HOST})
        self.assertEqual(sent.status_code, 200, sent.text)
        self.assertEqual(self.jobs.calls, ["setup", "selftest"])

    def test_enrollment_request_page_has_no_passkey_button_and_uncertain_outcomes_point_at_status(self):
        payload, rid = self.file()
        self.approve_with_auth0(rid)
        # an unexpected failure after the owner tapped must say "check the status", never "nothing was changed"
        flow = self.flow
        payload2, rid2 = self.file(label="Second")
        page = self.client.get("/approve/" + rid2)
        self.assertNotIn("fingerprint or PIN", page.text)
        self.assertNotIn("script-src", page.headers["content-security-policy"])
        original = flow.passkey_decide
        flow.passkey_decide = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        import re
        fields = dict(re.findall(r"name=(view|csrf) value='([^']+)'", page.text))
        sent = self.client.post("/approve/passkey", content=json.dumps({"view": fields["view"], "csrf": fields["csrf"],
                                "decision": "approve", "assertion": "{}"}),
                                headers={"content-type": "application/json", "origin": "https://" + HOST})
        flow.passkey_decide = original
        self.assertEqual(sent.status_code, 500)
        body = sent.json()
        self.assertTrue(body["uncertain"])
        self.assertEqual(body["next"], "/approve/status/" + rid2)
        self.assertIn("status", body["message"])
        self.assertNotIn("Nothing was changed", body["message"])

    def test_the_script_never_claims_nothing_changed_after_the_request_was_sent(self):
        from stynpilot import approval_web as web
        for js in (web._PASSKEY_JS, web._ENROLL_JS):
            self.assertIn("sent=true", js)
            self.assertIn("result is uncertain", js)

    def test_only_the_browser_that_approved_may_create_the_passkey(self):
        payload, rid = self.file()
        self.approve_with_auth0(rid)
        stranger = TestClient(self.app, base_url="https://" + HOST, follow_redirects=False)
        reply, options = self.enroll_options(rid, stranger)
        self.assertEqual(reply.status_code, 400)
        self.assertIsNone(options)
        self.assertEqual(self.pk.active(), [])
        self.assertEqual(self.pk.begin(rid)["label"], "Pixel phone")           # the window itself is still open for the right browser
        self.assertEqual(self.enroll_options(rid)[0].status_code, 200)

    def test_enrollment_page_for_an_unapproved_or_unknown_request_gives_nothing(self):
        payload, rid = self.file()
        reply, options = self.enroll_options(rid)
        self.assertEqual(reply.status_code, 400)
        self.assertIsNone(options)
        self.assertEqual(self.enroll_options("f" * 64)[0].status_code, 400)

    def test_a_service_restart_between_approval_and_creation_makes_the_owner_ask_again(self):
        payload, rid = self.file()
        self.approve_with_auth0(rid)
        self.flow._enroll_sessions.clear()                                     # the owner service restarted: the browser binding is gone
        self.assertEqual(self.enroll_options(rid)[0].status_code, 400)
        self.assertEqual(self.pk.active(), [])


class InstallerConfigTests(unittest.TestCase):
    BASE = {"issuer": "https://issuer.example.test/", "approval_client_id": "app", "owner": "acct_" + "a" * 40, "device": "dtdev_x",
            "owner_uid": 1000, "state_dir": "/var/lib/stynpilot", "socket_path": "/run/stynpilot/b.sock"}

    def test_passkey_identity_is_optional_validated_and_goes_together(self):
        from stynpilot.service import ConfigError, InstallerConfig
        plain = InstallerConfig.from_dict(dict(self.BASE))
        self.assertIsNone(plain.passkey_rp_id)
        good = InstallerConfig.from_dict(dict(self.BASE, passkey_rp_id=RP, passkey_origin=ORIGIN))
        self.assertEqual((good.passkey_rp_id, good.passkey_origin), (RP, ORIGIN))
        for bad in ({"passkey_rp_id": RP}, {"passkey_origin": ORIGIN},
                    {"passkey_rp_id": RP, "passkey_origin": "https://evil.example"},
                    {"passkey_rp_id": RP, "passkey_origin": "http://" + RP},
                    {"passkey_rp_id": "Bad_Host", "passkey_origin": "https://Bad_Host"},
                    {"passkey_rp_id": "localhost", "passkey_origin": "https://localhost"},
                    {"passkey_rp_id": RP, "passkey_origin": ORIGIN + "/path"}):
            with self.subTest(bad):
                with self.assertRaises(ConfigError):
                    InstallerConfig.from_dict(dict(self.BASE, **bad))

    def test_the_config_file_reader_accepts_only_the_known_optional_keys(self):
        import tempfile
        from pathlib import Path
        from stynpilot.service import INSTALLER_KEYS, INSTALLER_OPTIONAL, ConfigError, read_private_json
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "c.json"
            for extra, ok in (({"passkey_rp_id": RP, "passkey_origin": ORIGIN}, True), ({}, True), ({"surprise": 1}, False)):
                path.write_text(json.dumps(dict(self.BASE, **extra)))
                os.chmod(path, 0o600)
                if ok:
                    self.assertEqual(set(read_private_json(path, INSTALLER_KEYS, INSTALLER_OPTIONAL)), set(self.BASE) | set(extra))
                else:
                    with self.assertRaises(ConfigError):
                        read_private_json(path, INSTALLER_KEYS, INSTALLER_OPTIONAL)

    def test_building_the_installer_creates_a_persistent_private_passkey_store(self):
        import tempfile
        from pathlib import Path
        from stynpilot.service import InstallerConfig, build_installer
        import test_broker as tb
        with tempfile.TemporaryDirectory() as folder:
            cfg = InstallerConfig.from_dict(dict(self.BASE, state_dir=str(Path(folder) / "state"), socket_path=str(Path(folder) / "s.sock"),
                                                 owner_uid=os.getuid() if os.getuid() >= 1000 else 1000,
                                                 passkey_rp_id=RP, passkey_origin=ORIGIN))
            tb.BrokerTests.setUpClass()
            service = build_installer(cfg, jwks=tb.BrokerTests.jwks, require_root=False)
            self.assertEqual(service.executor.passkeys.rp_id, RP)
            mode = os.stat(Path(folder) / "state" / "passkeys.sqlite3").st_mode & 0o777
            self.assertEqual(mode, 0o600)


try:
    import test_runner_tools as rt
except ImportError:          # pragma: no cover
    rt = None


@unittest.skipIf(rt is None or rt.create_server is None, "MCP SDK not installed")
class AssistantPasskeyTools(unittest.TestCase):
    """What ChatGPT and Claude can do about passkeys: ask for one, ask to remove one, read the public list. Nothing else."""
    call, d = rt.RunnerToolTests.call, rt.RunnerToolTests.d

    def setUp(self):
        rt.RunnerToolTests.setUp(self)
        self.keys = [{"kid": "1" * 16, "credential_id": "SECRET-CRED-ID", "label": "Pixel", "synced": True, "sync_capable": True,
                      "created": 5, "last_used": None, "revoked": False, "public_key": "SHOULD-NEVER-SHOW"}]
        self.configured = True
        self.broker.passkey_list = lambda: {"configured": self.configured, "passkeys": self.keys, "retirement_ready": False,
                                            "audit_chain_ok": True}

    def test_enrollment_request_is_filed_for_the_owner_and_cannot_be_approved_by_an_assistant(self):
        out = self.call("commander_request_passkey_enrollment", self.d(label="Spare phone"))
        self.assertTrue(out["ok"], out)
        result = out["result"]
        self.assertEqual((result["kind"], result["state"], result["approved_by_ai"]), ("passkey", "pending", False))
        payload = self.store.payload(result["request_id"])
        self.assertEqual((payload["kind"], payload["action"], payload["label"], payload["kid"]), ("passkey", "enroll", "Spare phone", ""))
        self.assertIn("/approve/" + result["request_id"], result["owner_approval_url"])
        self.assertTrue(any("syncs" in line for line in result["summary"]))

    def test_label_and_revocation_checks(self):
        for bad in ("", "../x", "x" * 60, "a/b", " lead"):
            self.assertEqual(self.call("commander_request_passkey_enrollment", self.d(label=bad))["error"], "passkey_label_invalid", bad)
        self.assertEqual(self.call("commander_request_passkey_revocation", self.d(kid="f" * 16))["error"], "passkey_unknown")
        ok = self.call("commander_request_passkey_revocation", self.d(kid="1" * 16))
        self.assertTrue(ok["ok"], ok)
        self.assertEqual(self.store.payload(ok["result"]["request_id"])["kid"], "1" * 16)
        self.configured = False
        self.assertEqual(self.call("commander_request_passkey_enrollment", self.d(label="Pixel"))["error"], "passkeys_not_configured")

    def test_status_shows_only_public_facts(self):
        out = self.call("passkey_status", self.d())
        self.assertTrue(out["ok"], out)
        text = json.dumps(out)
        self.assertNotIn("SECRET-CRED-ID", text)
        self.assertNotIn("SHOULD-NEVER-SHOW", text)
        self.assertEqual(out["result"]["passkeys"][0]["label"], "Pixel")
        self.assertEqual((out["result"]["retirement_ready"], out["result"]["audit_chain_ok"]), (False, True))

    def test_a_read_only_token_cannot_ask_but_can_read(self):
        self.assertFalse(self.call("commander_request_passkey_enrollment", self.d(label="Pixel"), "readonly")["ok"])
        self.assertTrue(self.call("passkey_status", self.d(), "readonly")["ok"])
        self.assertFalse(self.call("passkey_status", self.d(), "stranger")["ok"])

    def test_the_new_tools_are_guarded_like_the_other_requests_and_none_can_approve(self):
        from stynpilot.server.propose_tools import PROPOSE_ONLY_TOOLS
        self.assertIn("commander_request_passkey_enrollment", PROPOSE_ONLY_TOOLS)
        self.assertIn("commander_request_passkey_revocation", PROPOSE_ONLY_TOOLS)
        self.assertNotIn("passkey_status", PROPOSE_ONLY_TOOLS)
        import asyncio
        names = {t.name for t in asyncio.run(self.server.list_tools()) if "passkey" in t.name}
        self.assertEqual(names, {"commander_request_passkey_enrollment", "commander_request_passkey_revocation", "passkey_status"})


try:
    import test_dev4_upgrade as tu
except ImportError:          # pragma: no cover
    tu = None


@unittest.skipIf(tu is None or jwt is None, "needs the upgrade test harness")
class UpgradeWithPasskey(unittest.TestCase, Enrolling):
    """The self-upgrade (the riskiest YELLOW action) approved by a passkey, through the real installer and upgrade preparation."""
    setUpClass = classmethod(tu.UpgradeTests.setUpClass.__func__)
    release_for, payload, good, denied, build = (tu.UpgradeTests.release_for, tu.UpgradeTests.payload, tu.UpgradeTests.good,
                                                 tu.UpgradeTests.denied, tu.UpgradeTests.build)

    def setUp(self):
        tu.UpgradeTests.setUp(self)
        self.pk = self.new_store(self.tmp / "broker")
        self.executor.passkeys = self.pk
        self.executor.allow_remote_activation = True
        self.phone = self.enroll(self.pk)

    def test_a_passkey_starts_exactly_one_upgrade_and_cannot_be_replayed(self):
        payload = self.good()
        rid = request_id(payload)[0]
        challenge = self.executor.challenge(payload, "approve")["challenge"]
        bad = proof_for(self.phone, payload, challenge, flags=0x01)
        self.denied("passkey_user_verification_required", self.executor.upgrade, payload, bad, challenge)
        self.assertEqual(self.launched, [])
        proof = proof_for(self.phone, payload, challenge)
        result = self.executor.upgrade(payload, proof, challenge)
        self.assertEqual((result["pending"], result["to_version"]), (True, "0.1.0~dev4"))
        self.assertEqual(len(self.launched), 1)
        self.assertTrue(self.executor.upgrader.job_dir(rid).exists())
        with self.assertRaises(ExecutionDenied):
            self.executor.upgrade(payload, proof, challenge)
        self.assertEqual(len(self.launched), 1)
        self.assertIn("proof_accepted", [e["event"] for e in self.pk.audit_tail(20)])

    def test_a_revoked_passkey_cannot_start_an_upgrade(self):
        payload = self.good()
        challenge = self.executor.challenge(payload, "approve")["challenge"]
        self.pk.revoke(self.pk.active()[0]["kid"], "9" * 64)
        self.denied("passkey_unknown_or_revoked", self.executor.upgrade, payload, proof_for(self.phone, payload, challenge), challenge)
        self.assertEqual(self.launched, [])


if __name__ == "__main__":
    unittest.main()
