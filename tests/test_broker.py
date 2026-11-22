"""The root installer (fake machine): challenge-bound approval, exact transaction, trusted origin,
real backup, safe rollback, plan-bound software. One regression test per G4 review blocker."""
import os
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from stynpilot.broker.executor import CHALLENGE_LIFETIME, ExecutionDenied, Executor
    from stynpilot.broker.proof import ProofVerifier, decision_nonce
except ImportError:          # pragma: no cover - optional dependencies
    jwt = None

from fake_machine import FakeMachine
from stynpilot import catalog
from stynpilot.identity import account_id
from stynpilot.requests import request_id

ISS, APP = "https://issuer.example.test/", "approval-app-client"
SUB = "auth0|test-owner"
OWNER = account_id(verified_issuer=ISS, verified_subject=SUB)
DEVICE = "dtdev_TESTONLYliveDevice"
CONF = "/etc/libnl.conf"


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class BrokerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key(), as_dict=True)
        public.update(kid="k1", use="sig", alg="RS256")
        cls.jwks = {"keys": [public]}
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self, installed=None, archive=None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.root = self.tmp / "root"
        (self.root / "etc/apt/sources.list.d").mkdir(parents=True)
        (self.root / "etc/apt/sources.list").write_text("deb http://archive.ubuntu.com/ubuntu noble main\n")
        (self.root / "etc/libnl.conf").write_text("old config\n")
        self.machine = FakeMachine(installed=installed or {"bash": "5.2"},
                                   available={"htop": "3.3.0-4build1", "libnl-3-200": "3.7.0"},
                                   deps={"htop": ["libnl-3-200"]}, file_root=self.root)
        self.machine.archive = archive or {}
        self.verifier = ProofVerifier(issuer=ISS, approval_client_id=APP, jwks=self.jwks)
        self.executor = Executor(state_dir=self.tmp / "broker", owner=OWNER, device=DEVICE, verifier=self.verifier,
                                 run=self.machine, require_root=False, sources_root=self.root / "etc/apt",
                                 file_root=self.root)

    def plan(self):
        from stynpilot.broker import apt
        validated, _ = catalog.install_plan("htop", owner=OWNER, device=DEVICE,
                                            resolve_apt=lambda names: apt.resolve(names, self.machine))
        self.machine.commands.clear()
        return validated.content()

    def proof(self, payload, challenge, *, decision="approve", key=None, sub=SUB, aud=APP, auth_age=10,
              nonce=None, kid="k1", alg="RS256"):
        rid, _ = request_id(payload)
        now = int(time.time())
        claims = {"iss": ISS, "aud": aud, "sub": sub, "iat": now, "exp": now + 300, "auth_time": now - auth_age,
                  "nonce": nonce or decision_nonce(decision, rid, rid, challenge)}
        signing = "x" * 32 if alg == "HS256" else (key or self.key)
        return jwt.encode(claims, signing, algorithm=alg, headers={"kid": kid})

    def approval(self, payload, **kw):
        """(challenge, proof) exactly as the real flow produces them."""
        decision = kw.pop("decision", "approve")
        challenge = self.executor.challenge(payload, decision)["challenge"]
        return challenge, self.proof(payload, challenge, decision=decision, **kw)

    def install(self, payload, **kw):
        self.last_request = request_id(payload)[0]
        challenge, token = self.approval(payload, **kw)
        return self.executor.install(payload, token, challenge)

    def denied(self, code, fn, *args):
        with self.assertRaises(ExecutionDenied) as caught:
            fn(*args)
        self.assertEqual(caught.exception.code, code)

    # --- happy path -------------------------------------------------------------------------
    def test_approved_install_runs_exactly_the_plan_with_a_verified_backup(self):
        payload = self.plan()
        result = self.install(payload)
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["backup_verified"])
        self.assertEqual(self.machine.installed, {"bash": "5.2", "htop": "3.3.0-4build1", "libnl-3-200": "3.7.0"})
        installs = self.machine.changes()
        self.assertEqual(len(installs), 1)
        self.assertIn("--no-download", installs[0])                                   # only the pre-fetched files
        self.assertEqual(installs[0][-2:], ["htop=3.3.0-4build1", "libnl-3-200=3.7.0"])
        entry = self.executor.ledger.rollbackable(result["rollback_id"], software="htop", owner=OWNER, device=DEVICE)
        self.assertEqual(entry["snapshot_verified"], 1)
        self.assertEqual(self.executor.runs.status(request_id(payload)[0])["state"], "done")

    def test_summary_is_rendered_by_the_installer_from_the_plan(self):
        payload = self.plan()
        shown = self.executor.challenge(payload, "approve")["summary"]
        self.assertTrue(any("htop" in line and "3.3.0-4build1" in line for line in shown))

    # --- G4 blocker 1: a login token alone is not approval -----------------------------------
    def test_a_plain_login_token_or_self_made_challenge_is_not_approval(self):
        payload = self.plan()
        rid, _ = request_id(payload)
        generic = self.proof(payload, "0" * 64, nonce="whatever-the-app-sent")
        real_challenge = self.executor.challenge(payload, "approve")["challenge"]
        self.denied("proof_is_for_a_different_decision", self.executor.install, payload, generic, real_challenge)
        invented = "ab" * 32                                                        # signed, correct format, never issued by root
        self.denied("challenge_unknown", self.executor.install, payload, self.proof(payload, invented), invented)
        self.assertEqual(self.machine.changes(), [])
        # A valid token for the REAL challenge still works afterwards: failed attempts burn nothing.
        self.assertTrue(self.executor.install(payload, self.proof(payload, real_challenge), real_challenge)["ok"])

    def test_bad_proofs_change_nothing(self):
        payload = self.plan()
        challenge = self.executor.challenge(payload, "approve")["challenge"]
        other = dict(payload, expires_at=payload["expires_at"][:-3] + "59Z")
        cases = {
            "proof_missing": "",
            "proof_invalid": self.proof(payload, challenge, key=self.other_key),
            "proof_invalid ": self.proof(payload, challenge, aud="some-other-app"),
            "proof_invalid  ": self.proof(payload, challenge, alg="HS256"),
            "proof_invalid   ": self.proof(payload, challenge, kid="unknown"),
            "proof_is_for_a_different_decision": self.proof(other, challenge),
            "proof_is_not_from_the_owner": self.proof(payload, challenge, sub="auth0|someone-else"),
            "owner_sign_in_not_recent": self.proof(payload, challenge, auth_age=3600),
        }
        for code, token in cases.items():
            with self.subTest(code.strip()):
                self.denied(code.strip(), self.executor.install, payload, token, challenge)
        self.assertEqual(self.machine.changes(), [])

    def test_challenge_is_single_use_and_expires(self):
        payload = self.plan()
        challenge, token = self.approval(payload)
        self.assertTrue(self.executor.install(payload, token, challenge)["ok"])
        self.denied("already_used", self.executor.install, payload, self.proof(payload, challenge, auth_age=20), challenge)
        self.denied("already_decided_or_used", self.executor.challenge, payload, "approve")
        self.setUp()
        payload = self.plan()
        challenge, token = self.approval(payload)
        self.executor.runs.clock = lambda: time.time() + CHALLENGE_LIFETIME + 5
        self.denied("challenge_expired", self.executor.install, payload, token, challenge)
        self.assertEqual(self.machine.changes(), [])

    def test_a_challenge_for_one_request_or_decision_never_works_for_another(self):
        payload = self.plan()
        challenge, _ = self.approval(payload)
        other = dict(payload, expires_at=payload["expires_at"][:-3] + "58Z")
        self.denied("challenge_unknown", self.executor.install, other, self.proof(other, challenge), challenge)
        deny_challenge, deny_token = self.approval(payload, decision="deny")
        self.denied("proof_is_for_a_different_decision", self.executor.install, payload, deny_token, deny_challenge)
        self.assertEqual(self.machine.changes(), [])

    def test_owner_can_deny_and_a_denied_request_can_never_be_approved(self):
        payload = self.plan()
        challenge, token = self.approval(payload, decision="deny")
        self.assertEqual(self.executor.deny(payload, token, challenge), {"ok": True, "denied_by_owner": True})
        self.assertEqual(self.executor.runs.status(request_id(payload)[0])["state"], "denied")
        self.denied("already_decided_or_used", self.executor.challenge, payload, "approve")
        self.assertEqual(self.machine.changes(), [])

    def test_changed_or_expired_plans_and_unsupported_steps_are_refused(self):
        payload = self.plan()
        challenge, token = self.approval(payload)
        tampered = dict(payload, steps=[{"kind": "apt", "packages": [{"name": "htop", "version": "3.3.0-4build1"}]}])
        with self.assertRaises(ExecutionDenied):
            self.executor.install(tampered, token, challenge)
        self.denied("plan_invalid_or_expired", self.executor.install, payload, token, challenge) if False else None
        with self.assertRaises(ExecutionDenied) as caught:
            self.executor._check_install_payload(payload, now=datetime.now(timezone.utc) + timedelta(hours=2))
        self.assertEqual(caught.exception.code, "plan_invalid_or_expired")
        container = dict(payload, steps=[{"kind": "container", "app": "web", "image": "docker.io/library/nginx@sha256:" + "a" * 64,
                                          "bind_ip": "127.0.0.1", "host_port": 8080, "container_port": 80, "data_subdir": "web"}])
        self.denied("step_kind_not_supported_yet", self.executor.challenge, container, "approve")
        self.assertEqual(self.machine.changes(), [])

    # --- G4 blocker 5: the software ID is bound to the immutable plan ----------------------------
    def test_software_comes_from_the_hashed_plan_not_the_caller(self):
        payload = self.plan()
        self.assertEqual(payload["software"], "htop")
        challenge, token = self.approval(payload)
        with self.assertRaises(TypeError):                                           # no caller-supplied software at all
            self.executor.install(payload, token, challenge, software="forgejo")
        self.assertEqual(self.executor.install(payload, token, challenge)["ok"], True)
        import sqlite3
        rows = sqlite3.connect(str(self.executor.dir / "installs.sqlite3")).execute("SELECT software FROM installs").fetchall()
        self.assertEqual(rows, [("htop",)])

    def test_plan_naming_other_or_mismatched_software_is_refused(self):
        payload = self.plan()
        for label, bad in (("unknown software", dict(payload, software="nmap")),
                           ("missing software", {k: v for k, v in payload.items() if k != "software"}),
                           ("software without its packages", dict(payload, software="htop", steps=[
                               {"kind": "apt", "packages": [{"name": "libnl-3-200", "version": "3.7.0"}]}]))):
            with self.subTest(label), self.assertRaises(ExecutionDenied):
                self.executor.challenge(bad, "approve")
        self.assertEqual(self.machine.changes(), [])

    # --- G4 blocker 4: exact transaction and trusted Ubuntu origin ---------------------------------
    def test_third_party_origin_or_insecure_source_stops_before_any_change(self):
        payload = self.plan()
        self.machine.origin["htop"] = "Evil"
        result = self.install(payload)
        self.assertEqual((result["ok"], result["stopped"], result["changed_anything"]),
                         (False, "package_not_from_the_ubuntu_archive", False))
        self.setUp()
        payload = self.plan()
        (self.root / "etc/apt/sources.list.d/evil.list").write_text("deb [trusted=yes] http://ppa.example.test/evil noble main\n")
        result = self.install(payload)
        self.assertEqual((result["stopped"], result["changed_anything"]), ("untrusted_package_source_configured", False))
        self.assertEqual(self.machine.changes(), [])

    def test_drift_or_removals_stop_before_any_change(self):
        for label, change, codes in (
                ("new candidate", lambda m: m.available.update({"htop": "3.4.0-1"}), ("download_failed", "package_not_from_the_ubuntu_archive")),
                ("new dependency", lambda m: m.deps.update({"htop": ["libnl-3-200", "libextra1"]}) or m.available.update({"libextra1": "1.0"}),
                 ("drift_from_approved_plan",)),
                ("would remove", lambda m: m.removes_on_install.append("bash"), ("would_remove_packages",))):
            with self.subTest(label):
                self.setUp()
                payload = self.plan()
                change(self.machine)
                result = self.install(payload)
                self.assertFalse(result["ok"])
                self.assertIn(result["stopped"], codes)
                self.assertIs(result["changed_anything"], False)
                self.assertEqual(self.machine.changes(), [])

    def test_extra_change_during_install_is_caught_and_undone(self):
        payload = self.plan()
        self.machine.extra_on_install = {"sneaky": "1.0"}
        result = self.install(payload)
        self.assertEqual((result["ok"], result["stopped"], result["restored_from_backup"]),
                         (False, "transaction_differed_from_plan", True))
        self.assertEqual(self.machine.installed, {"bash": "5.2"})

    def test_failed_install_is_restored_from_the_backup(self):
        payload = self.plan()
        self.machine.fail_install = True
        result = self.install(payload)
        self.assertEqual((result["ok"], result["stopped"], result["restored_from_backup"]), (False, "install_failed", True))
        self.assertEqual(self.machine.installed, {"bash": "5.2"})
        self.assertEqual(self.executor.runs.status(request_id(payload)[0])["state"], "failed")

    # --- G4 blocker 2: a real backup, not a version list ---------------------------------------------
    def upgrade_setup(self, archive=True):
        self.setUp(installed={"bash": "5.2", "libnl-3-200": "3.6.0"}, archive={"libnl-3-200": {"3.6.0"}} if archive else {})
        self.machine.conffiles = {"libnl-3-200": [CONF]}
        self.machine.manual.add("libnl-3-200")
        return self.plan()

    def test_upgrade_backup_holds_the_old_package_file_and_settings_and_restores_them(self):
        payload = self.upgrade_setup()
        result = self.install(payload)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["backup"], {"saved_package_files": 1, "saved_settings_files": 1})
        self.assertEqual((self.root / "etc/libnl.conf").read_text(), "config from 3.7.0\n")      # dpkg changed it
        back = self.rollback_payload(result)
        challenge, token = self.approval(back)
        undone = self.executor.rollback(back, token, challenge)
        self.assertTrue(undone["ok"], undone)
        self.assertEqual(self.machine.installed, {"bash": "5.2", "libnl-3-200": "3.6.0"})
        self.assertEqual((self.root / "etc/libnl.conf").read_text(), "old config\n")
        self.assertIn("libnl-3-200", self.machine.manual)
        self.assertNotIn("htop", self.machine.manual)

    def test_install_stops_when_the_current_version_cannot_be_saved(self):
        payload = self.upgrade_setup(archive=False)
        result = self.install(payload)
        self.assertEqual((result["ok"], result["stopped"], result["changed_anything"]),
                         (False, "backup_not_possible_current_version_unavailable", False))
        self.assertEqual(self.machine.changes(), [])

    def test_damaged_backup_blocks_rollback(self):
        payload = self.upgrade_setup()
        result = self.install(payload)
        snapshot = self.executor.dir / "snapshots" / result["rollback_id"] / "debs"
        next(snapshot.glob("*.deb")).write_bytes(b"tampered")
        back = self.rollback_payload(result)
        self.denied("backup_damaged", self.executor.challenge, back, "approve") if False else None
        self.denied("backup_damaged", self.executor.rollback, back, "x" * 20, "0" * 64)
        self.assertEqual(self.machine.installed["htop"], "3.3.0-4build1")

    # --- rollback: approved, scoped, and safe ------------------------------------------------------------
    def rollback_payload(self, installed, software="htop", **over):
        expires = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        payload = {"kind": "rollback", "software": software, "rollback_id": installed["rollback_id"],
                   "request_id": self.last_request, "snapshot_id": installed["rollback_id"],
                   "owner": OWNER, "device": DEVICE, "expires_at": expires}
        payload.update(over)
        return payload

    def installed_ok(self):
        payload = self.plan()
        self.last_request = request_id(payload)[0]
        result = self.install(payload)
        self.assertTrue(result["ok"], result)
        self.machine.commands.clear()
        return result

    def test_approved_rollback_restores_and_can_only_happen_once(self):
        result = self.installed_ok()
        back = self.rollback_payload(result)
        challenge, token = self.approval(back)
        undone = self.executor.rollback(back, token, challenge)
        self.assertTrue(undone["ok"], undone)
        self.assertEqual(self.machine.installed, {"bash": "5.2"})
        removes = [c for c in self.machine.changes() if c[1] == "remove"]
        self.assertTrue(removes and all("purge" not in c and "--purge" not in c for c in removes))     # settings kept
        again = self.rollback_payload(result, expires_at=back["expires_at"][:-3] + "58Z")
        self.denied("already_rolled_back", self.executor.challenge, again, "approve")

    def test_rollback_needs_a_challenge_bound_proof(self):
        result = self.installed_ok()
        back = self.rollback_payload(result)
        generic = self.proof(back, "0" * 64, nonce="plain-login")
        challenge = self.executor.challenge(back, "approve")["challenge"]
        self.denied("proof_is_for_a_different_decision", self.executor.rollback, back, generic, challenge)
        invented = "cd" * 32
        self.denied("challenge_unknown", self.executor.rollback, back, self.proof(back, invented), invented)
        self.assertEqual(self.machine.changes(), [])

    # --- G4 blocker 3: rollback never removes unrelated packages ------------------------------------------
    def test_rollback_is_refused_if_something_installed_later_depends_on_it(self):
        result = self.installed_ok()
        self.machine.installed["htop-addon"] = "1.0"
        self.machine.rdeps["htop"] = ["htop-addon"]
        back = self.rollback_payload(result)
        challenge, token = self.approval(back)
        self.denied("rollback_would_affect_other_packages", self.executor.rollback, back, token, challenge)
        self.assertEqual(self.machine.changes(), [])
        self.assertIn("htop", self.machine.installed)
        self.assertIn("htop-addon", self.machine.installed)

    def test_rollback_is_refused_if_the_packages_changed_since_install(self):
        result = self.installed_ok()
        self.machine.installed["htop"] = "9.9-manual-upgrade"
        back = self.rollback_payload(result)
        challenge, token = self.approval(back)
        self.denied("changed_since_install", self.executor.rollback, back, token, challenge)
        self.assertEqual(self.machine.changes(), [])

    def test_rollback_request_must_match_the_ledger(self):
        result = self.installed_ok()
        cases = {"unknown_rollback_id": self.rollback_payload(result, rollback_id="99" * 16, snapshot_id="99" * 16),
                 "rollback_id_is_for_other_software": self.rollback_payload(result, software="forgejo"),
                 "rollback_request_invalid": self.rollback_payload(result, request_id="f" * 64)}
        for code, back in cases.items():
            with self.subTest(code):
                self.denied(code, self.executor.challenge, back, "approve")
        self.assertEqual(self.machine.changes(), [])

    # --- installer hygiene -------------------------------------------------------------------------------------
    def test_installer_refuses_to_run_without_root_or_with_a_shared_state_folder(self):
        if os.geteuid() != 0:
            with self.assertRaises(ExecutionDenied):
                Executor(state_dir=self.tmp / "b", owner=OWNER, device=DEVICE, verifier=self.verifier)
        shared = self.tmp / "shared"
        shared.mkdir(mode=0o755)
        os.chmod(shared, 0o755)
        with self.assertRaises(ExecutionDenied):
            Executor(state_dir=shared, owner=OWNER, device=DEVICE, verifier=self.verifier, require_root=False)


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class BrokerSocketTests(unittest.TestCase):
    """The real UNIX socket: only the enrolled owner's UID gets in; G3 asks about rollbacks without reading root files."""
    setUpClass = classmethod(BrokerTests.setUpClass.__func__)
    setUp = BrokerTests.setUp
    plan = BrokerTests.plan
    proof = BrokerTests.proof

    def start(self, allowed_uid):
        import threading
        from stynpilot.broker.service import BrokerService
        self.sock_path = self.executor.dir.parent / "broker.sock"
        service = BrokerService(socket_path=self.sock_path, executor=self.executor, allowed_uid=allowed_uid)
        listener = service.bind()
        self.addCleanup(listener.close)

        def loop():
            try:
                while True:
                    conn, _ = listener.accept()
                    service.serve_one(conn)
            except OSError:
                pass
        threading.Thread(target=loop, daemon=True).start()
        return service

    def test_owner_uid_gets_a_challenge_then_installs_through_the_socket(self):
        from stynpilot.broker.service import BrokerLedger, call
        from stynpilot.ledger import LedgerError
        self.start(os.getuid())
        self.assertEqual(os.stat(self.sock_path).st_mode & 0o777, 0o600)
        payload = self.plan()
        issued = call(self.sock_path, {"op": "challenge", "payload": payload, "decision": "approve"})
        self.assertTrue(issued["ok"], issued)
        challenge = issued["challenge"]["challenge"]
        token = self.proof(payload, challenge)
        reply = call(self.sock_path, {"op": "install", "payload": payload, "proof": token, "challenge": challenge,
                                      "software": "forgejo"})                       # ignored: software is in the plan
        self.assertTrue(reply["ok"] and reply["result"]["ok"], reply)
        self.assertEqual(call(self.sock_path, {"op": "status", "request_id": request_id(payload)[0]})["status"]["state"], "done")
        replay = call(self.sock_path, {"op": "install", "payload": payload, "proof": token, "challenge": challenge})
        self.assertEqual(replay, {"ok": False, "error": "already_used"})
        self.assertEqual(call(self.sock_path, {"op": "approve", "request_id": "x"}), {"ok": False, "error": "unknown_op"})
        rid = reply["result"]["rollback_id"]
        ledger = BrokerLedger(str(self.sock_path))
        self.assertEqual(ledger.rollbackable(rid, software="htop", owner=OWNER, device=DEVICE)["snapshot_id"], rid)
        for kwargs in (dict(software="forgejo", owner=OWNER, device=DEVICE), dict(software="htop", owner="someone-else", device=DEVICE)):
            with self.assertRaises(LedgerError):
                ledger.rollbackable(rid, **kwargs)

    def test_any_other_uid_is_refused_at_the_door(self):
        from stynpilot.broker.service import call
        self.start(os.getuid() + 4242)                    # e.g. the separate AI runner account
        payload = self.plan()
        for message in ({"op": "challenge", "payload": payload, "decision": "approve"},
                        {"op": "rollbackable", "rollback_id": "aa" * 16, "software": "htop"}):
            try:
                reply = call(self.sock_path, message)
            except (BrokenPipeError, ConnectionResetError):       # refused before it even read our message
                continue
            self.assertEqual(reply, {"ok": False, "error": "caller_not_enrolled_owner"})
        self.assertEqual(self.machine.changes(), [])

    def test_garbage_and_oversized_messages(self):
        import socket as s
        self.start(os.getuid())
        for raw in (b"not json\n", b"[1,2]\n", b"{" + b" " * (300 * 1024) + b"}\n"):
            with self.subTest(size=len(raw)), s.socket(s.AF_UNIX, s.SOCK_STREAM) as conn:
                conn.connect(str(self.sock_path))
                try:
                    conn.sendall(raw)
                except (BrokenPipeError, ConnectionResetError):
                    continue
                reply = conn.recv(4096)
                self.assertIn(b'"ok": false', reply)


if __name__ == "__main__":
    unittest.main()
