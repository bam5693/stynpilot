"""The root installer: approval proof, one-time use, drift, backup, install, rollback (fake machine)."""
import os
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from stynpilot.broker.executor import ExecutionDenied, Executor
    from stynpilot.broker.proof import ProofDenied, ProofVerifier, approval_nonce
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


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class BrokerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key(), as_dict=True)
        public.update(kid="k1", use="sig", alg="RS256")
        cls.jwks = {"keys": [public]}
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.machine = FakeMachine(installed={"bash": "5.2"}, available={"htop": "3.3.0-4build1", "libnl-3-200": "3.7.0"},
                                   deps={"htop": ["libnl-3-200"]})
        self.verifier = ProofVerifier(issuer=ISS, approval_client_id=APP, jwks=self.jwks)
        self.executor = Executor(state_dir=Path(tmp.name) / "broker", owner=OWNER, device=DEVICE,
                                 verifier=self.verifier, run=self.machine, require_root=False)

    def plan(self):
        from stynpilot.broker import apt
        validated, _ = catalog.install_plan("htop", owner=OWNER, device=DEVICE,
                                            resolve_apt=lambda names: apt.resolve(names, self.machine))
        self.machine.commands.clear()
        return validated.content()

    def proof(self, payload, *, key=None, sub=SUB, aud=APP, auth_age=10, nonce=None, kid="k1", alg="RS256"):
        rid, _ = request_id(payload)
        now = int(time.time())
        claims = {"iss": ISS, "aud": aud, "sub": sub, "iat": now, "exp": now + 300, "auth_time": now - auth_age,
                  "nonce": nonce or approval_nonce(rid, rid)}
        signing = "x" * 32 if alg == "HS256" else (key or self.key)
        return jwt.encode(claims, signing, algorithm=alg, headers={"kid": kid})

    # --- the happy path ----------------------------------------------------------------------
    def test_approved_install_runs_exactly_the_plan_with_a_verified_backup(self):
        payload = self.plan()
        result = self.executor.install(payload, self.proof(payload), software="htop")
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["rollback_verified"])
        self.assertEqual(self.machine.installed, {"bash": "5.2", "htop": "3.3.0-4build1", "libnl-3-200": "3.7.0"})
        installs = [c for c in self.machine.changes() if c[1] == "install"]
        self.assertEqual(len(installs), 1)
        self.assertEqual(installs[0][-2:], ["htop=3.3.0-4build1", "libnl-3-200=3.7.0"])   # pinned, nothing else
        snapshot = self.executor.dir / "snapshots" / (result["rollback_id"] + ".json")
        self.assertEqual(os.stat(snapshot).st_mode & 0o777, 0o600)
        entry = self.executor.ledger.rollbackable(result["rollback_id"], software="htop", owner=OWNER, device=DEVICE)
        self.assertEqual(entry["snapshot_verified"], 1)
        self.assertEqual(self.executor.runs.status(request_id(payload)[0])["state"], "done")

    # --- nothing runs without the owner's exact, fresh, single-use approval -------------------
    def test_bad_proofs_change_nothing(self):
        payload = self.plan()
        other_plan = dict(payload, expires_at=payload["expires_at"][:-3] + "59Z")
        cases = {
            "proof_missing": "",
            "proof_invalid": self.proof(payload, key=self.other_key),                    # forged signature
            "proof_invalid ": self.proof(payload, aud="some-other-app"),
            "proof_invalid  ": self.proof(payload, alg="HS256"),
            "proof_invalid   ": self.proof(payload, kid="unknown"),
            "proof_is_for_a_different_plan": self.proof(other_plan),
            "proof_is_not_from_the_owner": self.proof(payload, sub="auth0|someone-else"),
            "owner_sign_in_not_recent": self.proof(payload, auth_age=3600),
        }
        for code, token in cases.items():
            with self.subTest(code.strip()), self.assertRaises(ExecutionDenied) as caught:
                self.executor.install(payload, token, software="htop")
            self.assertEqual(caught.exception.code, code.strip())
        self.assertEqual(self.machine.changes(), [])
        self.assertNotIn("htop", self.machine.installed)

    def test_changed_plan_after_approval_is_refused(self):
        payload = self.plan()
        token = self.proof(payload)
        tampered = dict(payload, steps=[{"kind": "apt", "packages": [{"name": "htop", "version": "3.3.0-4build1"}]}])
        with self.assertRaises(ExecutionDenied) as caught:
            self.executor.install(tampered, token, software="htop")
        self.assertEqual(caught.exception.code, "proof_is_for_a_different_plan")
        self.assertEqual(self.machine.changes(), [])

    def test_a_proof_works_once(self):
        payload = self.plan()
        token = self.proof(payload)
        self.assertTrue(self.executor.install(payload, token, software="htop")["ok"])
        with self.assertRaises(ExecutionDenied) as caught:
            self.executor.install(payload, token, software="htop")
        self.assertEqual(caught.exception.code, "already_used")
        with self.assertRaises(ExecutionDenied):
            self.executor.install(payload, self.proof(payload, auth_age=20), software="htop")   # fresh proof, same request

    def test_expired_plan_and_unsupported_steps_are_refused(self):
        payload = self.plan()
        with self.assertRaises(ExecutionDenied) as caught:
            self.executor.install(payload, self.proof(payload), software="htop",
                                  now=datetime.now(timezone.utc) + timedelta(hours=2))
        self.assertEqual(caught.exception.code, "plan_invalid_or_expired")
        container = dict(payload, steps=[{"kind": "container", "app": "web", "image": "docker.io/library/nginx@sha256:" + "a" * 64,
                                          "bind_ip": "127.0.0.1", "host_port": 8080, "container_port": 80, "data_subdir": "web"}])
        with self.assertRaises(ExecutionDenied) as caught:
            self.executor.install(container, self.proof(container), software="htop")
        self.assertEqual(caught.exception.code, "step_kind_not_supported_yet")

    # --- the machine must still match the plan ------------------------------------------------
    def test_drift_or_removals_stop_before_any_change(self):
        for label, change in (("new candidate", lambda m: m.available.update({"htop": "3.4.0-1"})),
                              ("new dependency", lambda m: m.deps.update({"htop": ["libnl-3-200", "libextra1"]})
                               or m.available.update({"libextra1": "1.0"})),
                              ("would remove", lambda m: m.removes_on_install.append("bash"))):
            with self.subTest(label):
                self.setUp()
                payload = self.plan()
                change(self.machine)
                result = self.executor.install(payload, self.proof(payload), software="htop")
                self.assertFalse(result["ok"])
                self.assertIn(result["stopped"], ("drift_from_approved_plan", "would_remove_packages",
                                                  "approved_version_no_longer_available"))
                self.assertIs(result["changed_anything"], False)
                self.assertEqual(self.machine.changes(), [])

    def test_failed_install_is_restored_from_the_backup(self):
        payload = self.plan()
        self.machine.fail_install = True
        result = self.executor.install(payload, self.proof(payload), software="htop")
        self.assertEqual((result["ok"], result["stopped"], result["restored_from_backup"]), (False, "install_failed", True))
        self.assertEqual(self.machine.installed, {"bash": "5.2"})
        self.assertEqual(self.executor.runs.status(request_id(payload)[0])["state"], "failed")

    # --- rollback --------------------------------------------------------------------------
    def rollback_payload(self, rollback_id, software="htop"):
        expires = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {"kind": "rollback", "software": software, "rollback_id": rollback_id, "request_id": "x",
                "snapshot_id": rollback_id, "owner": OWNER, "device": DEVICE, "expires_at": expires}

    def test_approved_rollback_restores_and_can_only_happen_once(self):
        payload = self.plan()
        installed = self.executor.install(payload, self.proof(payload), software="htop")
        back = self.rollback_payload(installed["rollback_id"])
        result = self.executor.rollback(back, self.proof(back))
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.machine.installed, {"bash": "5.2"})
        removes = [c for c in self.machine.changes() if c[1] == "remove"]
        self.assertTrue(removes and all("--purge" not in c and "purge" not in c for c in removes))   # settings kept
        again = self.rollback_payload(installed["rollback_id"])
        again["expires_at"] = again["expires_at"][:-3] + "58Z"
        with self.assertRaises(ExecutionDenied) as caught:
            self.executor.rollback(again, self.proof(again))
        self.assertEqual(caught.exception.code, "already_rolled_back")

    def test_rollback_refusals_change_nothing(self):
        payload = self.plan()
        installed = self.executor.install(payload, self.proof(payload), software="htop")
        self.machine.commands.clear()
        cases = {"unknown_rollback_id": self.rollback_payload("99" * 16),
                 "rollback_id_is_for_other_software": self.rollback_payload(installed["rollback_id"], "forgejo")}
        for code, back in cases.items():
            with self.subTest(code), self.assertRaises(ExecutionDenied) as caught:
                self.executor.rollback(back, self.proof(back))
            self.assertEqual(caught.exception.code, code)
        back = self.rollback_payload(installed["rollback_id"])
        with self.assertRaises(ExecutionDenied) as caught:
            self.executor.rollback(back, self.proof(self.rollback_payload("aa" * 16)))   # proof for another request
        self.assertEqual(caught.exception.code, "proof_is_for_a_different_plan")
        self.assertEqual(self.machine.changes(), [])

    def test_installer_refuses_to_run_without_root_or_with_a_shared_state_folder(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        if os.geteuid() != 0:
            with self.assertRaises(ExecutionDenied):
                Executor(state_dir=Path(tmp.name) / "b", owner=OWNER, device=DEVICE, verifier=self.verifier)
        shared = Path(tmp.name) / "shared"
        shared.mkdir(mode=0o755)
        os.chmod(shared, 0o755)
        with self.assertRaises(ExecutionDenied):
            Executor(state_dir=shared, owner=OWNER, device=DEVICE, verifier=self.verifier, require_root=False)


if __name__ == "__main__":
    unittest.main()


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class BrokerSocketTests(unittest.TestCase):
    """The real UNIX socket: only the enrolled owner's UID gets in; everything else is re-checked."""
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

    def test_owner_uid_installs_through_the_socket_and_status_is_reported(self):
        from stynpilot.broker.service import call
        self.start(os.getuid())
        self.assertEqual(os.stat(self.sock_path).st_mode & 0o777, 0o600)
        payload = self.plan()
        reply = call(self.sock_path, {"op": "install", "payload": payload, "proof": self.proof(payload), "software": "htop"})
        self.assertTrue(reply["ok"] and reply["result"]["ok"], reply)
        status = call(self.sock_path, {"op": "status", "request_id": request_id(payload)[0]})
        self.assertEqual(status["status"]["state"], "done")
        replay = call(self.sock_path, {"op": "install", "payload": payload, "proof": self.proof(payload), "software": "htop"})
        self.assertEqual(replay, {"ok": False, "error": "already_used"})
        self.assertEqual(call(self.sock_path, {"op": "approve", "request_id": "x"}), {"ok": False, "error": "unknown_op"})

    def test_any_other_uid_is_refused_at_the_door(self):
        from stynpilot.broker.service import call
        self.start(os.getuid() + 4242)                    # e.g. the separate AI runner account
        payload = self.plan()
        reply = call(self.sock_path, {"op": "install", "payload": payload, "proof": self.proof(payload), "software": "htop"})
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
