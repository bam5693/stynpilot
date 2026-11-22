"""G6 service assembly: config safety, owner-service start order (revocation provisioning, restart
reconciliation BEFORE listening, background worker) and the root installer's crash handling."""
import json
import os
import socket
import tempfile
import unittest
from pathlib import Path

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from stynpilot import service
    from stynpilot.broker.executor import Runs
    from stynpilot.requests import RequestStore
except ImportError:          # pragma: no cover
    jwt = None

from test_approval import DEVICE, OWNER, ApprovalTests
import test_broker as tb

ISS = "https://issuer.example.test/"


def owner_data(tmp, **over):
    data = {"issuer": ISS, "approval_client_id": "approval-app", "authorize_endpoint": ISS + "authorize",
            "token_endpoint": ISS + "oauth/token", "approval_public_host": "ryzen.example.test:8444",
            "approval_port": 18444, "state_dir": str(tmp / "state"), "broker_socket": str(tmp / "installer.sock")}
    data.update(over)
    return data


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class ConfigTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.tmp = Path(t.name)

    def refused(self, **over):
        with self.assertRaises(service.ConfigError):
            service.OwnerConfig.from_dict(owner_data(self.tmp, **over))

    def test_unsafe_owner_values_are_refused(self):
        self.refused(issuer="http://issuer.example.test/")
        self.refused(token_endpoint="https://evil.example.test/oauth/token")      # off the issuer's origin
        self.refused(authorize_endpoint="https://evil.example.test/authorize")
        self.refused(approval_port=80)
        self.refused(approval_public_host="127.0.0.1")                            # a DNS name is required
        self.refused(state_dir="relative/state")
        self.refused(approval_client_id="")

    def test_a_good_owner_config_builds_the_https_redirect_from_the_public_host(self):
        config = service.OwnerConfig.from_dict(owner_data(self.tmp))
        self.assertEqual(config.redirect_uri, "https://ryzen.example.test:8444/approve/callback")

    def test_config_file_must_be_private_exact_and_not_a_symlink(self):
        path = self.tmp / "owner.json"
        path.write_text(json.dumps(owner_data(self.tmp)))
        os.chmod(path, 0o644)
        with self.assertRaises(service.ConfigError):
            service.OwnerConfig.from_file(path)                                    # world-readable
        os.chmod(path, 0o600)
        self.assertEqual(service.OwnerConfig.from_file(path).approval_port, 18444)
        link = self.tmp / "link.json"
        link.symlink_to(path)
        with self.assertRaises(service.ConfigError):
            service.OwnerConfig.from_file(link)
        path.write_text(json.dumps(dict(owner_data(self.tmp), extra="x")))
        with self.assertRaises(service.ConfigError):
            service.OwnerConfig.from_file(path)                                    # unknown field

    def test_installer_config_needs_a_normal_owner_uid(self):
        data = {"issuer": ISS, "approval_client_id": "a", "owner": OWNER, "device": DEVICE, "owner_uid": 0,
                "state_dir": "/var/lib/x", "socket_path": "/run/x/i.sock"}
        with self.assertRaises(service.ConfigError):
            service.InstallerConfig.from_dict(data)
        data["owner_uid"] = 1000
        self.assertEqual(service.InstallerConfig.from_dict(data).owner_uid, 1000)


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class OwnerServiceTests(unittest.TestCase):
    plan, file = ApprovalTests.plan, ApprovalTests.file
    setUpClass = classmethod(tb.BrokerTests.setUpClass.__func__)

    def setUp(self):
        tb.BrokerTests.setUp(self)
        self.config = service.OwnerConfig.from_dict(owner_data(self.tmp))
        self.events = []

    def start(self, broker, fail=False):
        def listener(*, flow, public_host, port):
            self.events.append(("listen", port, public_host))
            if fail:
                raise RuntimeError("port in use")
            return type("L", (), {"stop": lambda s: self.events.append(("stop",))})()
        return service.start_owner_service(self.config, broker=broker, exchange=lambda c, v: "x" * 30,
                                           start_listener=listener)

    def broker(self, record):
        events = self.events
        outer = self

        class B:
            def status(self, rid):
                events.append(("status", rid[:8]))
                if isinstance(record, Exception):
                    raise record
                return record
        return B()

    def test_first_run_provisions_the_revocation_list_privately_and_starts_in_order(self):
        svc = self.start(self.broker({"state": "not_started"}))
        self.addCleanup(svc.stop)
        path = self.config.state_dir / "revoked-clients.json"
        self.assertTrue(svc.revocations_created)
        self.assertEqual(json.loads(path.read_text()), {"revoked": []})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.config.state_dir.stat().st_mode & 0o777, 0o700)
        self.assertIsNotNone(svc.flow._pool)                                       # the background approval worker
        self.assertEqual(self.events, [("listen", 18444, "ryzen.example.test:8444")])

    def test_restart_settles_leftover_requests_from_the_installer_record_before_listening(self):
        first = self.start(self.broker({"state": "not_started"}))
        first.stop()
        store = RequestStore(self.config.state_dir / "requests.sqlite3")
        payload = self.plan()
        from types import SimpleNamespace
        receipt, _ = store.submit(kind="install", software="htop", device=DEVICE, owner=OWNER,
                                  proposer=SimpleNamespace(client="chatgpt-connector", name="chatgpt"),
                                  payload=payload, summary=["ask"], expires=__import__("time").time() + 3000)
        rid = receipt["request_id"]
        store.transition(rid, "pending", "approved")
        store.transition(rid, "approved", "running")                               # the service died mid-install
        self.events.clear()
        svc = self.start(self.broker({"state": "done", "result": {"ok": True, "rollback_id": "r1"}}))
        self.addCleanup(svc.stop)
        self.assertEqual(svc.recovered, [rid])
        self.assertEqual([e[0] for e in self.events], ["status", "listen"])        # reconciled FIRST
        status = RequestStore(self.config.state_dir / "requests.sqlite3").status(rid, owner=OWNER, device=DEVICE)
        self.assertEqual(status["state"], "done")

    def test_restart_with_an_unreachable_installer_marks_the_request_for_the_owner(self):
        self.start(self.broker({"state": "not_started"})).stop()
        store = RequestStore(self.config.state_dir / "requests.sqlite3")
        from types import SimpleNamespace
        receipt, _ = store.submit(kind="install", software="htop", device=DEVICE, owner=OWNER,
                                  proposer=SimpleNamespace(client="chatgpt-connector", name="chatgpt"),
                                  payload=self.plan(), summary=["ask"], expires=__import__("time").time() + 3000)
        rid = receipt["request_id"]
        store.transition(rid, "pending", "approved")
        svc = self.start(self.broker(OSError("socket gone")))
        self.addCleanup(svc.stop)
        status = RequestStore(self.config.state_dir / "requests.sqlite3").status(rid, owner=OWNER, device=DEVICE)
        self.assertEqual(status["state"], "needs_owner_intervention")

    def test_a_missing_revocation_list_after_first_run_stops_the_service_instead_of_recreating_it(self):
        self.start(self.broker({"state": "not_started"})).stop()
        (self.config.state_dir / "revoked-clients.json").unlink()
        with self.assertRaises(service.ConfigError) as refused:
            self.start(self.broker({"state": "not_started"}))
        self.assertIn("owner_must_reprovision", str(refused.exception))
        self.assertFalse((self.config.state_dir / "revoked-clients.json").exists())

    def test_an_unreadable_revocation_list_stops_the_service(self):
        self.start(self.broker({"state": "not_started"})).stop()
        (self.config.state_dir / "revoked-clients.json").write_text("not json")
        os.chmod(self.config.state_dir / "revoked-clients.json", 0o600)
        with self.assertRaises(Exception):
            self.start(self.broker({"state": "not_started"}))

    def test_a_listener_that_cannot_start_leaves_no_worker_running(self):
        with self.assertRaises(RuntimeError):
            self.start(self.broker({"state": "not_started"}), fail=True)

    def test_a_group_readable_state_folder_is_refused(self):
        self.config.state_dir.mkdir(mode=0o755)
        os.chmod(self.config.state_dir, 0o755)
        with self.assertRaises(service.ConfigError):
            self.start(self.broker({"state": "not_started"}))


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class InstallerServiceTests(unittest.TestCase):
    setUpClass = classmethod(tb.BrokerTests.setUpClass.__func__)

    def setUp(self):
        tb.BrokerTests.setUp(self)

    def config(self):
        return service.InstallerConfig.from_dict({
            "issuer": ISS, "approval_client_id": tb.APP, "owner": OWNER, "device": DEVICE, "owner_uid": 1000,
            "state_dir": str(self.tmp / "inst"), "socket_path": str(self.tmp / "inst.sock")})

    def build(self):
        return service.build_installer(self.config(), jwks=self.jwks, run_command=self.machine, require_root=False,
                                       sources_root=self.root / "etc/apt", file_root=self.root)

    def test_installer_starts_with_a_signed_verifier_and_the_owner_only_door(self):
        broker = self.build()
        self.assertEqual(broker.allowed_uid, 1000)
        self.assertEqual(broker.executor.owner, OWNER)
        self.assertEqual(broker.executor.verifier.client_id, tb.APP)

    def test_a_run_left_running_by_a_crash_blocks_new_installs_after_restart(self):
        first = self.build()
        rid = "a" * 64
        challenge = first.executor.runs.issue(rid, "approve")
        first.executor.runs.consume(challenge=challenge, request_id=rid, decision="approve", proof="p", kind="install")
        self.assertEqual(first.executor.runs.status(rid)["state"], "running")
        restarted = self.build()                                                   # the root service restarted
        self.assertEqual(restarted.executor.runs.status(rid)["state"], "needs_owner_intervention")
        self.assertTrue(restarted.executor.needs_attention())
        self.assertEqual(restarted.handle({"op": "status", "request_id": rid})["status"]["state"],
                         "needs_owner_intervention")


class UnitFileTests(unittest.TestCase):
    root = Path(__file__).resolve().parent.parent / "deploy" / "systemd"

    def read(self, name):
        return (self.root / name).read_text()

    def test_owner_unit_is_unprivileged_and_hardened(self):
        text = self.read("stynpilot-owner.service")
        self.assertNotIn("User=root", text)
        for line in ("NoNewPrivileges=yes", "ProtectSystem=strict", "-m stynpilot.service owner"):
            self.assertIn(line, text)

    def test_installer_unit_is_root_only_and_runs_the_installer_role(self):
        text = self.read("stynpilot-installer.service")
        self.assertIn("User=root", text)
        self.assertIn("-m stynpilot.service installer", text)
        self.assertIn("RuntimeDirectory=stynpilot", text)

    def test_units_carry_no_secrets_or_public_listeners(self):
        for name in ("stynpilot-owner.service", "stynpilot-installer.service"):
            text = self.read(name).lower()
            for bad in ("token", "secret", "password", "0.0.0.0", "dtdev_", "auth0|"):
                self.assertNotIn(bad, text)


if __name__ == "__main__":
    unittest.main()
