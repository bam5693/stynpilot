"""G6 service assembly: config safety, owner-service start order (revocation provisioning, restart
reconciliation BEFORE listening, background worker) and the root installer's crash handling."""
import json
import os
import socket
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from stynpilot import service
    from stynpilot.broker.executor import Runs
    from stynpilot.requests import RequestStore
    import httpx
    from stynpilot.identity import MemoryRevocations
    from stynpilot.server.oidc import OIDCConfig
    from stynpilot.server import run
except ImportError:          # pragma: no cover
    jwt = None

from legacy_pairing import make_pairing_db

from test_approval import DEVICE, OWNER, ApprovalTests
import test_broker as tb

ISS = "https://issuer.example.test/"


MCP_HOST = "ryzen.example.test"
CLIENTS = [{"client_id": "claude-connector", "name": "claude", "kind": "claude"},
           {"client_id": "chatgpt-connector", "name": "chatgpt", "kind": "chatgpt"}]
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
               "MCP-Protocol-Version": "2025-06-18"}


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def owner_data(tmp, **over):
    data = {"issuer": ISS, "approval_client_id": "approval-app", "authorize_endpoint": ISS + "authorize",
            "token_endpoint": ISS + "oauth/token", "approval_public_host": "ryzen.example.test:8444",
            "approval_port": 18444, "state_dir": str(tmp / "state"), "broker_socket": str(tmp / "installer.sock"),
            "pairing_db": str(tmp / "pairing" / "pairing.db"), "mcp_public_host": MCP_HOST, "mcp_port": 18443,
            "enrolled_clients": CLIENTS}
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
        self.refused(mcp_port=18444)                                              # must differ from the approval port
        self.refused(enrolled_clients=[])
        self.refused(enrolled_clients=[{"client_id": "x", "name": "y"}])
        self.refused(mcp_public_host="10.0.0.5")

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
    plan = ApprovalTests.plan
    setUpClass = classmethod(tb.BrokerTests.setUpClass.__func__)

    def setUp(self):
        tb.BrokerTests.setUp(self)
        owner = OWNER
        make_pairing_db(self.tmp / "pairing", [(DEVICE, owner, time.time() + 3600, None, ["workspace.propose"])])
        (self.tmp / "pairing" / "pairing.db").exists() or None
        self.pairing = next((self.tmp / "pairing").iterdir())
        self.mcp_port, self.approval_port = free_port(), free_port()
        self.config = service.OwnerConfig.from_dict(owner_data(
            self.tmp, mcp_port=self.mcp_port, approval_port=self.approval_port, pairing_db=str(self.pairing)))
        self.events = []
        docs = {ISS + ".well-known/openid-configuration": {
                    "issuer": ISS, "authorization_endpoint": ISS + "authorize", "token_endpoint": ISS + "oauth/token",
                    "jwks_uri": ISS + ".well-known/jwks.json", "revocation_endpoint": ISS + "oauth/revoke",
                    "response_types_supported": ["code"], "code_challenge_methods_supported": ["S256"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "scopes_supported": ["openid", "offline_access"]},
                ISS + ".well-known/jwks.json": self.jwks}
        self.tokens = OIDCConfig(issuer=ISS, audience="https://%s/mcp" % MCP_HOST, revocations=MemoryRevocations(),
                                 allowed_scopes=run.PROPOSE_SCOPES, allow_volatile_revocations=True,
                                 fetch=docs.__getitem__).build_verifier()

    def provision(self):
        return service.provision_owner_state(self.config)

    def start(self, broker, **kw):
        svc = service.start_owner_service(
            self.config, broker=broker, exchange=lambda c, v: "x" * 30, tokens=self.tokens,
            resolve_apt=lambda names: [{"name": "htop", "version": "3.3.0-4build1"},
                                       {"name": "libnl-3-200", "version": "3.7.0-0.3build1.1"}],
            reconcile_interval=3600, **kw)
        self.addCleanup(svc.stop)
        return svc

    def broker(self, answer):
        """answer: a dict (the installer's record), or an exception to raise, or a callable."""
        events = self.events

        class B:
            def status(self, rid):
                events.append("status")
                value = answer() if callable(answer) else answer
                if isinstance(value, Exception):
                    raise value
                return value
        return B()

    def file(self):
        store = RequestStore(self.config.state_dir / "requests.sqlite3")
        receipt, _ = store.submit(kind="install", software="htop", device=DEVICE, owner=OWNER,
                                  proposer=SimpleNamespace(client="chatgpt-connector", name="chatgpt"),
                                  payload=self.plan(), summary=["ask"], expires=time.time() + 3000)
        return store, receipt["request_id"]

    def file2(self):
        store = RequestStore(self.config.state_dir / "requests.sqlite3")
        payload = self.plan()
        payload = dict(payload, expires_at=tb.BrokerTests.other_expiry(payload))
        receipt, _ = store.submit(kind="install", software="htop", device=DEVICE, owner=OWNER,
                                  proposer=SimpleNamespace(client="claude-connector", name="claude"),
                                  payload=payload, summary=["ask"], expires=time.time() + 3000)
        return store, receipt["request_id"]

    def state(self, rid):
        return RequestStore(self.config.state_dir / "requests.sqlite3").status(rid, owner=OWNER, device=DEVICE)

    NOT_STARTED = {"state": "not_started"}

    # --- provisioning and lost state ----------------------------------------------------------------
    def test_a_normal_start_never_creates_state(self):
        with self.assertRaises(service.ConfigError) as refused:
            self.start(self.broker(self.NOT_STARTED))
        self.assertIn("not_provisioned", str(refused.exception))
        self.assertFalse(self.config.state_dir.exists())

    def test_provision_creates_private_state_once_and_refuses_to_reset_it(self):
        self.provision()
        for name in service.PROVISIONED:
            self.assertEqual((self.config.state_dir / name).stat().st_mode & 0o777, 0o600, name)
        self.assertEqual(self.config.state_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual(json.loads((self.config.state_dir / "revoked-clients.json").read_text()), {"revoked": []})
        with self.assertRaises(service.ConfigError):
            self.provision()

    def test_losing_both_the_request_store_and_the_revocation_list_does_not_become_a_pristine_start(self):
        self.provision()
        from stynpilot.server.clients import RevocationFile
        RevocationFile(self.config.state_dir / "revoked-clients.json").set_revoked("claude-connector", True)
        for name in ("requests.sqlite3", "revoked-clients.json"):
            (self.config.state_dir / name).unlink()
        with self.assertRaises(service.ConfigError):
            self.start(self.broker(self.NOT_STARTED))
        self.assertFalse((self.config.state_dir / "revoked-clients.json").exists())       # nothing re-created
        for name in os.listdir(self.config.state_dir):
            (self.config.state_dir / name).unlink()                                      # even if everything is gone
        with self.assertRaises(service.ConfigError):
            self.start(self.broker(self.NOT_STARTED))

    def test_an_unreadable_revocation_list_stops_the_service(self):
        self.provision()
        (self.config.state_dir / "revoked-clients.json").write_text("not json")
        with self.assertRaises(Exception):
            self.start(self.broker(self.NOT_STARTED))

    def test_a_group_readable_state_folder_is_refused(self):
        self.provision()
        os.chmod(self.config.state_dir, 0o755)
        with self.assertRaises(service.ConfigError):
            self.start(self.broker(self.NOT_STARTED))

    # --- startup ordering with the root installer ---------------------------------------------------
    def test_start_runs_the_background_worker_and_both_loopback_listeners(self):
        self.provision()
        svc = self.start(self.broker(self.NOT_STARTED))
        self.assertIsNotNone(svc.flow._pool)
        page = httpx.Client(base_url="http://127.0.0.1:%d" % self.approval_port, timeout=10, trust_env=False)
        self.addCleanup(page.close)
        self.assertEqual(page.get("/approve/" + "a" * 64, headers={"Host": self.config.approval_public_host}).status_code, 400)
        self.assertEqual(page.get("/approve/" + "a" * 64, headers={"Host": "evil.example"}).status_code, 421)

    def test_user_service_starting_before_the_root_installer_waits_instead_of_marking_the_owner(self):
        self.provision()
        store, rid = self.file()
        store.transition(rid, "pending", "approved")
        store.transition(rid, "approved", "running")                               # service died mid-install
        installer = {"answer": OSError("installer socket not there yet")}
        svc = self.start(self.broker(lambda: installer["answer"]))
        self.assertEqual(svc.waiting, [rid])
        self.assertEqual(self.state(rid)["state"], "running")                      # NOT needs_owner_intervention
        self.assertEqual(service.reconcile_waiting(svc), [rid])                    # still not up: still waiting
        self.assertEqual(self.state(rid)["state"], "running")
        installer["answer"] = {"state": "done", "result": {"ok": True, "rollback_id": "r1"}}    # root comes up late
        self.assertEqual(service.reconcile_waiting(svc), [])
        self.assertEqual(self.state(rid)["state"], "done")                          # the real result, no spurious alarm
        self.assertEqual(self.state(rid)["result"]["rollback_id"], "r1")

    def test_a_run_the_installer_says_is_still_running_is_waited_for_not_replayed_or_alarmed(self):
        self.provision()
        store, rid = self.file()
        store.transition(rid, "pending", "approved")
        store.transition(rid, "approved", "running")
        answer = {"v": {"state": "running"}}
        svc = self.start(self.broker(lambda: answer["v"]))
        self.assertEqual(svc.waiting, [rid])
        answer["v"] = {"state": "done", "result": {"ok": True}}
        service.reconcile_waiting(svc)
        self.assertEqual(self.state(rid)["state"], "done")

    def test_a_long_installer_outage_is_reported_honestly_and_nothing_is_replayed(self):
        self.provision()
        store, rid = self.file()
        store.transition(rid, "pending", "approved")
        svc = self.start(self.broker(OSError("down")))
        self.assertEqual(service.reconcile_waiting(svc, now=1000.0), [rid])        # outage clock starts
        self.assertEqual(self.state(rid)["state"], "approved")
        self.assertEqual(service.reconcile_waiting(svc, now=1599.0), [rid])        # not yet ten minutes
        self.assertEqual(service.reconcile_waiting(svc, now=1600.0), [])
        status = self.state(rid)
        self.assertEqual(status["state"], "needs_owner_intervention")
        self.assertIsNone(status["result"]["changed_anything"])
        self.assertEqual(status["result"]["stopped"], "installer_unreachable_owner_must_verify")

    def test_a_legitimately_running_install_longer_than_ten_minutes_is_monitored_until_it_finishes(self):
        self.provision()
        store, rid = self.file()
        store.transition(rid, "pending", "approved")
        store.transition(rid, "approved", "running")
        answer = {"v": {"state": "running"}}
        svc = self.start(self.broker(lambda: answer["v"]))
        for minute in (1, 5, 11, 30, 90):                                           # reachable and running throughout
            self.assertEqual(service.reconcile_waiting(svc, now=1000.0 + minute * 60), [rid])
            self.assertEqual(self.state(rid)["state"], "running")                   # never an outage, never intervention
        answer["v"] = {"state": "done", "result": {"ok": True, "rollback_id": "r9"}}
        self.assertEqual(service.reconcile_waiting(svc, now=1000.0 + 95 * 60), [])
        self.assertEqual((self.state(rid)["state"], self.state(rid)["result"]["rollback_id"]), ("done", "r9"))
        # same for a failure the installer reports
        store2, rid2 = self.file2()
        store2.transition(rid2, "pending", "approved")
        store2.transition(rid2, "approved", "running")
        answer["v"] = {"state": "running"}
        svc.waiting.append(rid2)
        service.reconcile_waiting(svc, now=9000.0)
        answer["v"] = {"state": "failed", "result": {"ok": False, "stopped": "install_failed", "changed_anything": False}}
        service.reconcile_waiting(svc, now=99999.0)
        self.assertEqual(self.state(rid2)["state"], "failed")

    def test_the_outage_clock_restarts_when_the_installer_answers_in_between(self):
        self.provision()
        store, rid = self.file()
        store.transition(rid, "pending", "approved")
        store.transition(rid, "approved", "running")
        answer = {"v": OSError("down")}
        svc = self.start(self.broker(lambda: answer["v"]))
        service.reconcile_waiting(svc, now=0.0)
        answer["v"] = {"state": "running"}
        service.reconcile_waiting(svc, now=500.0)                                   # reachable: clock reset
        answer["v"] = OSError("down again")
        service.reconcile_waiting(svc, now=1000.0)                                  # new outage starts here
        self.assertEqual(service.reconcile_waiting(svc, now=1500.0), [rid])         # only 500s of outage
        self.assertEqual(service.reconcile_waiting(svc, now=1600.0), [])            # 600s: now honestly reported
        self.assertEqual(self.state(rid)["state"], "needs_owner_intervention")

    def test_the_installer_saying_it_never_saw_the_request_settles_it_as_unchanged(self):
        self.provision()
        store, rid = self.file()
        store.transition(rid, "pending", "approved")
        svc = self.start(self.broker(self.NOT_STARTED))
        self.assertEqual(svc.recovered, [rid])
        self.assertEqual(self.state(rid)["state"], "failed")
        self.assertIs(self.state(rid)["result"]["changed_anything"], False)

    # --- the AI-facing endpoint on the same store ---------------------------------------------------
    def token(self, azp, scope="health.read workspace.propose"):
        now = int(time.time())
        claims = {"iss": ISS, "aud": "https://%s/mcp" % MCP_HOST, "sub": "auth0|test-owner", "iat": now,
                  "exp": now + 300, "scope": scope, "azp": azp}
        return "Bearer " + jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "k1"})

    def test_both_assistants_file_and_read_the_same_durable_request_but_cannot_decide_it(self):
        self.provision()
        answer = {"v": self.NOT_STARTED}
        svc = self.start(self.broker(lambda: answer["v"]))
        client = httpx.Client(base_url="http://127.0.0.1:%d" % self.mcp_port, headers={"Host": MCP_HOST}, timeout=10,
                              trust_env=False)
        self.addCleanup(client.close)

        def call(azp, name, arguments):
            reply = client.post("/mcp", headers={**MCP_HEADERS, "Authorization": self.token(azp)}, json={
                "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}})
            result = reply.json()["result"]
            return result.get("structuredContent") or json.loads(result["content"][0]["text"])
        listed = client.post("/mcp", headers={**MCP_HEADERS, "Authorization": self.token("claude-connector")},
                             json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).json()["result"]["tools"]
        self.assertFalse([t["name"] for t in listed if any(w in t["name"] for w in ("approve", "decide", "deny", "confirm"))])
        filed = call("claude-connector", "commander_request_software_install", {"device_id": DEVICE, "software": "htop"})
        self.assertTrue(filed["ok"], filed)
        rid = filed["result"]["request_id"]
        self.assertTrue(filed["result"]["owner_approval_url"].startswith("https://ryzen.example.test:8444/approve/"))
        for azp in ("claude-connector", "chatgpt-connector"):
            seen = call(azp, "commander_software_install_status", {"device_id": DEVICE, "request_id": rid})
            self.assertEqual(seen["result"]["state"], "pending", azp)
        # the owner approves through the OWNER page + installer (here: the installer's record shows it done)
        store = RequestStore(self.config.state_dir / "requests.sqlite3")
        store.transition(rid, "pending", "approved")
        store.transition(rid, "approved", "running")
        store.transition(rid, "running", "done", result={"ok": True, "rollback_id": "r1"})
        for azp in ("claude-connector", "chatgpt-connector"):
            seen = call(azp, "commander_software_install_status", {"device_id": DEVICE, "request_id": rid})
            self.assertEqual(seen["result"]["state"], "done", azp)
        # nothing on the AI-facing app can reach the approval page
        for path in ("/approve/" + rid, "/approve/choose", "/approve/callback"):
            self.assertIn(client.get(path).status_code, (404, 405))


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


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class KeyRotationTests(unittest.TestCase):
    setUpClass = classmethod(tb.BrokerTests.setUpClass.__func__)
    plan, proof = tb.BrokerTests.plan, tb.BrokerTests.proof
    other_expiry = staticmethod(tb.BrokerTests.other_expiry)

    def setUp(self):
        tb.BrokerTests.setUp(self)
        from stynpilot.broker.proof import ProofVerifier
        new = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = jwt.algorithms.RSAAlgorithm.to_jwk(new.public_key(), as_dict=True)
        public.update(kid="k2", use="sig", alg="RS256")
        self.new_key, self.rotated = new, {"keys": [public]}
        self.fetches, self.provider = [], {"jwks": self.rotated}
        self.now = [1000.0]

        def loader():
            self.fetches.append(1)
            if isinstance(self.provider["jwks"], Exception):
                raise self.provider["jwks"]
            return self.provider["jwks"]
        self.verifier = ProofVerifier(issuer=ISS, approval_client_id=tb.APP, jwks=self.jwks, jwks_loader=loader,
                                      monotonic=lambda: self.now[0])

    def token(self, key, kid, *, alg="RS256", aud=tb.APP, nonce="n" * 20):
        now = int(time.time())
        return jwt.encode({"iss": ISS, "aud": aud, "sub": "auth0|test-owner", "iat": now, "exp": now + 300,
                           "auth_time": now, "nonce": nonce}, key, algorithm=alg, headers={"kid": kid})

    def verify(self, token, nonce="n" * 20):
        return self.verifier.verify(token, expected_nonce=nonce, owner=OWNER)

    def test_a_token_from_a_rotated_signing_key_verifies_after_one_refresh(self):
        self.assertTrue(self.verify(self.token(self.key, "k1")))                     # known key: no fetch
        self.assertEqual(self.fetches, [])
        self.assertTrue(self.verify(self.token(self.new_key, "k2")))                 # provider rotated
        self.assertEqual(len(self.fetches), 1)

    def test_refresh_never_weakens_checks_and_is_rate_limited(self):
        from stynpilot.broker.proof import ProofDenied
        forged = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaises(ProofDenied):
            self.verify(self.token(forged, "k2"))                                     # right kid, wrong signature
        with self.assertRaises(ProofDenied):
            self.verify(self.token(forged, "unknown"))
        with self.assertRaises(ProofDenied):
            self.verify(self.token(forged, "unknown2"))
        self.assertEqual(len(self.fetches), 1)                                        # cooldown: one fetch, not three
        self.now[0] += 31
        with self.assertRaises(ProofDenied):
            self.verify(self.token(forged, "unknown3"))
        self.assertEqual(len(self.fetches), 2)
        with self.assertRaises(ProofDenied):
            self.verify(self.token(self.new_key, "k2", aud="someone-else"))           # audience still pinned
        with self.assertRaises(ProofDenied):
            self.verify(self.token("x" * 40, "k2", alg="HS256"))                      # still RS256 only

    def test_a_bad_or_failed_refresh_keeps_the_old_keys(self):
        from stynpilot.broker.proof import ProofDenied
        self.provider["jwks"] = RuntimeError("provider down")
        with self.assertRaises(ProofDenied):
            self.verify(self.token(self.new_key, "k2"))
        self.assertTrue(self.verify(self.token(self.key, "k1")))                       # old key still works
        self.now[0] += 31
        self.provider["jwks"] = {"keys": [{"kty": "oct", "kid": "k9", "k": "AAAA"}]}   # malformed/forbidden key set
        with self.assertRaises(ProofDenied):
            self.verify(self.token(self.new_key, "k9"))
        self.assertTrue(self.verify(self.token(self.key, "k1")))

    def test_a_wrong_issuer_or_owner_is_still_refused_after_rotation(self):
        from stynpilot.broker.proof import ProofDenied
        self.assertTrue(self.verify(self.token(self.new_key, "k2")))
        with self.assertRaises(ProofDenied):
            self.verifier.verify(self.token(self.new_key, "k2"), expected_nonce="n" * 20, owner="acct_" + "0" * 40)


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class CommandLineTests(unittest.TestCase):
    """The real process entry point (what systemd would run), not just the functions."""

    def test_owner_refuses_to_start_unprovisioned_then_provision_works_once(self):
        import subprocess
        import sys
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        tmp = Path(t.name)
        path = tmp / "owner.json"
        path.write_text(json.dumps(owner_data(tmp, pairing_db=str(tmp / "pairing.db"))))
        os.chmod(path, 0o600)
        env = dict(os.environ, PYTHONPATH=str(Path(service.__file__).resolve().parent.parent), PYTHONDONTWRITEBYTECODE="1")

        def cli(role):
            return subprocess.run([sys.executable, "-m", "stynpilot.service", role, "--config", str(path)],
                                  capture_output=True, text=True, env=env, timeout=60)
        refused = cli("owner")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("not_provisioned", refused.stderr)
        self.assertEqual(cli("provision").returncode, 0)
        again = cli("provision")
        self.assertNotEqual(again.returncode, 0)
        self.assertIn("refusing_to_reset", again.stderr)


class UnitFileTests(unittest.TestCase):
    root = Path(__file__).resolve().parent.parent / "deploy" / "systemd"

    def read(self, name):
        return (self.root / name).read_text()

    def test_owner_unit_is_unprivileged_and_hardened(self):
        text = self.read("stynpilot-owner.service")
        self.assertNotIn("User=root", text)
        for line in ("NoNewPrivileges=yes", "ProtectSystem=strict", "/usr/bin/stynpilot service owner"):
            self.assertIn(line, text)

    def test_installer_unit_is_root_only_and_runs_the_installer_role(self):
        text = self.read("stynpilot-installer.service")
        self.assertIn("User=root", text)
        self.assertIn("/usr/bin/stynpilot service installer", text)
        self.assertIn("RuntimeDirectory=stynpilot", text)

    def test_unit_paths_match_the_sample_configs(self):
        owner_unit, installer_unit = self.read("stynpilot-owner.service"), self.read("stynpilot-installer.service")
        sample_owner = json.loads((self.root.parent / "owner.example.json").read_text())
        sample_installer = json.loads((self.root.parent / "installer.example.json").read_text())
        writable = [l.split("=", 1)[1].lstrip("-").replace("-%h", "%h").replace("%h", "/home/owner") for l in owner_unit.splitlines()
                    if l.startswith("ReadWritePaths=")][0]
        self.assertTrue(any(sample_owner["state_dir"].startswith(w) for w in writable.replace(" -", " ").split()), (sample_owner["state_dir"], writable))
        self.assertIn("StateDirectory=stynpilot-installer", installer_unit)
        self.assertEqual(sample_installer["state_dir"], "/var/lib/stynpilot-installer")
        self.assertEqual(os.path.dirname(sample_installer["socket_path"]), "/run/stynpilot")
        self.assertIn("RuntimeDirectory=stynpilot", installer_unit)
        self.assertIn("--config /etc/stynpilot/installer.json", installer_unit)
        self.assertIn(".config/stynpilot/owner.json", owner_unit)
        # a user service can't order itself after a system service; the code waits patiently instead
        self.assertNotIn("After=stynpilot-installer", owner_unit)

    def test_sample_configs_carry_only_placeholders(self):
        for name in ("owner.example.json", "installer.example.json"):
            text = (self.root.parent / name).read_text().lower()
            for bad in ("dtdev_", "auth0|", "acct_", "secret"):
                self.assertNotIn(bad, text)

    def test_units_carry_no_secrets_or_public_listeners(self):
        for name in ("stynpilot-owner.service", "stynpilot-installer.service"):
            text = self.read(name).lower()
            for bad in ("token", "secret", "password", "0.0.0.0", "dtdev_", "auth0|"):
                self.assertNotIn(bad, text)


if __name__ == "__main__":
    unittest.main()
