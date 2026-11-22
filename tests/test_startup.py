"""The real startup path: loopback listener, metadata, host checks and signed tokens end to end.

Uses a real uvicorn server on 127.0.0.1, real RS256 tokens, a fake identity
provider (injected fetch, no network) and a pairing database in the prototype's
layout. Needs the [server] extras; skipped otherwise.
"""
import socket
import tempfile
import time
import unittest
from pathlib import Path

try:
    import httpx
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from stynpilot.server import run
    from stynpilot.server.oidc import OIDCConfig
except ImportError:          # pragma: no cover - optional dependencies
    run = None

from legacy_pairing import make_pairing_db
from stynpilot.devices import PairingDeviceGrants
from stynpilot.identity import account_id

ISS = "https://issuer.example.test/"
HOST = "ryzen.example.test"
AUDIENCE = "https://%s/mcp" % HOST
DEVICE = "dtdev_TESTONLYliveDevice"
SUBJECT = "auth0|test-owner"
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
               "MCP-Protocol-Version": "2025-06-18"}


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@unittest.skipIf(run is None, "server extras not installed")
class StartupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key(), as_dict=True)
        public.update(kid="k1", use="sig", alg="RS256")
        cls.jwks = {"keys": [public]}

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        owner = account_id(verified_issuer=ISS, verified_subject=SUBJECT)
        self.tmp = Path(tmp.name)
        path = make_pairing_db(self.tmp / "state", [(DEVICE, owner, time.time() + 3600, None, ["workspace.propose"])])
        self.grants = PairingDeviceGrants(path)
        self.addCleanup(self.grants.close)
        docs = {ISS + ".well-known/openid-configuration": {
                    "issuer": ISS, "authorization_endpoint": ISS + "authorize", "token_endpoint": ISS + "oauth/token",
                    "jwks_uri": ISS + ".well-known/jwks.json", "revocation_endpoint": ISS + "oauth/revoke",
                    "response_types_supported": ["code"], "code_challenge_methods_supported": ["S256"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "scopes_supported": ["openid", "offline_access"]},
                ISS + ".well-known/jwks.json": self.jwks}
        from stynpilot.identity import MemoryRevocations
        tokens = OIDCConfig(issuer=ISS, audience=AUDIENCE, revocations=MemoryRevocations(),
                            allowed_scopes=frozenset({"health.read", "workspace.propose"}),
                            allow_volatile_revocations=True, fetch=docs.__getitem__).build_verifier()
        self.router_args = dict(tokens=tokens, grants=self.grants, read_health=lambda: {"cpu_usage_percent": 2.0})
        router = run.router_for_paired_device(tokens=tokens, grants=self.grants,
                                              read_health=lambda: {"cpu_usage_percent": 2.0},
                                              read_service_status=lambda s: {"state": "setup_required"})
        self.port = free_port()
        self.running = run.start(router=router, public_host=HOST, port=self.port)
        self.addCleanup(self.running.stop)
        self.client = httpx.Client(base_url="http://127.0.0.1:%d" % self.port, headers={"Host": HOST}, timeout=10, trust_env=False)
        self.addCleanup(self.client.close)

    def token(self, sub=SUBJECT, scope="health.read", azp="claude-connector"):
        now = int(time.time())
        claims = {"iss": ISS, "aud": AUDIENCE, "sub": sub, "iat": now, "exp": now + 300, "scope": scope, "azp": azp}
        return "Bearer " + jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "k1"})

    def rpc(self, method, params, token, rid=1):
        return self.client.post("/mcp", headers={**MCP_HEADERS, "Authorization": token},
                                json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params})

    @staticmethod
    def output(reply):
        result = reply.json()["result"]
        if isinstance(result.get("structuredContent"), dict):
            return result["structuredContent"]
        return __import__("json").loads(result["content"][0]["text"])

    def initialize(self, token):
        return self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                       "clientInfo": {"name": "test", "version": "1"}}, token)

    def test_metadata_document(self):
        reply = self.client.get("/.well-known/oauth-protected-resource/mcp")
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.json(), {"resource": AUDIENCE, "authorization_servers": [ISS],
                                        "scopes_supported": ["health.read"], "bearer_methods_supported": ["header"]})
        self.assertEqual(reply.headers["cache-control"], "no-store")

    def test_unknown_host_is_refused(self):
        reply = self.client.get("/.well-known/oauth-protected-resource/mcp", headers={"Host": "evil.test"})
        self.assertEqual(reply.status_code, 400)
        bad = httpx.post("http://127.0.0.1:%d/mcp" % self.port, headers={**MCP_HEADERS, "Host": "evil.test",
                         "Authorization": self.token()}, json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                         trust_env=False)
        self.assertNotEqual(bad.status_code, 200)

    def test_no_token_gets_401_pointing_at_the_metadata(self):
        reply = self.client.post("/mcp", headers=MCP_HEADERS, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        self.assertEqual(reply.status_code, 401)
        self.assertIn("resource_metadata=", reply.headers.get("www-authenticate", ""))
        self.assertIn("/.well-known/oauth-protected-resource", reply.headers.get("www-authenticate", ""))

    def test_signed_owner_token_reads_health_and_status_end_to_end(self):
        token = self.token()
        self.assertEqual(self.initialize(token).status_code, 200)
        listed = self.rpc("tools/list", {}, token, 2)
        self.assertEqual(sorted(t["name"] for t in listed.json()["result"]["tools"]),
                         ["computer_health", "software_service_status"])
        called = self.rpc("tools/call", {"name": "computer_health", "arguments": {"device_id": DEVICE}}, token, 3)
        self.assertEqual(self.output(called)["metrics"], {"cpu_usage_percent": 2.0})
        status = self.rpc("tools/call", {"name": "software_service_status",
                                         "arguments": {"device_id": DEVICE, "software": "forgejo"}}, token, 4)
        self.assertEqual(self.output(status)["status"]["state"], "setup_required")

    def test_someone_elses_token_and_wrong_scope_are_refused(self):
        stranger = self.token(sub="auth0|someone-else")
        self.assertEqual(self.initialize(stranger).status_code, 200)   # valid token, but not the owner
        called = self.rpc("tools/call", {"name": "computer_health", "arguments": {"device_id": DEVICE}}, stranger, 2)
        self.assertEqual(self.output(called), {"ok": False, "error": "device_unavailable_or_not_authorized"})
        self.assertEqual(self.initialize(self.token(scope="openid")).status_code, 401)

    def test_only_loopback_and_unprivileged_ports(self):
        for address, port in (("0.0.0.0", free_port()), ("192.0.2.1", free_port()), ("127.0.0.1", 80),
                              ("::1", free_port()), ("127.0.0.2", free_port()), ("127.0.0.1", True)):
            with self.subTest(address=address, port=port), self.assertRaises(PermissionError):
                run.start(router=None, public_host=HOST, port=port, address=address)


    def test_malformed_public_hosts_fail_before_startup(self):
        bad = ["", "evil.test@" + HOST, HOST + "?x=1", HOST + "#frag", "has space.test", HOST + ":443",
               "a%2fb.test", "-lead.test", "trail-.test", "nodot", "x" * 64 + ".test", HOST + "/mcp",
               "tab\tname.test", "ünicode.test", None, 7]
        for host in bad:
            with self.subTest(host=host), self.assertRaises((ValueError, PermissionError)):
                run.start(router=None, public_host=host, port=free_port())
        self.assertEqual(run.check_public_host("Computer-1.Tail0a1b2c.ts.net"), "computer-1.tail0a1b2c.ts.net")


    # --- G5: the approval page is a separate, local-only listener the AI-facing app cannot reach ---------------
    def approval_flow(self):
        from stynpilot.approval import ApprovalFlow
        from stynpilot.requests import RequestStore
        store = RequestStore(self.tmp / "state" / "approval-requests.sqlite3")
        return ApprovalFlow(store=store, broker=None, exchange=lambda c, v: "x",
                            authorize={"endpoint": ISS + "authorize", "client_id": "approval-app",
                                       "redirect_uri": "https://%s/approve/callback" % HOST})

    def test_approval_listener_is_local_only_host_checked_and_separate_from_the_mcp_app(self):
        flow = self.approval_flow()
        for address, port in (("0.0.0.0", free_port()), ("192.0.2.1", free_port()), ("::1", free_port()),
                              ("127.0.0.1", 80), ("127.0.0.1", True)):
            with self.subTest(address=address, port=port), self.assertRaises(PermissionError):
                run.start_approval(flow=flow, public_host=HOST, port=port, address=address)
        for host in ("", "evil/x", "has space.example", "a.b:0", "a.b:99999", "a.b:08", "http://a.b", "localhost"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                run.start_approval(flow=flow, public_host=host, port=free_port())
        self.assertEqual(run.check_approval_host("Ryzen.Example.Test:8444"), "ryzen.example.test:8444")
        port = free_port()
        running = run.start_approval(flow=flow, public_host=HOST, port=port)
        self.addCleanup(running.stop)
        self.assertEqual(running.local_url, "http://127.0.0.1:%d/approve" % port)
        self.assertEqual(running.server.config.host, "127.0.0.1")
        page = httpx.Client(base_url="http://127.0.0.1:%d" % port, timeout=10, trust_env=False)
        self.addCleanup(page.close)
        self.assertEqual(page.get("/approve/" + "a" * 64, headers={"Host": HOST}).status_code, 400)   # reached, unknown
        self.assertEqual(page.get("/approve/" + "a" * 64, headers={"Host": "evil.example"}).status_code, 421)
        self.assertEqual(page.get("/approve/" + "a" * 64).status_code, 421)                          # raw 127.0.0.1 host
        # the AI-facing MCP app on its own port serves none of it
        for method, path in (("GET", "/approve/" + "a" * 64), ("POST", "/approve/choose"), ("GET", "/approve/callback"),
                             ("GET", "/approve/status/" + "a" * 64)):
            reply = self.client.request(method, path)
            self.assertIn(reply.status_code, (404, 405), (method, path))

    def test_request_tools_end_to_end_with_signed_tokens(self):
        from stynpilot.requests import RequestStore
        from stynpilot.server.clients import EnrolledClients, RevocationFile
        store = RequestStore(self.tmp / "state" / "requests.sqlite3")
        enrolled = [{"client_id": "claude-connector", "name": "claude", "kind": "claude"}]
        with self.assertRaises(ValueError):           # memory-only revocations are refused in production
            run.start(router=None, public_host=HOST, port=free_port(),
                      propose=dict(clients=EnrolledClients(enrolled), store=store))
        revocations = RevocationFile(self.tmp / "state" / "revoked.json")
        revocations.provision()
        propose = dict(clients=EnrolledClients(enrolled, revocations=revocations),
                       store=store, resolve_apt=lambda names: [{"name": "htop", "version": "3.3.0-4build1"}, {"name": "libnl-3-200", "version": "3.7.0-0.3build1.1"}])
        port = free_port()
        running = run.start(router=run.router_for_paired_device(**self.router_args), public_host=HOST,
                            port=port, propose=propose)
        self.addCleanup(running.stop)
        client = httpx.Client(base_url="http://127.0.0.1:%d" % port, headers={"Host": HOST}, timeout=10,
                              trust_env=False)
        self.addCleanup(client.close)
        listed = client.post("/mcp", headers={**MCP_HEADERS, "Authorization": self.token(scope="health.read workspace.propose")},
                             json={"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {}}).json()["result"]["tools"]
        names = {t["name"] for t in listed}
        self.assertFalse([n for n in names if "approve" in n or "decide" in n or "confirm" in n], names)   # no AI approval tool
        meta = client.get("/.well-known/oauth-protected-resource/mcp").json()
        self.assertEqual(meta["scopes_supported"], ["health.read", "workspace.propose"])

        def call(token, name, arguments):
            reply = client.post("/mcp", headers={**MCP_HEADERS, "Authorization": token}, json={
                "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}})
            return self.output(reply)
        both = "health.read workspace.propose"
        filed = call(self.token(scope=both), "commander_request_software_install", {"device_id": DEVICE, "software": "htop"})
        self.assertTrue(filed["ok"], filed)
        self.assertEqual(filed["result"]["requested_by"], "claude")
        status = call(self.token(scope=both), "commander_software_install_status",
                      {"device_id": DEVICE, "request_id": filed["result"]["request_id"]})
        self.assertEqual(status["result"]["state"], "pending")
        self.assertEqual(call(self.token(scope=both, azp="not-enrolled"), "commander_request_software_install",
                              {"device_id": DEVICE, "software": "htop"}),
                         {"ok": False, "error": "client_not_enrolled_or_revoked"})
        self.assertEqual(call(self.token(scope="health.read"), "commander_request_software_install",
                              {"device_id": DEVICE, "software": "htop"}), {"ok": False, "error": "not_authorized"})


if __name__ == "__main__":
    unittest.main()
