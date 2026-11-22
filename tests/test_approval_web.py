"""The approval web page end to end (Starlette test client) on top of the real root executor."""
import http.server
import json
import threading
import time
import unittest
import urllib.parse

try:
    import jwt
    from starlette.testclient import TestClient
    from stynpilot.approval import ApprovalFlow
    from stynpilot.approval_web import COOKIE, build_app, token_exchange
except ImportError:          # pragma: no cover
    jwt = None

import test_approval as ta
from test_approval import OWNER, DEVICE

HOST = "ryzen.example.test"


@unittest.skipIf(jwt is None, "PyJWT/starlette not installed")
class WebTests(unittest.TestCase):
    setUpClass = classmethod(ta.ApprovalTests.setUpClass.__func__)
    plan, proof, file, exchange, make_flow = (ta.ApprovalTests.plan, ta.ApprovalTests.proof, ta.ApprovalTests.file,
                                              ta.ApprovalTests.exchange, ta.ApprovalTests.make_flow)
    other_expiry = staticmethod(ta.ApprovalTests.other_expiry)

    def setUp(self):
        ta.ApprovalTests.setUp(self)
        self.app = build_app(flow=self.flow, public_host=HOST)
        self.client = TestClient(self.app, base_url="https://" + HOST, follow_redirects=False)

    def open(self, rid, client=None):
        reply = (client or self.client).get("/approve/" + rid)
        self.assertEqual(reply.status_code, 200, reply.text)
        fields = dict(__import__("re").findall(r"name=(view|csrf) value='([^']+)'", reply.text))
        return reply, fields

    def choose(self, fields, decision, client=None, **headers):
        return (client or self.client).post("/approve/choose", content=urllib.parse.urlencode(dict(fields, decision=decision)),
                                            headers=dict({"content-type": "application/x-www-form-urlencoded"}, **headers))

    def test_page_shows_root_text_escaped_with_safe_headers_and_cookie(self):
        payload, rid = self.file()
        reply, fields = self.open(rid)
        self.assertIn("written by the installer", reply.text)
        self.assertIn("exact version 3.3.0-4build1", reply.text)
        self.assertIn("not a full system snapshot", reply.text)
        self.assertIn(rid[:12], reply.text)
        for header, value in (("cache-control", "no-store"), ("x-frame-options", "DENY"), ("referrer-policy", "no-referrer")):
            self.assertEqual(reply.headers[header], value)
        self.assertIn("frame-ancestors 'none'", reply.headers["content-security-policy"])
        cookie = reply.headers["set-cookie"].lower()
        for part in ("httponly", "secure", "samesite=lax", "path=/approve"):
            self.assertIn(part, cookie)
        self.assertEqual(self.machine.changes(), [])

    def test_full_approve_flow_through_the_browser_steps(self):
        payload, rid = self.file()
        _, fields = self.open(rid)
        step = self.choose(fields, "approve", origin="https://" + HOST)
        self.assertEqual(step.status_code, 303)
        location = urllib.parse.urlsplit(step.headers["location"])
        self.assertEqual(location.netloc, "issuer.example.test")
        params = dict(urllib.parse.parse_qsl(location.query))
        self.assertEqual((params["prompt"], params["max_age"], params["code_challenge_method"]), ("login", "0", "S256"))
        self.assertEqual(self.machine.changes(), [])                         # nothing ran before the sign-in returns
        self.last_params = params
        back = self.client.get("/approve/callback", params={"state": params["state"], "code": "auth0-code"})
        self.assertEqual(back.status_code, 200)
        self.assertIn("Approved. The installer ran the plan and finished.", back.text)
        self.assertIn("htop", self.machine.installed)
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["state"], "done")

    def test_deny_flow(self):
        payload, rid = self.file()
        _, fields = self.open(rid)
        step = self.choose(fields, "deny")
        params = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(step.headers["location"]).query))
        self.last_params = params
        back = self.client.get("/approve/callback", params={"state": params["state"], "code": "c"})
        self.assertIn("Denied. Nothing was changed.", back.text)
        self.assertEqual(self.machine.changes(), [])
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["state"], "denied")

    def test_forged_cross_site_or_session_less_posts_are_refused(self):
        payload, rid = self.file()
        _, fields = self.open(rid)
        self.assertEqual(self.choose(fields, "approve", origin="https://evil.example").status_code, 403)
        other_browser = TestClient(self.app, base_url="https://" + HOST, follow_redirects=False)   # no cookie
        self.assertEqual(self.choose(fields, "approve", client=other_browser).status_code, 403)
        self.assertEqual(self.choose(dict(fields, csrf="wrong"), "approve").status_code, 400)
        self.assertEqual(self.client.post("/approve/choose", content=b"x" * 10000,
                                          headers={"content-type": "application/x-www-form-urlencoded"}).status_code, 413)
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["state"], "pending")
        self.assertEqual(self.machine.changes(), [])

    def test_a_callback_from_another_browser_or_replayed_is_refused(self):
        payload, rid = self.file()
        _, fields = self.open(rid)
        step = self.choose(fields, "approve")
        params = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(step.headers["location"]).query))
        self.last_params = params
        stranger = TestClient(self.app, base_url="https://" + HOST, follow_redirects=False)
        refused = stranger.get("/approve/callback", params={"state": params["state"], "code": "c"})
        self.assertEqual(refused.status_code, 400)
        self.assertEqual(self.machine.changes(), [])
        # the state was consumed by the failed attempt, so the real browser needs a fresh page: nothing runs twice
        replay = self.client.get("/approve/callback", params={"state": params["state"], "code": "c"})
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(self.machine.changes(), [])
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["state"], "pending")

    def test_cancelled_sign_in_changes_nothing_and_wrong_hosts_are_refused(self):
        payload, rid = self.file()
        _, fields = self.open(rid)
        self.choose(fields, "approve")
        cancelled = self.client.get("/approve/callback", params={"error": "access_denied", "state": "x"})
        self.assertIn("Nothing was changed", cancelled.text)
        self.assertEqual(self.store.status(rid, owner=OWNER, device=DEVICE)["state"], "pending")
        wrong = TestClient(self.app, base_url="https://evil.example", follow_redirects=False)
        self.assertEqual(wrong.get("/approve/" + rid).status_code, 421)
        self.assertEqual(self.client.get("/approve/not-a-request").status_code, 404)
        self.assertEqual(self.client.get("/approve/" + "f" * 64).status_code, 400)

    def test_token_exchange_requires_https_and_returns_the_id_token(self):
        with self.assertRaises(ValueError):
            token_exchange(token_endpoint="http://issuer.example.test/oauth/token", client_id="a", redirect_uri="https://x")
        seen = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(handler):
                seen.update(dict(urllib.parse.parse_qsl(handler.rfile.read(int(handler.headers["content-length"])).decode())))
                body = json.dumps({"id_token": "tok.en.value", "access_token": "ignored"}).encode()
                handler.send_response(200)
                handler.send_header("content-length", str(len(body)))
                handler.end_headers()
                handler.wfile.write(body)

            def log_message(*a):
                pass
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        exchange = token_exchange(token_endpoint="http://127.0.0.1:%d/oauth/token" % server.server_port, client_id="app",
                                  redirect_uri="https://ryzen.example.test/approve/callback", allow_loopback_http=True)
        self.assertEqual(exchange("the-code", "the-verifier"), "tok.en.value")
        self.assertEqual((seen["grant_type"], seen["code_verifier"], seen["client_id"]),
                         ("authorization_code", "the-verifier", "app"))


if __name__ == "__main__":
    unittest.main()
