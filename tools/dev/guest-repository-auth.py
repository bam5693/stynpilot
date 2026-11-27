"""Exercise installed MCP, phone passkey, broker, and synthetic provider over HTTPS."""
import base64
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import ssl
import sys
import threading
import time
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).parent))
fixture = __import__("guest-restore")

import httpx
import jwt
from softauth import SoftAuthenticator
from stynpilot.approval_web import COOKIE
from stynpilot.broker.passkeys import PasskeyStore
from stynpilot.upgrade_worker import endpoint_answers
from test_repository_auth import DEVICE, FakeGitLab, REFRESH, SECRET, TARGET

HOST = "owner.example.test"


def mock_provider():
    cert, key = Path("/tmp/repository-provider.crt"), Path("/tmp/repository-provider.key")
    fixture.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-subj", "/CN=gitlab.com", "-addext", "subjectAltName=DNS:gitlab.com",
                    "-out", str(cert), "-keyout", str(key))
    Path("/usr/local/share/ca-certificates/stynpilot-fixture-gitlab.crt").write_bytes(cert.read_bytes())
    fixture.command("update-ca-certificates")
    with Path("/etc/hosts").open("a") as hosts:
        hosts.write("\n127.0.0.2 gitlab.com\n")
    app = FakeGitLab()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, data, content_type="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            target = urlsplit(self.path)
            if target.path == "/oauth/device" and target.query == "user_code=EXAMPLE-123":
                app.ready = True
                self.reply(200, b"Synthetic provider approval", "text/plain")
            elif self.path == "/team/fixture.git/info/refs?service=git-upload-pack":
                expected = "Basic " + base64.b64encode(("oauth2:" + SECRET + str(app.refresh_count)).encode()).decode()
                if self.headers.get("Authorization") != expected:
                    self.reply(401, b"{}")
                    return
                self.reply(200, b"001e# service=git-upload-pack\n0000", "application/x-git-upload-pack-advertisement")
            elif self.path == "/oauth/token/info":
                status, data = app(self.path, bearer=self.headers.get("Authorization", "").removeprefix("Bearer "))
                self.reply(status, json.dumps(data).encode())
            else:
                self.reply(404, b"{}")

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            data = {key: value[0] for key, value in parse_qs(raw.decode()).items()}
            status, answer = app(self.path, data=data)
            if self.path == "/oauth/token" and status == 200:
                answer["expires_in"] = 45 if "device_code" in data else 7200
            self.reply(status, json.dumps(answer).encode())

    server = ThreadingHTTPServer(("127.0.0.2", 443), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return app, cert


def main():
    app, cert = mock_provider()
    fixture.ETC.mkdir(mode=0o700, exist_ok=True)
    fixture.write(fixture.ETC / "repository-authorization.json", {"fixture-private": TARGET})
    signing_key = fixture.setup(check_restore_path=False, lab=True)
    keys = PasskeyStore(fixture.STATE / "passkeys.sqlite3", rp_id=HOST, origin="https://" + HOST)
    authenticator = SoftAuthenticator("https://" + HOST, HOST)
    enrollment = "e" * 64
    keys.open_window(enrollment, "Repository owner fixture", "fixture")
    key = keys.complete(enrollment, authenticator.register(bytes.fromhex(keys.begin(enrollment)["challenge"])))
    keys.activate(key["kid"], key["label"], key["pub"], enrollment, "fixture")

    with (httpx.Client(base_url="http://127.0.0.1:18443", headers={"Host": HOST}, timeout=30, trust_env=False) as mcp,
          httpx.Client(base_url="http://127.0.0.1:18444", headers={"Host": HOST}, timeout=30, trust_env=False) as phone,
          httpx.Client(verify=ssl.create_default_context(cafile=str(cert)), timeout=15, trust_env=False) as provider):
        def call(name, client="fixture", **args):
            now = int(time.time())
            token = jwt.encode({"iss": fixture.ISSUER, "aud": "https://" + HOST + "/mcp", "sub": "fixture|test-owner",
                                "iat": now, "exp": now + 120, "azp": client, "scope": "health.read workspace.propose"},
                               signing_key, algorithm="RS256", headers={"kid": "fixture"})
            response = mcp.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": name, "arguments": {"device_id": fixture.DEVICE, **args}}},
                headers={"Authorization": "Bearer " + token, "Accept": "application/json, text/event-stream",
                         "MCP-Protocol-Version": "2025-03-26"})
            response.raise_for_status()
            assert all(secret not in response.text for secret in (DEVICE, SECRET, REFRESH))
            result = response.json()["result"]
            return result.get("structuredContent") or json.loads(result["content"][0]["text"])

        def approve(action, **args):
            filed = call("commander_request_repository_access", action=action, **args)
            assert filed["ok"], filed
            rid = filed["result"]["request_id"]
            page = phone.get("/approve/" + rid)
            page.raise_for_status()
            assert "Approval requires an enrolled passkey" in page.text
            options = json.loads(html.unescape(re.search("data-o='([^']+)'", page.text).group(1)))
            nonce = base64.urlsafe_b64decode(options["challenge"]["approve"] + "==")
            assertion = json.dumps(authenticator.assert_(nonce))
            path = "/approve/status/" + rid
            reply = phone.post("/approve/passkey", headers={"Origin": "https://" + HOST, "Cookie": COOKIE + "=" + options["view"]},
                               json={"view": options["view"], "csrf": options["csrf"],
                                     "decision": "approve", "assertion": assertion})
            reply.raise_for_status()
            assert reply.json()["ok"], reply.text
            fixture.until(lambda: "<h1>Done</h1>" in phone.get(path).text, 20)
            return rid, options["csrf"], options["view"]

        repository = {"repository": "fixture-private"}
        assert call("repository_private_readiness", **repository)["error"] == "repository_grant_unavailable"
        assert not call("commander_request_repository_access", action="authorize", operations=["push"], days=1, **repository)["result"]["ok"]
        rid, csrf, view = approve("authorize", operations=["read"], days=1, **repository)
        connection = "/approve/repository/" + rid
        origin = {"Origin": "https://" + HOST, "Cookie": COOKIE + "=" + view}
        assert phone.post(connection, data={"csrf": "different", "step": "start"}, headers=origin).status_code == 400
        opened = phone.post(connection, data={"csrf": csrf, "step": "start"}, headers=origin)
        opened.raise_for_status()
        assert DEVICE not in opened.text
        link = html.unescape(re.search(r"href='(https://gitlab\.com/oauth/device[^']+)'", opened.text).group(1))
        provider.get(link).raise_for_status()
        time.sleep(5)
        connected = phone.post(connection, data={"csrf": csrf, "step": "check"}, headers=origin)
        assert "Repository connected" in connected.text, connected.status_code
        assert all(secret not in connected.text for secret in (DEVICE, SECRET, REFRESH))
        assert call("repository_access_grants", client="fixture-other")["result"]["grants"] == []
        assert call("repository_private_readiness", client="fixture-other", **repository)["error"] == "repository_grant_unavailable"
        assert call("repository_private_readiness", repository="unknown")["error"] == "repository_provider_not_configured"
        fixture.command("systemctl", "restart", "stynpilot-installer.service")
        fixture.until(lambda: fixture.broker("runner", "repository_grants", {"client": "fixture"}), 20)
        assert call("repository_private_readiness", **repository)["result"] == {"readable": True}
        assert app.refresh_count == 1
        approve("suspend")
        assert call("repository_private_readiness", **repository)["error"] == "repository_access_suspended"
        approve("resume")
        state_path = fixture.STATE / "repository-authorization/grants.json"
        persisted = json.loads(state_path.read_bytes())
        persisted["grants"][rid]["expires"] = int(time.time()) - 1
        fixture.write(state_path, persisted)
        assert call("repository_private_readiness", **repository)["error"] == "repository_grant_unavailable"
        approve("revoke", **repository)
        assert call("repository_private_readiness", **repository)["error"] == "repository_grant_unavailable"
        app.principal = 99
        refused_id, csrf, view = approve("authorize", operations=["read"], days=1, **repository)
        connection = "/approve/repository/" + refused_id
        origin = {"Origin": "https://" + HOST, "Cookie": COOKIE + "=" + view}
        phone.post(connection, data={"csrf": csrf, "step": "start"}, headers=origin).raise_for_status()
        time.sleep(5)
        refused = phone.post(connection, data={"csrf": csrf, "step": "check"}, headers=origin)
        assert refused.status_code == 400 and "repository_provider_scope_mismatch" in refused.text
        assert call("repository_private_readiness", **repository)["error"] == "repository_grant_unavailable"
        assert all(secret not in state_path.read_text() for secret in (SECRET, REFRESH))
        installer_log = fixture.command("journalctl", "-b", "-u", "stynpilot-installer.service", "--no-pager")
        owner_log = fixture.command("journalctl", "-b", "_SYSTEMD_USER_UNIT=stynpilot-owner.service", "--no-pager")
        assert all(secret not in installer_log + owner_log for secret in (DEVICE, SECRET, REFRESH))
        fixture.until(lambda: endpoint_answers({"port": 18443, "host": HOST}), 20)

    __import__("guest-archive-mcp").main(signing_key, require_redaction=True)
    print("STYNPILOT_PACKAGED_REPOSITORY_AUTH_OK", flush=True)


if __name__ == "__main__":
    main()
