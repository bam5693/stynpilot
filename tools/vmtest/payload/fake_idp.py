#!/usr/bin/python3
"""TEST-ONLY stand-in for Auth0 inside the disposable VM. It signs ID tokens exactly like an OpenID provider would
(RS256, kid, iss/aud/sub/iat/exp/auth_time/nonce) and checks PKCE, so the real StyNpilot code paths run unchanged.
It "signs the owner in" automatically, which is what the real owner's passkey/Face ID step replaces on the Ryzen.
NEVER installed on a real machine.  Usage: fake_idp.py CERT KEY STATE_DIR"""
import base64
import hashlib
import http.server
import json
import os
import secrets
import ssl
import sys
import threading
import time
import urllib.parse

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CERT, KEY, STATE = sys.argv[1:4]
ISS = "https://auth.g8test.example/"
OWNER_SUB = "auth0|g8-owner"
os.makedirs(STATE, exist_ok=True)
KEYFILE = os.path.join(STATE, "signing.pem")
if os.path.exists(KEYFILE):
    signing = serialization.load_pem_private_key(open(KEYFILE, "rb").read(), None)
else:
    signing = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    open(KEYFILE, "wb").write(signing.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(signing.public_key(), as_dict=True)
JWK.update(kid="g8k1", use="sig", alg="RS256")
CODES, LOCK = {}, threading.Lock()


def sign(claims):
    return jwt.encode(claims, signing, algorithm="RS256", headers={"kid": "g8k1"})


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        sys.stderr.write("idp: " + (a[0] % a[1:]) + "\n")

    def send(self, code, body=b"", ctype="application/json", headers=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        if url.path == "/.well-known/openid-configuration":
            return self.send(200, json.dumps({"issuer": ISS, "authorization_endpoint": ISS + "authorize",
                                              "token_endpoint": ISS + "oauth/token", "jwks_uri": ISS + ".well-known/jwks.json",
                                              "revocation_endpoint": ISS + "oauth/revoke",
                                              "response_types_supported": ["code"], "code_challenge_methods_supported": ["S256"],
                                              "grant_types_supported": ["authorization_code", "refresh_token"],
                                              "scopes_supported": ["openid", "offline_access"]}).encode())
        if url.path == "/.well-known/jwks.json":
            return self.send(200, json.dumps({"keys": [JWK]}).encode())
        if url.path == "/authorize":                         # the owner "signs in": allowed only with the whole PKCE request
            need = ("client_id", "redirect_uri", "state", "nonce", "code_challenge", "response_type")
            if any(k not in q for k in need) or q.get("code_challenge_method") != "S256" or q["response_type"] != "code":
                return self.send(400, b'{"error":"invalid_request"}')
            code = secrets.token_urlsafe(24)
            with LOCK:
                CODES[code] = dict(q, used=False, made=time.time())
            back = q["redirect_uri"] + ("&" if "?" in q["redirect_uri"] else "?") + urllib.parse.urlencode({"code": code, "state": q["state"]})
            return self.send(302, b"", headers=[("Location", back)])
        if url.path == "/ai-token":                          # TEST helper: a bearer for an enrolled AI client
            now = int(time.time())
            token = sign({"iss": ISS, "aud": "https://%s/mcp" % q["mcp_host"], "sub": OWNER_SUB, "iat": now, "exp": now + 600,
                          "scope": "health.read workspace.propose", "azp": q["azp"]})
            return self.send(200, json.dumps({"token": token}).encode())
        self.send(404, b"{}")

    def do_POST(self):
        if self.path != "/oauth/token":
            return self.send(404, b"{}")
        form = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()).items()}
        with LOCK:
            entry = CODES.get(form.get("code"))
            if not entry or entry["used"] or time.time() - entry["made"] > 120:
                return self.send(400, b'{"error":"invalid_grant"}')
            entry["used"] = True
        challenge = base64.urlsafe_b64encode(hashlib.sha256(form.get("code_verifier", "").encode()).digest()).rstrip(b"=").decode()
        if challenge != entry["code_challenge"] or form.get("client_id") != entry["client_id"] or form.get("redirect_uri") != entry["redirect_uri"]:
            return self.send(400, b'{"error":"invalid_grant"}')
        now = int(time.time())
        token = sign({"iss": ISS, "aud": entry["client_id"], "sub": OWNER_SUB, "iat": now, "exp": now + 300,
                      "auth_time": now, "nonce": entry["nonce"]})
        self.send(200, json.dumps({"id_token": token, "token_type": "Bearer"}).encode())


server = http.server.ThreadingHTTPServer(("127.0.0.1", 443), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
