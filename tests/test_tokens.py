"""Real RS256 tokens against the verifier (needs the [server] extras; skipped otherwise)."""
import time
import unittest

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from stynpilot.server.tokens import RotatingTokenVerifier, TokenVerifier
except ImportError:          # pragma: no cover - optional dependencies
    jwt = None

from stynpilot.identity import MemoryRevocations, TokenDenied, account_id

ISS, AUD = "https://issuer.example.test/", "https://ryzen.example.test/mcp"


def keypair(kid):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    public.update(kid=kid, use="sig", alg="RS256")
    return key, public


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class TokenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key, cls.public = keypair("k1")
        cls.other_key, cls.other_public = keypair("k2")

    def setUp(self):
        self.revocations = MemoryRevocations()
        self.verifier = TokenVerifier(issuer=ISS, audience=AUD, jwks={"keys": [self.public]},
                                      allowed_scopes=frozenset({"health.read", "workspace.propose"}),
                                      revocations=self.revocations)

    def token(self, key=None, kid="k1", **claims):
        now = int(time.time())
        body = {"iss": ISS, "aud": AUD, "sub": "auth0|owner", "iat": now, "exp": now + 300, "scope": "health.read"}
        body.update(claims)
        body = {k: v for k, v in body.items() if v is not None}
        return "Bearer " + jwt.encode(body, key or self.key, algorithm="RS256", headers={"kid": kid})

    def test_good_token(self):
        who = self.verifier.authorize(self.token(), required_scope="health.read")
        self.assertEqual(who.account, account_id(verified_issuer=ISS, verified_subject="auth0|owner"))
        self.assertIn("health.read", who.scopes)

    def test_refusals(self):
        now = int(time.time())
        bad = {
            "expired": self.token(exp=now - 60, iat=now - 120),
            "wrong audience": self.token(aud="https://elsewhere.test/mcp"),
            "wrong issuer": self.token(iss="https://evil.test/"),
            "no subject": self.token(sub=None),
            "missing scope": self.token(scope="openid"),
            "unknown key": self.token(key=self.other_key, kid="k2"),
            "forged with other key": self.token(key=self.other_key, kid="k1"),
            "not bearer": self.token().replace("Bearer ", "Basic "),
        }
        for label, header in bad.items():
            with self.subTest(label), self.assertRaises(TokenDenied):
                self.verifier.authorize(header, required_scope="health.read")

    def test_scope_not_on_server_allowlist_is_refused_even_if_token_has_it(self):
        with self.assertRaises(TokenDenied):
            self.verifier.authorize(self.token(scope="health.read workspace.review"), required_scope="workspace.review")

    def test_header_key_urls_and_hs256_refused(self):
        now = int(time.time())
        body = {"iss": ISS, "aud": AUD, "sub": "x", "iat": now, "exp": now + 60, "scope": "health.read"}
        jku = jwt.encode(body, self.key, algorithm="RS256", headers={"kid": "k1", "jku": "https://evil.test/jwks"})
        hs = jwt.encode(body, "x" * 32, algorithm="HS256", headers={"kid": "k1"})
        for token in (jku, hs):
            with self.assertRaises(TokenDenied):
                self.verifier.authorize("Bearer " + token, required_scope="health.read")

    def test_revocation_cutoff_and_broken_store(self):
        header = self.token(iat=int(time.time()) - 10)
        account = account_id(verified_issuer=ISS, verified_subject="auth0|owner")
        self.revocations.revoke_before(ISS, account, int(time.time()))
        with self.assertRaises(TokenDenied):
            self.verifier.authorize(header, required_scope="health.read")

        class Broken:
            def revoked_before(self, *a):
                raise OSError("disk gone")
        self.verifier.revocations = Broken()
        with self.assertRaises(TokenDenied):
            self.verifier.authorize(self.token(), required_scope="health.read")

    def test_bad_key_sets_rejected(self):
        for jwks in ({}, {"keys": []}, {"keys": [dict(self.public, kty="EC")]}, {"keys": [self.public, self.public]}):
            with self.subTest(jwks=str(jwks)[:30]), self.assertRaises(ValueError):
                TokenVerifier(issuer=ISS, audience=AUD, jwks=jwks, allowed_scopes=frozenset({"health.read"}))

    def test_ai_clients_stay_separate_from_the_owner_and_each_other(self):
        chatgpt = self.verifier.authorize(self.token(azp="chatgpt-connector"), required_scope="health.read")
        claude = self.verifier.authorize(self.token(azp="claude-connector"), required_scope="health.read")
        self.assertEqual(chatgpt.account, claude.account)          # same owner...
        self.assertNotEqual(chatgpt.client, claude.client)         # ...two distinct AI clients
        self.assertEqual(self.verifier.authorize(self.token(client_id="m2m-app"),
                                                 required_scope="health.read").client, "m2m-app")
        self.assertIsNone(self.verifier.authorize(self.token(), required_scope="health.read").client)
        for bad in ("", "has space", "x" * 200, 7):
            with self.subTest(bad=bad), self.assertRaises(TokenDenied):
                self.verifier.authorize(self.token(azp=bad), required_scope="health.read")

    def test_rotating_picks_up_new_key_and_expires_stale_keys(self):
        now = [1000.0]
        keysets = [{"keys": [self.public]}]
        rotating = RotatingTokenVerifier(issuer=ISS, audience=AUD, initial_jwks={"keys": [self.public]},
                                         jwks_loader=lambda: keysets[0], allowed_scopes=frozenset({"health.read"}),
                                         revocations=self.revocations, clock=lambda: now[0])
        keysets[0] = {"keys": [self.other_public]}
        who = rotating.authorize(self.token(key=self.other_key, kid="k2"), required_scope="health.read")
        self.assertTrue(who.account.startswith("acct_"))

        def fail():
            raise OSError("issuer down")
        rotating._loader = fail
        now[0] += 3700
        with self.assertRaises(TokenDenied):
            rotating.authorize(self.token(key=self.other_key, kid="k2"), required_scope="health.read")


if __name__ == "__main__":
    unittest.main()
