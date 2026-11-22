"""Identity-provider discovery is checked strictly before any key is trusted."""
import unittest

from stynpilot.identity import MemoryRevocations
from stynpilot.server.oidc import OIDCConfig, OIDCError, jwks_uri_from_discovery

ISS = "https://issuer.example.test/"


def discovery(**over):
    doc = {"issuer": ISS, "authorization_endpoint": ISS + "authorize", "token_endpoint": ISS + "oauth/token",
           "jwks_uri": ISS + ".well-known/jwks.json", "revocation_endpoint": ISS + "oauth/revoke",
           "response_types_supported": ["code"], "code_challenge_methods_supported": ["S256"],
           "grant_types_supported": ["authorization_code", "refresh_token"],
           "scopes_supported": ["openid", "offline_access", "profile"]}
    doc.update(over)
    return doc


class OIDCTests(unittest.TestCase):
    def test_good_discovery(self):
        self.assertEqual(jwks_uri_from_discovery(ISS, discovery()), ISS + ".well-known/jwks.json")

    def test_bad_discovery_is_refused(self):
        cases = {
            "issuer mismatch": discovery(issuer="https://evil.test/"),
            "jwks elsewhere": discovery(jwks_uri="https://evil.test/jwks.json"),
            "plain http": discovery(token_endpoint="http://issuer.example.test/oauth/token"),
            "creds in url": discovery(jwks_uri="https://u:p@issuer.example.test/jwks"),
            "no pkce": discovery(code_challenge_methods_supported=["plain"]),
            "no refresh": discovery(grant_types_supported=["authorization_code"]),
            "no code flow": discovery(response_types_supported=["token"]),
            "not a dict": [],
        }
        for label, doc in cases.items():
            with self.subTest(label), self.assertRaises(OIDCError):
                jwks_uri_from_discovery(ISS, doc)

    def test_durable_revocations_required(self):
        with self.assertRaises(OIDCError):
            OIDCConfig(issuer=ISS, audience="https://ryzen.example.test/mcp", revocations=MemoryRevocations(),
                       allowed_scopes=frozenset({"health.read"}))
        OIDCConfig(issuer=ISS, audience="https://ryzen.example.test/mcp", revocations=MemoryRevocations(),
                   allowed_scopes=frozenset({"health.read"}), allow_volatile_revocations=True)

    def test_fetch_never_leaves_the_issuer(self):
        config = OIDCConfig(issuer=ISS, audience="https://a.test/mcp", revocations=MemoryRevocations(),
                            allowed_scopes=frozenset({"health.read"}), allow_volatile_revocations=True)
        for url in ("https://evil.test/x", "http://issuer.example.test/x", "https://issuer.example.test:8443/x"):
            with self.subTest(url), self.assertRaises(OIDCError):
                config._fetch_json(url)


if __name__ == "__main__":
    unittest.main()
