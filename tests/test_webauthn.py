import os, sys, unittest
sys.path.insert(0, os.path.dirname(__file__))
from cryptography.hazmat.primitives.asymmetric import ec
from softauth import SoftAuthenticator, cbor
from stynpilot import webauthn as w

RP, ORIGIN = "deckplayhq.tail4bc147.ts.net", "https://deckplayhq.tail4bc147.ts.net:8443"
CH = os.urandom(32)


def reg(a, **kw):
    return w.verify_registration(a.register(CH, **kw), rp_id=RP, origin=ORIGIN, challenge=CH)


def asr(a, resp, ch=CH, xy=None):
    return w.verify_assertion(resp, rp_id=RP, origin=ORIGIN, challenge=ch, public_key_xy=xy or a.xy)


class Registration(unittest.TestCase):
    def setUp(self):
        self.a = SoftAuthenticator(ORIGIN, RP)

    def test_valid_records_synced_flags(self):
        r = reg(self.a)
        self.assertTrue(r["backup_eligible"] and r["backup_state"])
        self.assertEqual(r["public_key"], self.a.xy.hex())

    def test_device_bound(self):
        r = reg(SoftAuthenticator(ORIGIN, RP, backup_eligible=False, backup_state=False))
        self.assertFalse(r["backup_eligible"])

    def test_refusals(self):
        for kw, code in [({"origin": "https://evil.example"}, "wrong_origin"), ({"rp_id": "evil.example"}, "wrong_relying_party"),
                         ({"fmt": "packed"}, "attestation_not_accepted"), ({"att_stmt": {"x": 1}}, "attestation_not_accepted"),
                         ({"kind": "webauthn.get"}, "wrong_ceremony_type"), ({"extra_client": {"crossOrigin": True}}, "cross_origin_refused"),
                         ({"cose": {1: 2, 3: -257, -1: 1, -2: bytes(32), -3: bytes(32)}}, "unsupported_key")]:
            with self.assertRaises(w.WebAuthnError, msg=kw) as c:
                reg(self.a, **kw)
            self.assertEqual(c.exception.code, code)

    def test_wrong_challenge_and_no_uv(self):
        with self.assertRaises(w.WebAuthnError) as c:
            w.verify_registration(self.a.register(os.urandom(32)), rp_id=RP, origin=ORIGIN, challenge=CH)
        self.assertEqual(c.exception.code, "wrong_challenge")
        with self.assertRaises(w.WebAuthnError) as c:
            reg(SoftAuthenticator(ORIGIN, RP, uv=False))
        self.assertEqual(c.exception.code, "user_verification_required")


class Assertion(unittest.TestCase):
    def setUp(self):
        self.a = SoftAuthenticator(ORIGIN, RP)

    def test_valid_and_zero_counter(self):
        self.assertEqual(asr(self.a, self.a.assert_(CH))["sign_count"], 0)

    def test_refusals(self):
        other = ec.generate_private_key(ec.SECP256R1())
        for kw, code in [({"origin": "https://evil.example"}, "wrong_origin"), ({"rp_id": "evil.example"}, "wrong_relying_party"),
                         ({"flags": 0x01}, "user_verification_required"), ({"flags": 0x04}, "user_verification_required"),
                         ({"flags": 0x05 | 0x80}, "extensions_not_accepted"), ({"flags": 0x05 | 0x40}, "malformed_authenticator_data"),
                         ({"kind": "webauthn.create"}, "wrong_ceremony_type"), ({"tamper": True}, "signature_invalid"),
                         ({"sign_with": other}, "signature_invalid"), ({"extra_client": {"crossOrigin": True}}, "cross_origin_refused")]:
            with self.assertRaises(w.WebAuthnError, msg=kw) as c:
                asr(self.a, self.a.assert_(CH, **kw))
            self.assertEqual(c.exception.code, code, kw)

    def test_challenge_binding(self):
        with self.assertRaises(w.WebAuthnError) as c:
            asr(self.a, self.a.assert_(CH), ch=os.urandom(32))
        self.assertEqual(c.exception.code, "wrong_challenge")

    def test_other_key(self):
        with self.assertRaises(w.WebAuthnError) as c:
            asr(self.a, self.a.assert_(CH), xy=SoftAuthenticator(ORIGIN, RP).xy)
        self.assertEqual(c.exception.code, "signature_invalid")

    def test_garbage(self):
        for bad in (None, {}, {"client_data_json": 5}, {"client_data_json": "!!", "authenticator_data": "", "signature": ""}):
            with self.assertRaises(w.WebAuthnError):
                asr(self.a, bad)


class Cbor(unittest.TestCase):
    def test_roundtrip(self):
        v = {"a": [1, -5, b"xy", "z"], 3: {}}
        self.assertEqual(w.cbor_decode(cbor(v)), v)

    def test_hostile(self):
        for raw in (b"\x5f\xff", b"\xa1\x01\x01\x01\x02", b"\xa2\x01\x01\x01\x02", b"\x01\x00", b"\x7f", b"\x81" * 20 + b"\x00", b"\x59\xff\xff"):
            with self.assertRaises(w.WebAuthnError):
                w.cbor_decode(raw)


if __name__ == "__main__":
    unittest.main()
