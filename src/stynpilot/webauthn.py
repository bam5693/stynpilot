"""Strict WebAuthn verification for the owner's passkeys (standard library + ``cryptography``).

Scope is deliberately narrow, because this is security-sensitive code:
* ONE algorithm: ES256 (ECDSA P-256 with SHA-256, COSE alg -7). Anything else is refused.
* Registration accepts attestation format "none" only (no attestation parsing, no trust roots, no metadata service).
* Every ceremony is checked against values the INSTALLER chose: relying-party ID, exact origin, and a challenge it issued.
* User verification (fingerprint / screen lock) is REQUIRED on every assertion, not just at registration.
* A tiny CBOR reader handles exactly the shapes WebAuthn uses (definite lengths only, bounded depth and size).

It proves "the holder of this passkey, with the phone unlocked by fingerprint or PIN, signed THIS challenge on THIS origin".
It does not prove what the screen showed; the installer's single-use challenge is bound to the exact request and plan.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature  # noqa: F401  (documented dependency)

FLAG_UP, FLAG_UV, FLAG_BE, FLAG_BS, FLAG_AT, FLAG_ED = 0x01, 0x04, 0x08, 0x10, 0x40, 0x80
MAX_BYTES = 8192
COSE_ES256 = -7


class WebAuthnError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def b64u_decode(text):
    if type(text) is not str or len(text) > MAX_BYTES * 2 or not text.isascii():
        raise WebAuthnError("malformed_value")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        raise WebAuthnError("malformed_value") from None


def b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# -- minimal CBOR ----------------------------------------------------------------------------------------------
def _cbor(data, pos=0, depth=0):
    if depth > 6 or pos >= len(data):
        raise WebAuthnError("malformed_cbor")
    first = data[pos]
    major, info = first >> 5, first & 0x1F
    pos += 1
    if info < 24:
        value = info
    elif info in (24, 25, 26, 27):
        size = {24: 1, 25: 2, 26: 4, 27: 8}[info]
        if pos + size > len(data):
            raise WebAuthnError("malformed_cbor")
        value = int.from_bytes(data[pos:pos + size], "big")
        pos += size
    else:
        raise WebAuthnError("malformed_cbor")                      # indefinite lengths and reserved values are refused
    if major == 0:
        return value, pos
    if major == 1:
        return -1 - value, pos
    if major in (2, 3):
        if value > MAX_BYTES or pos + value > len(data):
            raise WebAuthnError("malformed_cbor")
        raw = bytes(data[pos:pos + value])
        if major == 3:
            try:
                return raw.decode("utf-8"), pos + value
            except UnicodeDecodeError:
                raise WebAuthnError("malformed_cbor") from None
        return raw, pos + value
    if major == 4:
        if value > 64:
            raise WebAuthnError("malformed_cbor")
        items = []
        for _ in range(value):
            item, pos = _cbor(data, pos, depth + 1)
            items.append(item)
        return items, pos
    if major == 5:
        if value > 64:
            raise WebAuthnError("malformed_cbor")
        out = {}
        for _ in range(value):
            key, pos = _cbor(data, pos, depth + 1)
            item, pos = _cbor(data, pos, depth + 1)
            if type(key) not in (int, str) or key in out:
                raise WebAuthnError("malformed_cbor")
            out[key] = item
        return out, pos
    raise WebAuthnError("malformed_cbor")


def cbor_decode(data):
    if type(data) is not bytes or len(data) > MAX_BYTES:
        raise WebAuthnError("malformed_cbor")
    value, pos = _cbor(data)
    if pos != len(data):
        raise WebAuthnError("malformed_cbor")                      # no trailing bytes
    return value


# -- authenticator data ------------------------------------------------------------------------------------------
def parse_auth_data(raw):
    """rpIdHash(32) | flags(1) | signCount(4) | [attested credential data] (no extensions accepted)."""
    if type(raw) is not bytes or len(raw) < 37 or len(raw) > MAX_BYTES:
        raise WebAuthnError("malformed_authenticator_data")
    flags = raw[32]
    out = {"rp_id_hash": raw[:32], "flags": flags, "sign_count": struct.unpack(">I", raw[33:37])[0],
           "user_present": bool(flags & FLAG_UP), "user_verified": bool(flags & FLAG_UV),
           "backup_eligible": bool(flags & FLAG_BE), "backup_state": bool(flags & FLAG_BS), "credential": None}
    if flags & FLAG_ED:
        raise WebAuthnError("extensions_not_accepted")
    rest = raw[37:]
    if flags & FLAG_AT:
        if len(rest) < 18:
            raise WebAuthnError("malformed_authenticator_data")
        credential_id_length = struct.unpack(">H", rest[16:18])[0]
        if not 16 <= credential_id_length <= 128 or len(rest) < 18 + credential_id_length:
            raise WebAuthnError("malformed_authenticator_data")
        credential_id = bytes(rest[18:18 + credential_id_length])
        key, end = _cbor(bytes(rest), 18 + credential_id_length)
        if end != len(rest):
            raise WebAuthnError("malformed_authenticator_data")
        out["credential"] = {"aaguid": bytes(rest[:16]).hex(), "id": credential_id, "key": key}
    elif rest:
        raise WebAuthnError("malformed_authenticator_data")
    return out


def public_key_from_cose(key):
    if (type(key) is not dict or key.get(1) != 2 or key.get(3) != COSE_ES256 or key.get(-1) != 1
            or type(key.get(-2)) is not bytes or type(key.get(-3)) is not bytes or len(key[-2]) != 32 or len(key[-3]) != 32):
        raise WebAuthnError("unsupported_key")                      # ES256 on P-256 only
    try:
        public = ec.EllipticCurvePublicNumbers(int.from_bytes(key[-2], "big"), int.from_bytes(key[-3], "big"), ec.SECP256R1()).public_key()
    except ValueError:
        raise WebAuthnError("unsupported_key") from None
    return public, key[-2] + key[-3]


def public_key_from_xy(xy):
    if type(xy) is not bytes or len(xy) != 64:
        raise WebAuthnError("unsupported_key")
    try:
        return ec.EllipticCurvePublicNumbers(int.from_bytes(xy[:32], "big"), int.from_bytes(xy[32:], "big"), ec.SECP256R1()).public_key()
    except ValueError:
        raise WebAuthnError("unsupported_key") from None


# -- client data -----------------------------------------------------------------------------------------------
def _client_data(raw, *, kind, challenge, origin):
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise WebAuthnError("malformed_client_data")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise WebAuthnError("malformed_client_data") from None
    if type(data) is not dict or data.get("type") != kind:
        raise WebAuthnError("wrong_ceremony_type")
    if data.get("crossOrigin") not in (None, False):
        raise WebAuthnError("cross_origin_refused")
    if data.get("origin") != origin:
        raise WebAuthnError("wrong_origin")
    got = data.get("challenge")
    if type(got) is not str or not hmac.compare_digest(got, b64u_encode(challenge)):
        raise WebAuthnError("wrong_challenge")
    return data


def rp_hash(rp_id):
    return hashlib.sha256(rp_id.encode("ascii")).digest()


# -- ceremonies --------------------------------------------------------------------------------------------------
def verify_registration(response, *, rp_id, origin, challenge):
    """``response``: dict(client_data_json, attestation_object) as base64url strings. Returns what to pin."""
    if type(response) is not dict:
        raise WebAuthnError("malformed_value")
    client = b64u_decode(response.get("client_data_json"))
    _client_data(client, kind="webauthn.create", challenge=challenge, origin=origin)
    attestation = cbor_decode(b64u_decode(response.get("attestation_object")))
    if type(attestation) is not dict or attestation.get("fmt") != "none" or attestation.get("attStmt") != {}:
        raise WebAuthnError("attestation_not_accepted")
    raw = attestation.get("authData")
    if type(raw) is not bytes:
        raise WebAuthnError("malformed_authenticator_data")
    auth = parse_auth_data(raw)
    if not hmac.compare_digest(auth["rp_id_hash"], rp_hash(rp_id)):
        raise WebAuthnError("wrong_relying_party")
    if not auth["user_present"] or not auth["user_verified"]:
        raise WebAuthnError("user_verification_required")
    if auth["credential"] is None:
        raise WebAuthnError("no_credential")
    _, xy = public_key_from_cose(auth["credential"]["key"])
    return {"credential_id": b64u_encode(auth["credential"]["id"]), "public_key": xy.hex(), "aaguid": auth["credential"]["aaguid"],
            "backup_eligible": auth["backup_eligible"], "backup_state": auth["backup_state"], "sign_count": auth["sign_count"]}


def verify_assertion(response, *, rp_id, origin, challenge, public_key_xy):
    """``response``: dict(client_data_json, authenticator_data, signature) as base64url strings, already matched to a pinned key.
    Returns the parsed authenticator data (flags, sign_count). User verification is required."""
    if type(response) is not dict:
        raise WebAuthnError("malformed_value")
    client = b64u_decode(response.get("client_data_json"))
    _client_data(client, kind="webauthn.get", challenge=challenge, origin=origin)
    raw = b64u_decode(response.get("authenticator_data"))
    auth = parse_auth_data(raw)
    if auth["credential"] is not None:
        raise WebAuthnError("malformed_authenticator_data")
    if not hmac.compare_digest(auth["rp_id_hash"], rp_hash(rp_id)):
        raise WebAuthnError("wrong_relying_party")
    if not auth["user_present"] or not auth["user_verified"]:
        raise WebAuthnError("user_verification_required")
    signature = b64u_decode(response.get("signature"))
    if not 8 <= len(signature) <= 80:
        raise WebAuthnError("malformed_value")
    try:
        public_key_from_xy(public_key_xy).verify(signature, raw + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise WebAuthnError("signature_invalid") from None
    return auth
