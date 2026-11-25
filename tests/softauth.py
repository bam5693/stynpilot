"""A SOFTWARE AUTHENTICATOR for tests: the same bytes a phone's passkey produces (real P-256 keys, real ECDSA, real CBOR,
real authenticator data), with knobs to make every kind of wrong or hostile response."""
import hashlib
import json
import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from stynpilot.webauthn import b64u_encode


def cbor(value):
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
        raise ValueError
    if isinstance(value, bool) or value is None:
        raise TypeError
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(v) for v in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(type(value))


class SoftAuthenticator:
    def __init__(self, origin, rp_id, *, backup_eligible=True, backup_state=True, uv=True, counter=0, synced_counter_zero=True):
        self.origin, self.rp_id = origin, rp_id
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.backup_eligible, self.backup_state, self.uv = backup_eligible, backup_state, uv
        self.counter, self.synced_counter_zero = counter, synced_counter_zero

    @property
    def xy(self):
        n = self.key.public_key().public_numbers()
        return n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")

    def _flags(self, attested):
        flags = 0x01 | (0x04 if self.uv else 0) | (0x08 if self.backup_eligible else 0) | (0x10 if self.backup_state else 0)
        return flags | (0x40 if attested else 0)

    def _client(self, kind, challenge, origin=None, extra=None):
        data = {"type": kind, "challenge": b64u_encode(challenge), "origin": origin or self.origin, "crossOrigin": False}
        data.update(extra or {})
        return json.dumps(data, separators=(",", ":")).encode()

    def register(self, challenge, *, rp_id=None, origin=None, fmt="none", att_stmt=None, cose=None, kind="webauthn.create", extra_client=None):
        key = cose or {1: 2, 3: -7, -1: 1, -2: self.xy[:32], -3: self.xy[32:]}
        attested = (hashlib.sha256((rp_id or self.rp_id).encode()).digest() + bytes([self._flags(True)]) + struct.pack(">I", self.counter)
                    + bytes(16) + struct.pack(">H", len(self.credential_id)) + self.credential_id + cbor(key))
        client = self._client(kind, challenge, origin, extra_client)
        return {"client_data_json": b64u_encode(client),
                "attestation_object": b64u_encode(cbor({"fmt": fmt, "attStmt": att_stmt if att_stmt is not None else {}, "authData": attested}))}

    def assert_(self, challenge, *, rp_id=None, origin=None, flags=None, kind="webauthn.get", extra_client=None, sign_with=None, tamper=False):
        if not self.synced_counter_zero:
            self.counter += 1
        flag_byte = self._flags(False) if flags is None else flags
        auth = hashlib.sha256((rp_id or self.rp_id).encode()).digest() + bytes([flag_byte]) + struct.pack(">I", self.counter)
        client = self._client(kind, challenge, origin, extra_client)
        signed = auth + hashlib.sha256(client).digest()
        signature = (sign_with or self.key).sign(signed, ec.ECDSA(hashes.SHA256()))
        if tamper:
            signature = signature[:-1] + bytes([signature[-1] ^ 1])
        return {"client_data_json": b64u_encode(client), "authenticator_data": b64u_encode(auth), "signature": b64u_encode(signature),
                "credential_id": b64u_encode(self.credential_id)}
