"""The owner's approval proof: an Auth0-signed ID token bound to ONE exact plan.

Why a signed token and not a database row: the StyNpilot service that talks to
ChatGPT and Claude runs as the owner's normal user. If it were compromised, it could
write any file that user can write, including a fake "approved" row. It cannot
produce Auth0's signature. So the root installer accepts only this proof:

- an ID token signed by the owner's Auth0 tenant (RS256, a key from the trusted JWKS),
- issued to the StyNpilot approval app (``aud`` = its client ID),
- for the owner's own account (``sub`` maps to the request's owner account),
- recent (``auth_time`` within a few minutes), so a stale sign-in can't approve,
- whose ``nonce`` equals ``approval_nonce(request_id, plan_sha256)``. The approval page
  (G5) starts the sign-in with that nonce, so the signature covers this exact plan.

The installer also remembers every proof it has used (root-owned), so a proof works
only once. Needs PyJWT with cryptography (Ubuntu: python3-jwt, python3-cryptography).
"""
from __future__ import annotations

import hashlib
import hmac
import re
import time

import jwt

from ..identity import account_id

_HEX64 = re.compile(r"[a-f0-9]{64}\Z")
MAX_AUTH_AGE = 300            # seconds between the owner's sign-in and the approval
MAX_TOKEN_BYTES = 8192


class ProofDenied(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def approval_nonce(request_id, plan_sha256):
    """What the owner's sign-in must carry to approve exactly this request and plan."""
    for value in (request_id, plan_sha256):
        if type(value) is not str or not _HEX64.fullmatch(value):
            raise ProofDenied("invalid_request")
    return hashlib.sha256(("stynpilot-approve-v1|%s|%s" % (request_id, plan_sha256)).encode()).hexdigest()


def proof_fingerprint(id_token):
    return hashlib.sha256(id_token.encode("ascii", "replace")).hexdigest()


class ProofVerifier:
    def __init__(self, *, issuer, approval_client_id, jwks, clock=time.time):
        from ..server.tokens import _load_keys        # same strict JWKS rules as the endpoint
        if not isinstance(issuer, str) or not issuer.startswith("https://"):
            raise ValueError("HTTPS issuer required")
        if type(approval_client_id) is not str or not approval_client_id:
            raise ValueError("Approval app client ID required")
        self.issuer, self.client_id, self.clock = issuer, approval_client_id, clock
        self.keys = _load_keys(jwks)

    def verify(self, id_token, *, request_id, plan_sha256, owner):
        """Return the proof fingerprint if this token approves exactly this plan for this owner."""
        if type(id_token) is not str or not 20 <= len(id_token) <= MAX_TOKEN_BYTES:
            raise ProofDenied("proof_missing")
        expected = approval_nonce(request_id, plan_sha256)
        try:
            header = jwt.get_unverified_header(id_token)
            if header.get("alg") != "RS256" or "jku" in header or "x5u" in header:
                raise ProofDenied("proof_invalid")
            key = self.keys.get(header.get("kid"))
            if key is None:
                raise ProofDenied("proof_invalid")
            claims = jwt.decode(id_token, key=key, algorithms=["RS256"], issuer=self.issuer,
                                audience=self.client_id, leeway=5,
                                options={"require": ["iss", "aud", "exp", "iat", "sub", "nonce", "auth_time"]})
        except ProofDenied:
            raise
        except (jwt.PyJWTError, TypeError, ValueError):
            raise ProofDenied("proof_invalid") from None
        if not hmac.compare_digest(str(claims.get("nonce")), expected):
            raise ProofDenied("proof_is_for_a_different_plan")
        auth_time = claims.get("auth_time")
        if type(auth_time) is not int or not 0 <= self.clock() - auth_time <= MAX_AUTH_AGE:
            raise ProofDenied("owner_sign_in_not_recent")
        try:
            who = account_id(verified_issuer=self.issuer, verified_subject=claims["sub"])
        except ValueError:
            raise ProofDenied("proof_invalid") from None
        if not hmac.compare_digest(who, owner):
            raise ProofDenied("proof_is_not_from_the_owner")
        return proof_fingerprint(id_token)
