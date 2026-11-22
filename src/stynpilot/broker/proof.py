"""The owner's decision proof: an Auth0-signed ID token bound to ONE root-issued challenge.

What this proves, precisely (and what it does not):
- The root installer issues a random, single-use **challenge** for one request and one
  decision ("approve" or "deny"), and renders the plain-English summary of the exact plan
  itself (``render_summary``). The approval page (G5) must show that root-rendered text.
- The owner then signs in to his Auth0 tenant with
  ``nonce = decision_nonce(decision, request_id, plan_sha256, challenge)``. Auth0 signs an
  ID token carrying that nonce.
- The installer accepts the token only if it's signed by the trusted Auth0 keys, for the
  approval app, for the owner's account, with a sign-in under 5 minutes old, and its
  nonce matches a challenge the installer issued, unexpired and unused, for this exact
  request, plan and decision.

So a token proves that the owner freshly authenticated *for this specific decision on
this specific plan*, through a flow the installer started. It does NOT by itself prove
what the owner's screen showed. That depends on the G5 page displaying the
root-rendered summary from a component the AI-facing service can't alter. G5 must meet
that requirement (see MASTER_PLAN G5). A generic Auth0 sign-in, a sign-in without a
root-issued challenge, or a replayed one is never accepted.

Needs PyJWT with cryptography (Ubuntu: python3-jwt, python3-cryptography).
"""
from __future__ import annotations

import hashlib
import hmac
import re
import time

import jwt

from ..identity import account_id

_HEX64 = re.compile(r"[a-f0-9]{64}\Z")
DECISIONS = ("approve", "deny")
MAX_AUTH_AGE = 300            # seconds between the owner's sign-in and the decision
MAX_TOKEN_BYTES = 8192


class ProofDenied(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def decision_nonce(decision, request_id, plan_sha256, challenge):
    if decision not in DECISIONS:
        raise ProofDenied("invalid_decision")
    for value in (request_id, plan_sha256, challenge):
        if type(value) is not str or not _HEX64.fullmatch(value):
            raise ProofDenied("invalid_request")
    text = "stynpilot-decision-v2|%s|%s|%s|%s" % (decision, request_id, plan_sha256, challenge)
    return hashlib.sha256(text.encode()).hexdigest()


def summary_hash(lines):
    """Fingerprint of the root-rendered summary, so a relay that alters the text is detected."""
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def proof_fingerprint(id_token):
    return hashlib.sha256(id_token.encode("ascii", "replace")).hexdigest()


def render_summary(payload):
    """Plain-English text of an install or rollback payload, produced by the root installer itself."""
    if payload.get("kind") == "rollback":
        return ["Roll back %s (install %s)." % (payload.get("software"), str(payload.get("rollback_id"))[:12]),
                "Packages that install added are removed (their settings files are kept); packages it "
                "upgraded go back to their saved earlier versions. Application data and other changes are not restored.",
                "Expires %s UTC." % str(payload.get("expires_at")).replace("T", " ").rstrip("Z")]
    lines = ["Install %s on device ending ...%s." % (payload.get("software"), str(payload.get("device"))[-4:])]
    for step in payload.get("steps", []):
        for package in step.get("packages", []):
            lines.append("Package %s, exact version %s, from the Ubuntu archive." % (package["name"], package["version"]))
    lines.append("Backup limits: this saves the packages it changes and their tracked settings files so they can be "
                 "rolled back. It is not a full system snapshot: application data and other changes are not restored.")
    lines.append("Expires %s UTC." % str(payload.get("expires_at")).replace("T", " ").rstrip("Z"))
    return lines


class ProofVerifier:
    def __init__(self, *, issuer, approval_client_id, jwks, clock=time.time):
        from ..server.tokens import _load_keys        # same strict JWKS rules as the endpoint
        if not isinstance(issuer, str) or not issuer.startswith("https://"):
            raise ValueError("HTTPS issuer required")
        if type(approval_client_id) is not str or not approval_client_id:
            raise ValueError("Approval app client ID required")
        self.issuer, self.client_id, self.clock = issuer, approval_client_id, clock
        self.keys = _load_keys(jwks)

    def verify(self, id_token, *, expected_nonce, owner):
        """Return the proof fingerprint if this token carries exactly ``expected_nonce`` for the owner."""
        if type(id_token) is not str or not 20 <= len(id_token) <= MAX_TOKEN_BYTES:
            raise ProofDenied("proof_missing")
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
        if not hmac.compare_digest(str(claims.get("nonce")), expected_nonce):
            raise ProofDenied("proof_is_for_a_different_decision")
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
