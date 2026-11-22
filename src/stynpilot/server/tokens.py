"""Verify the owner's Auth0 access tokens (RS256 JWT) for the MCP endpoint.

Ported from the GitLab prototype (mcp_token_verifier.py). Needs PyJWT with
cryptography (``pip install stynpilot[server]``).

Only keys from a server-trusted JWKS are used; header-supplied key URLs (jku, x5u)
are refused. Issuer, audience, expiry, issued-at and subject are required. A token
must carry the scope the caller asks for, and the scope must be on this server's
own allowlist. The verified subject becomes a pseudonymous account ID, and the
revocation store is checked on every call (an unreadable store denies access).
"""
from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass

import jwt

from ..identity import MemoryRevocations, TokenDenied, account_id

_KID = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_SCOPE = re.compile(r"[a-z][a-z0-9._:-]{0,63}\Z")
_CLIENT = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
MAX_BEARER = 8192
MAX_SUBJECT = 256


@dataclass(frozen=True)
class Authorization:
    """Who is calling: the owner's account AND, separately, which AI client app.

    ``account`` is the human owner (from ``sub``). ``client`` is the OAuth client the
    token was issued to (``azp`` or ``client_id``), e.g. the ChatGPT connector or the
    Claude connector. Two clients acting for the same owner share ``account`` but
    never ``client``, so task leases, rate limits and approvals can tell them apart.
    ``client`` is None when the token names no client; write tools must refuse that.
    """
    account: str
    scopes: frozenset
    issuer: str
    audience: str
    client: str | None = None


def _load_keys(jwks):
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise ValueError("Server-trusted JWKS required")
    keys = {}
    for raw in jwks["keys"]:
        if not isinstance(raw, dict) or raw.get("kty") != "RSA" or raw.get("alg", "RS256") != "RS256":
            raise ValueError("Only RS256 RSA verification keys are allowed")
        if raw.get("use", "sig") != "sig" or ("key_ops" in raw and "verify" not in raw["key_ops"]):
            raise ValueError("Key cannot verify signatures")
        kid = raw.get("kid")
        if not isinstance(kid, str) or not _KID.fullmatch(kid) or kid in keys:
            raise ValueError("Missing, duplicate or invalid key ID")
        try:
            key = jwt.PyJWK.from_dict(raw).key
        except (jwt.PyJWTError, ValueError, TypeError) as error:
            raise ValueError("Unusable public key") from error
        if getattr(key, "key_size", 0) < 2048:
            raise ValueError("RSA key too short")
        keys[kid] = key
    if not 1 <= len(keys) <= 10:
        raise ValueError("Expected 1-10 trusted signing keys")
    return keys


class TokenVerifier:
    def __init__(self, *, issuer, audience, jwks, allowed_scopes, revocations=None, leeway_seconds=5):
        if (not isinstance(issuer, str) or not issuer.startswith("https://")
                or not isinstance(audience, str) or not audience
                or type(leeway_seconds) is not int or not 0 <= leeway_seconds <= 60):
            raise ValueError("Trusted issuer, audience and bounded leeway required")
        if (not isinstance(allowed_scopes, frozenset) or not allowed_scopes
                or any(type(s) is not str or not _SCOPE.fullmatch(s) for s in allowed_scopes)):
            raise ValueError("Explicit scope allowlist required")
        if revocations is not None and not callable(getattr(revocations, "revoked_before", None)):
            raise ValueError("Revocation store required")
        self.issuer, self.audience, self.allowed_scopes = issuer, audience, allowed_scopes
        self.leeway = leeway_seconds
        self.revocations = revocations if revocations is not None else MemoryRevocations()
        self.keys = _load_keys(jwks)

    def authorize(self, authorization_header, *, required_scope):
        if (not isinstance(authorization_header, str) or not authorization_header.startswith("Bearer ")
                or len(authorization_header) > MAX_BEARER or authorization_header.count(" ") != 1):
            raise TokenDenied("Access denied")
        token = authorization_header[7:]
        if len(token) < 20 or type(required_scope) is not str or required_scope not in self.allowed_scopes:
            raise TokenDenied("Access denied")
        try:
            header = jwt.get_unverified_header(token)
            if (header.get("alg") != "RS256" or "jku" in header or "x5u" in header
                    or not isinstance(header.get("kid"), str)):
                raise TokenDenied("Access denied")
            key = self.keys.get(header["kid"])
            if key is None:
                raise TokenDenied("Access denied")
            claims = jwt.decode(token, key=key, algorithms=["RS256"], issuer=self.issuer,
                                audience=self.audience, leeway=self.leeway,
                                options={"require": ["iss", "aud", "exp", "iat", "sub"]})
        except (jwt.PyJWTError, KeyError, TypeError, ValueError) as error:
            raise TokenDenied("Access denied") from error
        subject, scope_text = claims.get("sub"), claims.get("scope")
        if (not isinstance(subject, str) or not 1 <= len(subject) <= MAX_SUBJECT
                or not isinstance(scope_text, str) or len(scope_text) > 1024):
            raise TokenDenied("Access denied")
        scopes = frozenset(scope_text.split())
        if required_scope not in scopes:
            raise TokenDenied("Access denied")
        client = claims.get("azp", claims.get("client_id"))
        if client is not None and (not isinstance(client, str) or not _CLIENT.fullmatch(client)):
            raise TokenDenied("Access denied")
        try:
            account = account_id(verified_issuer=self.issuer, verified_subject=subject)
            cutoff = self.revocations.revoked_before(self.issuer, account)
        except Exception as error:      # an unreadable store must never restore access
            raise TokenDenied("Access denied") from error
        if cutoff is not None and int(claims["iat"]) <= cutoff:
            raise TokenDenied("Access denied")
        return Authorization(account=account, scopes=scopes, issuer=self.issuer, audience=self.audience,
                             client=client)


class RotatingTokenVerifier:
    """Refreshes the JWKS on a schedule or on an unknown key ID, within strict bounds.

    A failed refresh keeps the last good keys, but never for longer than max_stale.
    """

    def __init__(self, *, issuer, audience, initial_jwks, jwks_loader, allowed_scopes, revocations,
                 refresh_interval=300.0, retry_cooldown=15.0, max_stale=3600.0, clock=time.monotonic):
        if not callable(jwks_loader) or not callable(clock) or revocations is None:
            raise ValueError("JWKS loader, clock and durable revocation store required")
        if not (1 <= retry_cooldown <= 300 and retry_cooldown <= refresh_interval <= 3600
                and refresh_interval <= max_stale <= 86400):
            raise ValueError("JWKS refresh bounds are invalid")
        self.issuer, self.audience, self.allowed_scopes = issuer, audience, allowed_scopes
        self._loader, self._revocations, self._clock = jwks_loader, revocations, clock
        self._refresh, self._cooldown, self._max_stale = float(refresh_interval), float(retry_cooldown), float(max_stale)
        self._lock = threading.RLock()
        self._verifier = self._build(initial_jwks)
        now = clock()
        self._last_success, self._last_attempt = now, now - self._cooldown

    def _build(self, jwks):
        return TokenVerifier(issuer=self.issuer, audience=self.audience, jwks=jwks,
                             allowed_scopes=self.allowed_scopes, revocations=self._revocations)

    def _try_refresh(self, now):
        self._last_attempt = now
        try:
            self._verifier = self._build(self._loader())
        except Exception:
            return
        self._last_success = self._clock()

    def authorize(self, authorization_header, *, required_scope):
        kid = None
        if isinstance(authorization_header, str) and authorization_header.startswith("Bearer "):
            try:
                header = jwt.get_unverified_header(authorization_header[7:])
                if header.get("alg") == "RS256" and "jku" not in header and "x5u" not in header:
                    kid = header.get("kid")
            except (jwt.PyJWTError, TypeError, ValueError):
                kid = None
        with self._lock:
            now = self._clock()
            due = now - self._last_success >= self._refresh
            unknown = isinstance(kid, str) and kid not in self._verifier.keys
            if (due or unknown) and now - self._last_attempt >= self._cooldown:
                self._try_refresh(now)
                now = self._clock()
            if now - self._last_success > self._max_stale:
                raise TokenDenied("Access denied")
            verifier = self._verifier
        return verifier.authorize(authorization_header, required_scope=required_scope)
