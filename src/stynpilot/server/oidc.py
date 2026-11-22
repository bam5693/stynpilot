"""Load the owner's identity provider (Auth0) settings safely, then build the token verifier.

Ported from the GitLab prototype (oidc_provider.py). Standard library for the
network part; the verifier itself needs the [server] extra.

- The issuer is set by the owner's configuration, never by a request or a token.
- Discovery and JWKS are fetched over verified HTTPS, without following redirects,
  only from the issuer's own origin, as JSON, at most 256 KiB.
- The provider must support authorization code + PKCE S256 and refresh tokens.
- A durable revocation store is required (a test-only memory store must be allowed
  explicitly).
"""
from __future__ import annotations

import json
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

MAX_JSON = 256 * 1024


class OIDCError(ValueError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def https_origin(url):
    if not isinstance(url, str) or len(url) > 2048:
        raise OIDCError("Endpoint must be a bounded HTTPS URL")
    try:
        parts = urlsplit(url)
        port = parts.port or 443
    except ValueError as error:
        raise OIDCError("Endpoint URL is invalid") from error
    if (parts.scheme != "https" or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.query or parts.fragment):
        raise OIDCError("Endpoints must use HTTPS without credentials, query or fragment")
    return parts.hostname.lower(), port


def jwks_uri_from_discovery(issuer, metadata):
    """Check the discovery document strictly; return the JWKS URL."""
    if not isinstance(metadata, dict) or metadata.get("issuer") != issuer:
        raise OIDCError("Discovery issuer does not match the configured issuer")
    origin = https_origin(issuer)
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri", "revocation_endpoint"):
        if https_origin(metadata.get(field)) != origin:
            raise OIDCError("Every endpoint must stay on the issuer's origin")
    need = {
        "response_types_supported": {"code"},
        "code_challenge_methods_supported": {"S256"},
        "grant_types_supported": {"authorization_code", "refresh_token"},
        "scopes_supported": {"openid", "offline_access"},
    }
    for field, required in need.items():
        value = metadata.get(field)
        if not isinstance(value, list) or not required <= set(value):
            raise OIDCError("Provider is missing required support: " + field)
    return metadata["jwks_uri"]


class OIDCConfig:
    def __init__(self, *, issuer, audience, revocations, allowed_scopes, timeout_seconds=4.0,
                 ssl_context=None, allow_volatile_revocations=False, fetch=None,
                 refresh_interval=300.0, retry_cooldown=15.0, max_stale=3600.0):
        https_origin(issuer)
        if not isinstance(audience, str) or not audience.strip():
            raise OIDCError("API audience required")
        if type(timeout_seconds) not in (int, float) or not 0.5 <= timeout_seconds <= 10:
            raise OIDCError("Timeout must be 0.5-10 seconds")
        if ssl_context is not None and not isinstance(ssl_context, ssl.SSLContext):
            raise OIDCError("A verified TLS context is required")
        if (revocations is None or not callable(getattr(revocations, "revoked_before", None))
                or (getattr(revocations, "durable", False) is not True and allow_volatile_revocations is not True)):
            raise OIDCError("A durable revocation store is required")
        self.issuer, self.audience, self.revocations = issuer, audience, revocations
        self.allowed_scopes, self.timeout = allowed_scopes, timeout_seconds
        self.ssl_context = ssl_context or ssl.create_default_context()
        self._fetch = fetch or self._fetch_json
        self._bounds = dict(refresh_interval=refresh_interval, retry_cooldown=retry_cooldown, max_stale=max_stale)

    def _fetch_json(self, url):
        if https_origin(url) != https_origin(self.issuer):
            raise OIDCError("Fetch target is outside the configured issuer")
        request = Request(url, headers={"Accept": "application/json", "User-Agent": "StyNpilot-OIDC/1"})
        opener = build_opener(HTTPSHandler(context=self.ssl_context), _NoRedirect())
        try:
            with opener.open(request, timeout=self.timeout) as response:
                if response.status != 200 or response.headers.get_content_type() != "application/json":
                    raise OIDCError("Endpoint did not return a JSON success")
                body = response.read(MAX_JSON + 1)
        except OIDCError:
            raise
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            raise OIDCError("Endpoint could not be reached securely") from error
        if len(body) > MAX_JSON:
            raise OIDCError("Document too large")
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise OIDCError("Endpoint returned invalid JSON") from error
        if not isinstance(value, dict):
            raise OIDCError("Document must be a JSON object")
        return value

    def build_verifier(self):
        from .tokens import RotatingTokenVerifier
        discovery = self._fetch(self.issuer.rstrip("/") + "/.well-known/openid-configuration")
        jwks_uri = jwks_uri_from_discovery(self.issuer, discovery)
        if https_origin(jwks_uri) != https_origin(self.issuer):
            raise OIDCError("JWKS must stay on the issuer's origin")
        return RotatingTokenVerifier(issuer=self.issuer, audience=self.audience,
                                     initial_jwks=self._fetch(jwks_uri), jwks_loader=lambda: self._fetch(jwks_uri),
                                     allowed_scopes=self.allowed_scopes, revocations=self.revocations, **self._bounds)
