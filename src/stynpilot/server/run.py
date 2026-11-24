"""Start the paired computer's MCP endpoint: loopback only, exact host names, OAuth metadata.

Ported from the GitLab prototype (start_health_connection and
_serve_health_resource_metadata in src/commander_health_connection.py, plus
protected_resource_metadata / metadata_url / www_authenticate from
src/commander_ai_endpoint.py). Needs the [server] extra.

The server only ever listens on a loopback address. Reaching it from ChatGPT or
Claude goes through the owner's own tunnel (Tailscale Funnel or Cloudflare), which
is a separate, owner-approved setup step. Requests must name an expected host
(DNS-rebinding protection), and the RFC 9728 document tells AI clients which
identity provider and scopes to use. It never names anything private beyond the
public resource URL.
"""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

READ_SCOPES = frozenset({"health.read"})
LISTEN_ADDRESS = "127.0.0.1"   # IPv4 loopback only for now (PR #9 review); ::1 needs bracketed URLs
# A strict DNS host name: labels of letters, digits and inner hyphens, dot-separated, no
# user-info, port, path, query, fragment, whitespace or percent-encoding.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
PUBLIC_HOST = re.compile(r"(?=.{1,253}\Z)%s(?:\.%s)+\Z" % (_LABEL, _LABEL))


def check_public_host(host):
    if type(host) is not str or not PUBLIC_HOST.fullmatch(host) or host.rsplit(".", 1)[-1].isdigit():
        raise ValueError("Public host must be a plain DNS name such as computer.example.net")
    return host.lower()


def metadata_url(resource):
    """RFC 9728 well-known URL for a path-bearing resource, e.g. https://h/mcp ->
    https://h/.well-known/oauth-protected-resource/mcp"""
    parts = urlsplit(resource)
    if parts.scheme != "https" or not parts.hostname or parts.query or parts.fragment:
        raise ValueError("HTTPS resource required")
    return "%s://%s/.well-known/oauth-protected-resource%s" % (parts.scheme, parts.netloc, parts.path.rstrip("/"))


def protected_resource_metadata(resource, issuer, scopes):
    if not isinstance(issuer, str) or not issuer.startswith("https://"):
        raise ValueError("HTTPS issuer required")
    if type(scopes) not in (set, frozenset) or not scopes:
        raise ValueError("Scopes required")
    metadata_url(resource)
    return {"resource": resource, "authorization_servers": [issuer],
            "scopes_supported": sorted(scopes), "bearer_methods_supported": ["header"]}


def www_authenticate(resource):
    return 'Bearer resource_metadata="%s"' % metadata_url(resource)


PROPOSE_SCOPES = frozenset({"health.read", "workspace.propose"})


MAX_STEP_UP_BODY = 65536
MAX_STEP_UP_BUFFERS = 8                # at most this many bodies are held in memory at once


class ScopeChallenge:
    """ASGI wrapper that makes the OAuth challenge say which scopes the endpoint needs (RFC 6750 ``scope``).

    ChatGPT chooses its scopes from the challenge, not from ``scopes_supported``; the SDK's challenge names none, so a
    connector could be authorized with health.read only. Two additions, both purely informational:
    1. every ``WWW-Authenticate: Bearer`` the endpoint sends also carries ``scope="..."``;
    2. a tools/call for a request tool made with a token that VERIFIES but lacks workspace.propose gets an HTTP 403
       ``insufficient_scope`` challenge naming the scopes, so the client can ask the owner for them (step-up).
    It never admits anything: tokens are still verified by the SDK and every tool still runs its own checks. On any
    doubt (bad body, bad token, unknown host, big body) the request passes through unchanged.
    """

    def __init__(self, app, *, scopes, resource, hosts, tokens, guarded_tools):
        self.app, self.resource, self.hosts, self.tokens = app, resource, frozenset(hosts), tokens
        self.scope_text = " ".join(sorted(scopes))
        self.guarded = frozenset(guarded_tools)
        self.path = urlsplit(resource).path
        self.metadata = metadata_url(resource)
        self._slots = threading.BoundedSemaphore(MAX_STEP_UP_BUFFERS)

    def _challenge(self, error=None, description=None):
        parts = []
        if error:
            parts += ['error="%s"' % error, 'error_description="%s"' % description]
        parts += ['resource_metadata="%s"' % self.metadata, 'scope="%s"' % self.scope_text]
        return "Bearer " + ", ".join(parts)

    def _candidate(self, scope):
        """Cheap checks BEFORE any body is read: only a request that already carries a genuine health.read token that
        lacks workspace.propose, on a known host, with a small declared body, is ever buffered. Everyone else (no
        token, bad token, big or chunked body) passes straight through, so an anonymous caller can't make us hold data."""
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        host = headers.get(b"host", b"").decode("latin-1").lower()
        auth = headers.get(b"authorization", b"").decode("latin-1")
        length = headers.get(b"content-length", b"")
        if host not in self.hosts or not auth.startswith("Bearer ") or not length.isdigit():
            return False
        if not 0 < int(length) <= MAX_STEP_UP_BODY:
            return False
        try:
            who = self.tokens.authorize(auth, required_scope="health.read")
        except Exception:                    # an unverifiable token is the SDK's to refuse (plain 401)
            return False
        return "workspace.propose" not in (getattr(who, "scopes", None) or ())

    def _calls_guarded_tool(self, body):
        try:
            data = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeError):
            return False
        messages = data if isinstance(data, list) else [data]
        called = set()
        for message in messages[:32]:
            if isinstance(message, dict) and message.get("method") == "tools/call":
                params = message.get("params")
                name = params.get("name") if isinstance(params, dict) else None
                if isinstance(name, str):
                    called.add(name)
        return bool(called & self.guarded)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def tell(message):
            if message["type"] == "http.response.start":
                headers = []
                for key, value in message.get("headers", []):
                    if key.lower() == b"www-authenticate" and b"scope=" not in value:
                        value = value + b', scope="' + self.scope_text.encode() + b'"'
                    headers.append((key, value))
                message = {**message, "headers": headers}
            await send(message)

        if (scope["method"] == "POST" and scope["path"] == self.path and self.guarded and self._candidate(scope)
                and self._slots.acquire(blocking=False)):
            try:
                held, body, more = [], b"", True
                while more:
                    message = await receive()
                    held.append(message)
                    if message["type"] != "http.request":
                        break
                    body += message.get("body", b"")
                    more = message.get("more_body", False)
                    if len(body) > MAX_STEP_UP_BODY:      # declared small but sent big: stop holding, pass through
                        body, more = None, True
                        break
            finally:
                self._slots.release()
            if body is not None and not more and self._calls_guarded_tool(body):
                reply = json.dumps({"error": "insufficient_scope",
                                    "error_description": "Required scope: workspace.propose"}).encode()
                await send({"type": "http.response.start", "status": 403, "headers": [
                    (b"content-type", b"application/json"), (b"content-length", str(len(reply)).encode()),
                    (b"www-authenticate", self._challenge("insufficient_scope",
                                                          "Required scope: workspace.propose").encode())]})
                return await send({"type": "http.response.body", "body": reply})
            queue = list(held)

            async def replay():
                return queue.pop(0) if queue else await receive()
            return await self.app(scope, replay, tell)
        return await self.app(scope, receive, tell)


def build_app(*, router, public_host, port, scopes=None, propose=None, diag=None):
    """The ASGI app: MCP at /mcp plus its metadata document, both host-checked."""
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from .app import create_server
    from .propose_tools import PROPOSE_ONLY_TOOLS

    public_host = check_public_host(public_host)
    resource = "https://%s/mcp" % public_host
    hosts = [public_host, "%s:%d" % (LISTEN_ADDRESS, port)]
    scopes = scopes or (PROPOSE_SCOPES if propose else READ_SCOPES)
    server = create_server(router=router, resource_url=resource, allowed_hosts=hosts, propose=propose, diag=diag)
    app = server.streamable_http_app()
    document = protected_resource_metadata(resource, router.tokens.issuer, scopes)
    allowed = {h.lower() for h in hosts}

    async def metadata(request):
        if request.headers.get("host", "").lower() not in allowed:
            return JSONResponse({"error": "invalid_host"}, status_code=400)
        return JSONResponse(document, headers={"Cache-Control": "no-store"})

    app.routes.insert(0, Route(urlsplit(metadata_url(resource)).path, metadata, methods=["GET"]))
    return ScopeChallenge(app, scopes=scopes, resource=resource, hosts=allowed, tokens=router.tokens,
                          guarded_tools=PROPOSE_ONLY_TOOLS if "workspace.propose" in scopes else frozenset())


@dataclass
class Running:
    server: object
    thread: threading.Thread
    local_url: str

    def stop(self, timeout=5):
        self.server.should_exit = True
        self.thread.join(timeout=timeout)


def start(*, router, public_host, port, address=LISTEN_ADDRESS, startup_timeout=15, propose=None, diag=None):
    """Start in a background thread. Only 127.0.0.1, an unprivileged port and a strict host name."""
    if propose is not None and getattr(propose.get("clients"), "revocations", None) is None:
        raise ValueError("Request tools need a durable revocation file (EnrolledClients(revocations=...))")
    if address != LISTEN_ADDRESS:
        raise PermissionError("The endpoint listens on 127.0.0.1 only")
    if type(port) is not int or isinstance(port, bool) or not 1024 < port <= 65535:
        raise PermissionError("Unprivileged port required")
    check_public_host(public_host)
    import uvicorn
    app = build_app(router=router, public_host=public_host, port=port, propose=propose, diag=diag)
    web = uvicorn.Server(uvicorn.Config(app, host=address, port=port, log_level="warning",
                                        proxy_headers=False, server_header=False))
    thread = threading.Thread(target=web.run, name="stynpilot-mcp", daemon=True)
    thread.start()
    deadline = time.monotonic() + startup_timeout
    while not web.started:
        if not thread.is_alive() or time.monotonic() > deadline:
            web.should_exit = True
            raise RuntimeError("MCP endpoint did not start (port in use?)")
        time.sleep(0.05)
    return Running(web, thread, "http://%s:%d/mcp" % (address, port))


def check_approval_host(host):
    """The approval page's public name as the browser (through the HTTPS proxy) sends it: DNS name, optional :port."""
    if type(host) is not str:
        raise ValueError("Approval host must be a DNS name with an optional port")
    name, _, port = host.partition(":")
    check_public_host(name)
    if port and not (port.isdigit() and 1 <= int(port) <= 65535 and str(int(port)) == port):
        raise ValueError("Approval host port is invalid")
    return host.lower()


def start_approval(*, flow, public_host, port, address=LISTEN_ADDRESS, startup_timeout=15):
    """The owner's approval page, as its OWN loopback listener in the owner-side service.

    Never part of the AI-facing MCP app (different app, different port; the MCP app has no /approve routes).
    It listens on 127.0.0.1 only; the owner's HTTPS proxy (tailscale serve, an owner-approved step) forwards to
    it, and the page only answers to ``public_host``. It never touches Auth0 settings: the sign-in values come
    in through ``flow.authorize``.
    """
    from ..approval_web import build_app as build_approval_app
    if address != LISTEN_ADDRESS:
        raise PermissionError("The approval page listens on 127.0.0.1 only")
    if type(port) is not int or isinstance(port, bool) or not 1024 < port <= 65535:
        raise PermissionError("Unprivileged port required")
    host = check_approval_host(public_host)
    import uvicorn
    app = build_approval_app(flow=flow, public_host=host, secure_cookie=True)
    web = uvicorn.Server(uvicorn.Config(app, host=address, port=port, log_level="warning",
                                        proxy_headers=False, server_header=False))
    thread = threading.Thread(target=web.run, name="stynpilot-approval", daemon=True)
    thread.start()
    deadline = time.monotonic() + startup_timeout
    while not web.started:
        if not thread.is_alive() or time.monotonic() > deadline:
            web.should_exit = True
            raise RuntimeError("Approval page did not start (port in use?)")
        time.sleep(0.05)
    return Running(web, thread, "http://%s:%d/approve" % (address, port))


def router_for_paired_device(*, tokens, grants, read_health, read_service_status=None, read_inventory=None):
    """Bind the router to the one live paired owner/device in the pairing database."""
    from .router import LocalOwnership, ReadRouter
    paired = grants.paired_devices()
    if len(paired) != 1:
        raise RuntimeError("Exactly one live paired device is required (found %d)" % len(paired))
    owner_id, device_id = paired[0]
    return ReadRouter(tokens=tokens, ownership=LocalOwnership(grants=grants, owner_id=owner_id, device_id=device_id),
                      read_health=read_health, read_service_status=read_service_status,
                      read_inventory=read_inventory)
