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

import ipaddress
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

READ_SCOPES = frozenset({"health.read"})


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


def build_app(*, router, public_host, port, scopes=READ_SCOPES):
    """The ASGI app: MCP at /mcp plus its metadata document, both host-checked."""
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from .app import create_server

    if type(public_host) is not str or not public_host or "/" in public_host or ":" in public_host:
        raise ValueError("Exact public host name required")
    resource = "https://%s/mcp" % public_host
    hosts = [public_host, "127.0.0.1:%d" % port]
    server = create_server(router=router, resource_url=resource, allowed_hosts=hosts)
    app = server.streamable_http_app()
    document = protected_resource_metadata(resource, router.tokens.issuer, scopes)
    allowed = {h.lower() for h in hosts}

    async def metadata(request):
        if request.headers.get("host", "").lower() not in allowed:
            return JSONResponse({"error": "invalid_host"}, status_code=400)
        return JSONResponse(document, headers={"Cache-Control": "no-store"})

    app.routes.insert(0, Route(urlsplit(metadata_url(resource)).path, metadata, methods=["GET"]))
    return app


@dataclass
class Running:
    server: object
    thread: threading.Thread
    local_url: str

    def stop(self, timeout=5):
        self.server.should_exit = True
        self.thread.join(timeout=timeout)


def start(*, router, public_host, port, address="127.0.0.1", startup_timeout=15):
    """Start in a background thread. Refuses any non-loopback address or privileged port."""
    try:
        loopback = ipaddress.ip_address(address).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        raise PermissionError("The endpoint listens on loopback only")
    if type(port) is not int or not 1024 < port <= 65535:
        raise PermissionError("Unprivileged port required")
    import uvicorn
    app = build_app(router=router, public_host=public_host, port=port)
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


def router_for_paired_device(*, tokens, grants, read_health, read_service_status=None):
    """Bind the router to the one live paired owner/device in the pairing database."""
    from .router import LocalOwnership, ReadRouter
    paired = grants.paired_devices()
    if len(paired) != 1:
        raise RuntimeError("Exactly one live paired device is required (found %d)" % len(paired))
    owner_id, device_id = paired[0]
    return ReadRouter(tokens=tokens, ownership=LocalOwnership(grants=grants, owner_id=owner_id, device_id=device_id),
                      read_health=read_health, read_service_status=read_service_status)
