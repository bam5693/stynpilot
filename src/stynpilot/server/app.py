"""The paired computer's MCP server (Streamable HTTP), read-only tools.

Ported from the GitLab prototype (customer_mcp_server.py). Needs the MCP SDK 1.x
(``pip install stynpilot[server]``).

Tools: ``computer_health`` and, when the router has a status reader,
``software_service_status``. Both are GREEN: health.read scope, owner/device
grant, read-only, and they change nothing. Install and approval tools are added in
a later step (MASTER_PLAN Phase G); this server can never approve anything.
"""
from __future__ import annotations

import logging
from typing import Annotated

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import AnyHttpUrl, TypeAdapter, UrlConstraints

from ..identity import TokenDenied
from .router import READ_SCOPE, AccessDenied, ReadRouter

_LOG = logging.getLogger("stynpilot.auth")
NOT_AUTHORIZED = {"ok": False, "error": "device_unavailable_or_not_authorized"}
UNIDENTIFIED_CLIENT = "unidentified-client"   # read-only tools only; write tools must refuse it
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)


class _SDKTokenVerifier:
    """Adapts our verifier to the MCP SDK's bearer-token hook."""

    def __init__(self, router):
        self.router = router

    async def verify_token(self, token):
        try:
            who = self.router.tokens.authorize("Bearer " + token, required_scope=READ_SCOPE)
        except (TokenDenied, ValueError):
            return None
        # Keep the AI client and the owner apart: client_id is the OAuth client (ChatGPT, Claude...),
        # subject is the owner account. Never collapse them into one caller identity.
        return AccessToken(token=token, client_id=getattr(who, "client", None) or UNIDENTIFIED_CLIENT,
                           subject=who.account, scopes=sorted(who.scopes))


def _bearer():
    """The verified request's bearer header, or None if scope or token are missing."""
    try:
        token = get_access_token()
    except Exception:
        return None
    scopes = getattr(token, "scopes", None) if token is not None else None
    raw = getattr(token, "token", None) if token is not None else None
    if not isinstance(scopes, (list, tuple, set, frozenset)) or READ_SCOPE not in scopes or type(raw) is not str or not raw:
        return None
    return "Bearer " + raw


def create_server(*, router, resource_url, allowed_hosts=None, propose=None, diag=None):
    """``propose``: optional dict(clients=EnrolledClients, store=RequestStore, resolve_apt=..., approval_url=...)
    that adds the YELLOW request tools. Without it the server is read-only."""
    if not isinstance(router, ReadRouter):
        raise ValueError("A ReadRouter is required")
    if not isinstance(resource_url, str) or not resource_url.startswith("https://"):
        raise ValueError("MCP resource URL must use HTTPS")
    if resource_url != router.tokens.audience:
        raise ValueError("MCP resource must exactly match the verified token audience")
    try:
        exact = TypeAdapter(Annotated[AnyHttpUrl, UrlConstraints(preserve_empty_path=True)]).validate_python(resource_url)
    except (TypeError, ValueError) as error:
        raise ValueError("Exact HTTPS resource URL required") from error
    if str(exact) != resource_url:
        raise ValueError("MCP resource must not be normalized to another identifier")
    extra = {}
    if allowed_hosts is not None:
        if (type(allowed_hosts) is not list or not 1 <= len(allowed_hosts) <= 8
                or any(type(h) is not str or not h or len(h) > 260 for h in allowed_hosts)):
            raise ValueError("Exact allowed host names required")
        from mcp.server.transport_security import TransportSecuritySettings
        extra["transport_security"] = TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=list(allowed_hosts), allowed_origins=[])
    server = FastMCP(
        name="StyNpilot",
        instructions=("Read the paired computer's health and the status of StyNpilot-installed software"
                      + (", plus diagnostics, service logs and protected text-file reads" if diag else "")
                      + (", and ask the owner to approve catalog software installs or rollbacks" if propose else "")
                      + ". This server cannot approve anything; the owner approves separately on his phone."),
        auth=AuthSettings(issuer_url=router.tokens.issuer, resource_server_url=exact,
                          required_scopes=[READ_SCOPE], validate_token_resource=False),
        token_verifier=_SDKTokenVerifier(router),
        host="127.0.0.1", stateless_http=True, json_response=True, **extra)

    @server.tool(name="computer_health", title="Read computer health", annotations=READ_ONLY,
                 description=("Read CPU, memory, disk, temperature and uptime for the paired computer. "
                              "This tool cannot control the device."))
    def computer_health(device_id: str) -> dict:
        header = _bearer()
        if header is None:
            return NOT_AUTHORIZED
        try:
            metrics = router.health(authorization_header=header, device_id=device_id)
        except AccessDenied:
            return NOT_AUTHORIZED
        except Exception as error:
            _LOG.warning("health_internal_failure type=%s", type(error).__name__)
            return {"ok": False, "error": "device_health_temporarily_unavailable"}
        return {"ok": True, "device_id": device_id, "scope": READ_SCOPE, "metrics": metrics}

    if router.read_inventory is not None:
        @server.tool(name="computer_inventory", title="Read computer hardware and software inventory", annotations=READ_ONLY,
                     description=("Read-only inventory of the paired computer: OS, CPU, motherboard, memory capacity, "
                                  "GPU, drives, and installed Ubuntu packages. No serial numbers, addresses, host names "
                                  "or file contents. Changes nothing."))
        def computer_inventory(device_id: str) -> dict:
            header = _bearer()
            if header is None:
                return NOT_AUTHORIZED
            try:
                report = router.inventory(authorization_header=header, device_id=device_id)
            except AccessDenied:
                return NOT_AUTHORIZED
            except Exception as error:
                _LOG.warning("inventory_internal_failure type=%s", type(error).__name__)
                return {"ok": False, "error": "inventory_temporarily_unavailable"}
            return {"ok": True, "device_id": device_id, "scope": READ_SCOPE, "inventory": report}

    if router.read_service_status is not None:
        @server.tool(name="software_service_status", title="Check installed software status", annotations=READ_ONLY,
                     description=("Read-only check of one StyNpilot catalog application (for example 'forgejo'): "
                                  "installed, enabled at boot, listening, answering, version, and whether its "
                                  "first-run setup is still pending. Changes nothing."))
        def software_service_status(device_id: str, software: str) -> dict:
            header = _bearer()
            if header is None:
                return NOT_AUTHORIZED
            try:
                report = router.service_status(authorization_header=header, device_id=device_id, software=software)
            except AccessDenied:
                return NOT_AUTHORIZED
            except KeyError:
                return {"ok": False, "error": "unknown_software"}
            except Exception as error:
                _LOG.warning("service_status_internal_failure type=%s", type(error).__name__)
                return {"ok": False, "error": "service_status_temporarily_unavailable"}
            return {"ok": True, "device_id": device_id, "scope": READ_SCOPE, "status": report}

    if diag is not None:
        from .diag_tools import register as register_diag
        register_diag(server, router=router, bearer=_bearer, **diag)

    if propose is not None:
        from .propose_tools import register
        register(server, router=router, bearer=_bearer, **propose)

    return server
