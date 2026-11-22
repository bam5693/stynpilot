"""YELLOW request tools: an assistant may ASK; only the owner can approve (needs [server] extra).

Ported from the GitLab prototype (src/stynpilot_software_tools.py), rebuilt on the
general plan format, the enrolled-client checks and the owner's request queue.

Every call is checked, in order, before anything is filed:
1. the token verifies with ``workspace.propose`` (and the owner's account);
2. the AI client is identified, enrolled, not revoked, and holds no review scope;
3. the device is the owner's, unrevoked and unexpired, and the owner granted it
   ``workspace.propose``;
4. the software is a catalog id, and its plan validates.

The tools return a receipt. They have no way to approve, run, cancel or widen a request.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

from mcp.types import ToolAnnotations

from .. import catalog
from ..identity import TokenDenied
from ..plan import PlanError
from ..requests import RequestError
from .clients import PROPOSE_SCOPE, ClientDenied
from .router import AccessDenied

_LOG = logging.getLogger("stynpilot.propose")
_ROLLBACK_ID = re.compile(r"[a-f0-9]{16,64}\Z")
REQUEST_TOOLS = ("commander_software_catalog", "commander_request_software_install",
                 "commander_software_install_status", "commander_request_software_rollback")
FILES_A_REQUEST = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False)
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)


def _error(code):
    return {"ok": False, "error": code}


class ProposeGate:
    """The four checks above. Returns (proposer, owner_id) or raises with a stable code."""

    def __init__(self, *, router, clients):
        self.router, self.clients = router, clients

    def check(self, header, device_id):
        try:
            who = self.router.tokens.authorize(header, required_scope=PROPOSE_SCOPE)
        except TokenDenied:
            raise ClientDenied("not_authorized") from None
        proposer = self.clients.proposer(who)
        self.router._require_device(who.account, device_id)        # owner, unrevoked, unexpired
        grant = self.router.ownership.grants.get(owner_id=who.account, device_id=device_id)
        if grant is None or PROPOSE_SCOPE not in (getattr(grant, "scopes", None) or ()):
            raise ClientDenied("device_not_granted_propose")
        return proposer, who.account


def register(server, *, router, clients, store, bearer, resolve_apt=None, approval_url=None, clock=None):
    """Add the request tools. ``bearer()`` returns the verified request's bearer header or None."""
    gate = ProposeGate(router=router, clients=clients)
    now = clock or (lambda: datetime.now(timezone.utc))

    def guarded(device_id):
        header = bearer()
        if header is None:
            raise ClientDenied("not_authorized")
        try:
            return gate.check(header, device_id)
        except AccessDenied:
            raise ClientDenied("device_unavailable_or_not_authorized") from None

    def receipt(result):
        if approval_url:
            result["owner_approval_url"] = approval_url
        result["next"] = ("The owner reviews and approves this on his phone. "
                          "Check progress with commander_software_install_status.")
        return {"ok": True, "result": result}

    @server.tool(name="commander_software_catalog", title="List software that can be requested",
                 annotations=READ_ONLY,
                 description="List the catalog ids an assistant may request. Read-only; changes nothing.")
    def software_catalog() -> dict:
        return {"ok": True, "software": catalog.listing()}

    @server.tool(name="commander_request_software_install", title="Ask the owner to approve a software install",
                 annotations=FILES_A_REQUEST,
                 description=("Ask the computer's owner to approve installing one catalog application. "
                              "StyNpilot builds the exact plan; the owner reviews and approves it separately "
                              "on his phone. You supply only the catalog id and cannot approve anything."))
    def request_install(device_id: str, software: str) -> dict:
        try:
            proposer, owner = guarded(device_id)
            plan, summary = catalog.install_plan(software, owner=owner, device=device_id,
                                                 resolve_apt=resolve_apt, now=now())
            expires = datetime.strptime(plan.content()["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc).timestamp()
            result, _ = store.submit(kind="install", software=software, device=device_id, owner=owner,
                                     proposer=proposer, payload=plan.content(), summary=summary, expires=expires)
        except (ClientDenied, catalog.CatalogError, RequestError) as denied:
            return _error(denied.code)
        except PlanError:
            return _error("plan_invalid")
        except Exception as error:
            _LOG.warning("install request failed type=%s", type(error).__name__)
            return _error("request_refused")
        return receipt(result)

    @server.tool(name="commander_software_install_status", title="Check a software request",
                 annotations=READ_ONLY,
                 description="Check whether the owner approved a request, and its safe progress and result.")
    def install_status(device_id: str, request_id: str) -> dict:
        try:
            _, owner = guarded(device_id)
            return {"ok": True, "result": store.status(request_id, owner=owner, device=device_id)}
        except (ClientDenied, RequestError) as denied:
            return _error(denied.code)
        except Exception as error:
            _LOG.warning("status failed type=%s", type(error).__name__)
            return _error("status_unavailable")

    @server.tool(name="commander_request_software_rollback", title="Ask the owner to approve a rollback",
                 annotations=FILES_A_REQUEST,
                 description=("Ask the owner to approve rolling back one StyNpilot-managed installation. "
                              "User data is preserved. You cannot approve anything."))
    def request_rollback(device_id: str, software: str, rollback_id: str) -> dict:
        try:
            proposer, owner = guarded(device_id)
            item = catalog.entry(software)
            if type(rollback_id) is not str or not _ROLLBACK_ID.fullmatch(rollback_id):
                return _error("invalid_rollback_id")
            expires = now() + timedelta(hours=1)
            payload = {"kind": "rollback", "software": software, "rollback_id": rollback_id,
                       "owner": owner, "device": device_id, "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ")}
            summary = ["Roll back %s to its state before the recorded install %s." % (item["title"], rollback_id[:12]),
                       "User data is kept; only files StyNpilot created and that are unchanged are removed.",
                       "Expires %s UTC if not approved." % payload["expires_at"].replace("T", " ").rstrip("Z")]
            result, _ = store.submit(kind="rollback", software=software, device=device_id, owner=owner,
                                     proposer=proposer, payload=payload, summary=summary,
                                     expires=expires.timestamp())
        except (ClientDenied, catalog.CatalogError, RequestError) as denied:
            return _error(denied.code)
        except Exception as error:
            _LOG.warning("rollback request failed type=%s", type(error).__name__)
            return _error("request_refused")
        return receipt(result)

    return gate
