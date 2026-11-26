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

import json

from .. import catalog, impact, release
from ..identity import TokenDenied
from ..ledger import LedgerError
from ..plan import PlanError
from ..requests import RequestError
from .clients import PROPOSE_SCOPE, ClientDenied
READ_SCOPE = "health.read"
from .router import AccessDenied

_LOG = logging.getLogger("stynpilot.propose")
_SLUG = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
_ROLLBACK_ID = re.compile(r"[a-f0-9]{16,64}\Z")
REQUEST_TOOLS = ("commander_software_catalog", "commander_software_search", "commander_request_software_install",
                 "commander_software_install_status", "commander_request_software_rollback",
                 "commander_request_stynpilot_upgrade")
# Tools that file or read requests need workspace.propose; search and the catalog list are read-only (GREEN).
# The runner tools that change anything (request, edit files, run, cancel) need workspace.propose too.
RUNNER_WRITE_TOOLS = frozenset({"commander_prepare_stynpilot_release", "commander_request_stynpilot_release",
                                "commander_resume_stynpilot_release",
                                "commander_request_passkey_enrollment", "commander_request_passkey_revocation",
                                "commander_request_runner_setup", "commander_request_workspace_authorization",
                                "commander_request_workspace_removal", "workspace_write", "workspace_edit", "workspace_move",
                                "workspace_delete", "job_run", "job_cancel", "runner_selftest",
                                "commander_backup_now", "commander_backup_drill", "commander_request_backup_retention",
                                "commander_request_backup_key_rotation"})
PROPOSE_ONLY_TOOLS = frozenset({"commander_request_software_install", "commander_software_install_status",
                                "commander_request_software_rollback", "commander_request_stynpilot_upgrade"}) | RUNNER_WRITE_TOOLS
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
            # A token that is genuine but was granted only health.read (an assistant connected before the owner allowed
            # requests) gets a distinct, honest code and a log line naming the client and its scopes (never the token).
            # A token that does not verify at all still gets the plain code: no hint to a stranger.
            try:
                seen = self.router.tokens.authorize(header, required_scope=READ_SCOPE)
            except TokenDenied:
                raise ClientDenied("not_authorized") from None
            _LOG.warning("request tools refused: token lacks %s client=%s scopes=%s", PROPOSE_SCOPE,
                         getattr(seen, "client", None), sorted(getattr(seen, "scopes", ()) or ()))
            raise ClientDenied("insufficient_scope_workspace_propose") from None
        proposer = self.clients.proposer(who)
        self.router._require_device(who.account, device_id)        # owner, unrevoked, unexpired
        grant = self.router.ownership.grants.get(owner_id=who.account, device_id=device_id)
        if grant is None or PROPOSE_SCOPE not in (getattr(grant, "scopes", None) or ()):
            raise ClientDenied("device_not_granted_propose")
        return proposer, who.account


def register(server, *, router, clients, store, bearer, ledger=None, resolve_apt=None, approval_url=None, clock=None,
             analyze_apt=None, installed_apt=None, search_apt=None, fetch_release=None, installed_version=None, release_keys=None):
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
        if approval_url:               # a link to THIS request's approval page; it carries no secret and decides nothing
            result["owner_approval_url"] = approval_url.rstrip("/") + "/approve/" + result["request_id"]
        result["next"] = ("The owner reviews and approves this on his phone. "
                          "Check progress with commander_software_install_status.")
        return {"ok": True, "result": result}

    @server.tool(name="commander_software_catalog", title="List software that can be requested",
                 annotations=READ_ONLY,
                 description="List the catalog ids an assistant may request. Read-only; changes nothing.")
    def software_catalog() -> dict:
        return {"ok": True, "software": catalog.listing()}

    @server.tool(name="commander_software_search", title="Search Ubuntu packages by name",
                 annotations=READ_ONLY,
                 description=("Search the computer's signed Ubuntu package lists by package NAME (read-only, local, "
                              "bounded). Returns name, version, summary, whether it is installed and whether an AI "
                              "may request it. Changes nothing."))
    def software_search(device_id: str, query: str) -> dict:
        try:
            header = bearer()
            if header is None:
                raise ClientDenied("not_authorized")
            try:
                router.authorize_read(header, device_id)                  # GREEN: read scope only, like inventory
            except AccessDenied:
                raise ClientDenied("device_unavailable_or_not_authorized") from None
            if search_apt is None:
                return _error("search_unavailable")
            try:
                found = search_apt(query)
            except ValueError:
                return _error("invalid_search_text")
            except RuntimeError:
                return _error("search_unavailable")
            results = []
            for item in found:
                blocked = impact.refusal_for(item["name"])
                results.append({**{k: item[k] for k in ("name", "version", "summary", "section", "installed")},
                                "installed": item.get("installed") is not None and bool(item.get("installed")),
                                "installed_version": item.get("installed"),
                                "ai_may_request": blocked is None,
                                **({"blocked_reason": impact.explain(blocked)} if blocked else {})})
            try:
                router.authorize_read(header, device_id)                  # a read can outlast a revocation
            except AccessDenied:
                raise ClientDenied("device_unavailable_or_not_authorized") from None
            return {"ok": True, "results": results,
                    "note": "Ubuntu archive only. To install, call commander_request_software_install with packages=[names]."}
        except ClientDenied as denied:
            return _error(denied.code)
        except Exception as error:
            _LOG.warning("search failed type=%s", type(error).__name__)
            return _error("search_unavailable")

    @server.tool(name="commander_request_software_install", title="Ask the owner to approve a software install",
                 annotations=FILES_A_REQUEST,
                 description=("Ask the computer's owner to approve installing software: either one catalog id "
                              "(software) or 1-3 Ubuntu package NAMES (packages) found with commander_software_search. "
                              "StyNpilot independently resolves signed Ubuntu versions and dependencies, refuses "
                              "kernels, boot, login, firewall and other core packages, and builds the exact plan; "
                              "the owner reviews and approves it separately on his phone. You cannot approve anything."))
    def request_install(device_id: str, software: str = "", packages: list[str] | None = None) -> dict:
        try:
            proposer, owner = guarded(device_id)
            if bool(software) == bool(packages):
                return _error("give_software_or_packages")
            info = None
            if packages:
                plan, summary, info = catalog.generic_install_plan(
                    packages, owner=owner, device=device_id, analyze=analyze_apt, installed=installed_apt, now=now())
                software = info["software"]
            else:
                plan, summary = catalog.install_plan(software, owner=owner, device=device_id,
                                                     resolve_apt=resolve_apt, now=now())
            expires = datetime.strptime(plan.content()["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc).timestamp()
            result, _ = store.submit(kind="install", software=software, device=device_id, owner=owner,
                                     proposer=proposer, payload=plan.content(), summary=summary, expires=expires)
            if info:
                result = {**result, "requested": info["requested"], "already_installed": info["already_installed"]}
        except (ClientDenied, RequestError) as denied:
            return _error(denied.code)
        except catalog.CatalogError as denied:
            code = denied.code
            out = _error(code.split(":", 1)[0])
            if code.startswith("blocked_package:"):
                out["reason"] = impact.explain(code.split(":", 1)[1])
            if code == "already_installed":
                out = {"ok": True, "already_installed": True, "result": {"already_installed": True},
                       "next": "Nothing to install: those packages are already installed. No request was filed."}
            return out
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
            title = catalog.describe(software) if catalog.is_generic(software) and _SLUG.fullmatch(software) \
                else catalog.entry(software)["title"]
            if type(rollback_id) is not str or not _ROLLBACK_ID.fullmatch(rollback_id):
                return _error("invalid_rollback_id")
            if ledger is None:
                return _error("rollback_not_available")
            # Only a real StyNpilot install of this software, on this owner's device, with a
            # verified backup, may be rolled back. Anything else is refused before the owner is asked.
            install = ledger.rollbackable(rollback_id, software=software, owner=owner, device=device_id)
            expires = now() + timedelta(hours=1)
            payload = {"kind": "rollback", "software": software, "rollback_id": rollback_id,
                       "request_id": install["request_id"], "snapshot_id": install["snapshot_id"],
                       "owner": owner, "device": device_id, "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ")}
            summary = ["Roll back %s (install %s)." % (title, rollback_id[:12]),
                       "Packages that install added are removed (their settings files are kept); packages it "
                       "upgraded go back to their saved earlier versions. The installer re-checks everything first "
                       "and refuses if anything else would be affected.",
                       "Expires %s UTC if not approved." % payload["expires_at"].replace("T", " ").rstrip("Z")]
            result, _ = store.submit(kind="rollback", software=software, device=device_id, owner=owner,
                                     proposer=proposer, payload=payload, summary=summary,
                                     expires=expires.timestamp())
        except (ClientDenied, catalog.CatalogError, RequestError, LedgerError) as denied:
            return _error(denied.code)
        except Exception as error:
            _LOG.warning("rollback request failed type=%s", type(error).__name__)
            return _error("request_refused")
        return receipt(result)

    @server.tool(name="commander_request_stynpilot_upgrade", title="Ask the owner to approve a StyNpilot upgrade",
                 annotations=FILES_A_REQUEST,
                 description=("Ask the owner to approve upgrading StyNpilot itself to a published, SIGNED release "
                              "(version like 0.1.0~dev14). StyNpilot downloads the release manifest from the project's "
                              "fixed release address, checks its signature against keys it already trusts, and files the "
                              "request; the owner sees the version, checksum and signing key on his phone and signs in to "
                              "approve. After approval StyNpilot backs up, installs, restarts, checks itself and "
                              "automatically rolls back if anything fails. You cannot approve, and cannot choose the "
                              "download address or the key."))
    def request_upgrade(device_id: str, version: str) -> dict:
        try:
            proposer, owner = guarded(device_id)
            if fetch_release is None or installed_version is None:
                return _error("upgrade_not_available")
            tag = release.tag_for_version(version)
            manifest_url, signature_url = release.manifest_urls(tag)
            try:
                manifest = json.loads(fetch_release(manifest_url, release.MAX_MANIFEST_BYTES).decode("utf-8"))
                signature = fetch_release(signature_url, 1024).decode("ascii").strip()
                key = release.verify(manifest, signature, release_keys or release.load_trusted_keys())
            except (ValueError, UnicodeError):
                return _error("release_manifest_unreadable")
            if manifest["tag"] != tag or manifest["version"].replace("~", "-") != version.replace("~", "-"):
                return _error("release_does_not_match_requested_version")
            installed = installed_version()
            expires = now() + timedelta(hours=1)
            payload = {"kind": "upgrade", "software": "stynpilot-self", "owner": owner, "device": device_id,
                       "manifest": manifest, "signature": signature,
                       "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ")}
            summary = release.summary_lines(manifest, key, installed)
            result, _ = store.submit(kind="upgrade", software="stynpilot-self", device=device_id, owner=owner,
                                     proposer=proposer, payload=payload, summary=summary, expires=expires.timestamp())
        except (ClientDenied, RequestError, release.ReleaseError) as denied:
            return _error(denied.code)
        except Exception as error:
            _LOG.warning("upgrade request failed type=%s", type(error).__name__)
            return _error("request_refused")
        return receipt(result)

    return gate
