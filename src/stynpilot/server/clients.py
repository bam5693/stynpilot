"""Enrolled AI clients: who may *propose* changes, each separately revocable (standard library).

Ported from the GitLab prototype (AIClientRegistry / AIIdentityVerifier checks in
src/commander_ai_endpoint.py), applied to the write-capable (propose) tools.

A propose call must come from:
- an identified OAuth client (``azp``/``client_id``; the read-only placeholder
  ``unidentified-client`` is refused),
- that the owner enrolled (ChatGPT connector, Claude connector, a local worker...),
- that is not currently revoked (revoking one client never affects the others),
- whose token has ``workspace.propose`` and does NOT have ``workspace.review``: an AI
  session that could also approve would be able to approve its own requests.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass

PROPOSE_SCOPE = "workspace.propose"
REVIEW_SCOPE = "workspace.review"
UNIDENTIFIED_CLIENT = "unidentified-client"
KINDS = ("chatgpt", "claude", "local")
_CLIENT = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")


class ClientDenied(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Proposer:
    client: str
    name: str
    kind: str
    account: str


class EnrolledClients:
    """The owner's list of AI clients, e.g. [{"client_id": ..., "name": "claude", "kind": "claude"}]."""

    def __init__(self, clients):
        if type(clients) is not list or not 1 <= len(clients) <= 8:
            raise ValueError("One to eight enrolled AI clients required")
        self._clients, names = {}, set()
        for item in clients:
            if (type(item) is not dict or set(item) != {"client_id", "name", "kind"}
                    or type(item["client_id"]) is not str or not _CLIENT.fullmatch(item["client_id"])
                    or item["client_id"] == UNIDENTIFIED_CLIENT
                    or type(item["name"]) is not str or not _NAME.fullmatch(item["name"])
                    or item["kind"] not in KINDS
                    or item["client_id"] in self._clients or item["name"] in names):
                raise ValueError("Invalid or duplicate AI client")
            self._clients[item["client_id"]] = dict(item)
            names.add(item["name"])
        self._revoked, self._lock = set(), threading.Lock()

    def revoke(self, client_id):
        with self._lock:
            self._revoked.add(client_id)

    def reinstate(self, client_id):
        with self._lock:
            self._revoked.discard(client_id)

    def proposer(self, who):
        """``who`` is a verified Authorization. Returns a Proposer or raises ClientDenied."""
        client = getattr(who, "client", None)
        scopes = frozenset(getattr(who, "scopes", ()) or ())
        if not isinstance(client, str) or client == UNIDENTIFIED_CLIENT:
            raise ClientDenied("client_identity_missing")
        if REVIEW_SCOPE in scopes:
            raise ClientDenied("assistant_session_must_not_have_review_scope")
        if PROPOSE_SCOPE not in scopes:
            raise ClientDenied("insufficient_scope")
        with self._lock:
            entry = None if client in self._revoked else self._clients.get(client)
        if entry is None:
            raise ClientDenied("client_not_enrolled_or_revoked")
        return Proposer(client=client, name=entry["name"], kind=entry["kind"], account=who.account)
