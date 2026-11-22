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

import json
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path

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


class RevocationFile:
    """Durable list of revoked AI client IDs: a private JSON file, replaced atomically.

    Read on EVERY check, so a revocation takes effect immediately and survives restarts.
    If the file can't be read or trusted, every proposal is refused (fail closed). That includes a
    MISSING file: it is created once, explicitly, by ``provision()`` (installer / owner setup), so
    deleting it afterwards can never silently bring a revoked client back. Recovery is an owner
    action (``provision()`` again, then re-revoke anyone who should stay out).
    """

    def __init__(self, path):
        self.path = Path(path)
        if not self.path.is_absolute():
            raise ValueError("Absolute revocation file path required")
        self._lock = threading.Lock()

    def _check_folder(self):
        info = os.lstat(self.path.parent)
        if self.path.parent.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ClientDenied("client_state_unreadable")

    def revoked(self):
        with self._lock:
            try:
                self._check_folder()
                fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
            except (OSError, ClientDenied):
                raise ClientDenied("client_state_unreadable") from None
            try:
                info = os.fstat(fd)
                if info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 65536:
                    raise ClientDenied("client_state_unreadable")
                data = json.loads(os.read(fd, 65537).decode("utf-8"))
            except (OSError, ValueError, UnicodeError):
                raise ClientDenied("client_state_unreadable") from None
            finally:
                os.close(fd)
            if (type(data) is not dict or set(data) != {"revoked"} or type(data["revoked"]) is not list
                    or any(type(x) is not str or not _CLIENT.fullmatch(x) for x in data["revoked"])):
                raise ClientDenied("client_state_unreadable")
            return frozenset(data["revoked"])

    def provision(self):
        """Create the empty list once. Returns True if created, False if it already exists (left untouched)."""
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._check_folder()
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                return False
            try:
                os.write(fd, b'{"revoked": []}')
                os.fsync(fd)
            finally:
                os.close(fd)
            return True

    def _write(self, revoked):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._check_folder()
        tmp = self.path.with_name(self.path.name + ".tmp")
        fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, json.dumps({"revoked": sorted(revoked)}).encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.path)

    def set_revoked(self, client_id, revoked):
        """Owner-side only (owner tool / phone, G5). Never exposed to an AI."""
        current = set(self.revoked())
        (current.add if revoked else current.discard)(client_id)
        with self._lock:
            self._write(current)


class EnrolledClients:
    """The owner's list of AI clients, e.g. [{"client_id": ..., "name": "claude", "kind": "claude"}].

    ``revocations``: a RevocationFile. Production must pass one; without it, revocations
    live only in memory (tests).
    """

    def __init__(self, clients, *, revocations=None):
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
        self._memory, self._lock, self.revocations = set(), threading.Lock(), revocations

    def _revoked(self):
        if self.revocations is not None:
            return self.revocations.revoked()
        with self._lock:
            return frozenset(self._memory)

    def revoke(self, client_id):
        if self.revocations is not None:
            self.revocations.set_revoked(client_id, True)
        else:
            with self._lock:
                self._memory.add(client_id)

    def reinstate(self, client_id):
        if self.revocations is not None:
            self.revocations.set_revoked(client_id, False)
        else:
            with self._lock:
                self._memory.discard(client_id)

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
        entry = None if client in self._revoked() else self._clients.get(client)
        if entry is None:
            raise ClientDenied("client_not_enrolled_or_revoked")
        return Proposer(client=client, name=entry["name"], kind=entry["kind"], account=who.account)
