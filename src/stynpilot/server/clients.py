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
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path

from .. import archive_publication, repo_archive, vault

PROPOSE_SCOPE = "workspace.propose"
REVIEW_SCOPE = "workspace.review"
UNIDENTIFIED_CLIENT = "unidentified-client"
KINDS = ("chatgpt", "claude", "local")
_CLIENT = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
ARCHIVE_AUTHORITY = "archive-client-authority"
_AUTHORITY_MARKER = ".archive-client-authority-enabled"


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
            return self._read_both()

    def _read_current(self):
        try:
            self._check_folder()
            data = json.loads(vault._read_private(self.path, 65536))
        except (OSError, ValueError, vault.VaultError):
            raise ClientDenied("client_state_unreadable") from None
        if (type(data) is not dict or set(data) != {"revoked"} or type(data["revoked"]) is not list
                or any(type(x) is not str or not _CLIENT.fullmatch(x) for x in data["revoked"])):
            raise ClientDenied("client_state_unreadable")
        return frozenset(data["revoked"])

    def _authority(self):
        return RevocationFile(self.path.parent / ARCHIVE_AUTHORITY / self.path.name)

    def _read_both(self):
        current = self._read_current()
        authority = self._authority()
        if os.path.lexists(authority.path.parent) or os.path.lexists(self.path.parent / _AUTHORITY_MARKER):
            current |= authority._read_current()
        return current

    def enable_archive_fence(self):
        """Initialize the separately mounted authority from the existing revocations."""
        authority = self._authority()
        marker = self.path.parent / _AUTHORITY_MARKER
        with self._lock, archive_publication.lock(self.path.parent):
            current = self._read_current()
            try:
                authority.path.parent.mkdir(mode=0o700)
            except FileExistsError:
                with archive_publication.lock(authority.path.parent):
                    retained = authority._read_current()
                    if not current <= retained:
                        authority._write(current | retained)
            else:
                if os.path.lexists(marker):
                    raise ClientDenied("client_state_unreadable")
                authority._write(current)
            if not os.path.lexists(marker):
                vault._write_atomic(self.path.parent, marker.name, b"enabled\n")

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
        data = json.dumps({"revoked": sorted(revoked)}).encode("utf-8")
        if len(data) > 65536:
            raise ClientDenied("client_state_unreadable")
        vault._write_atomic(self.path.parent, self.path.name, data)

    def set_revoked(self, client_id, revoked):
        """Owner-side only (owner tool / phone, G5). Never exposed to an AI."""
        if type(client_id) is not str or not _CLIENT.fullmatch(client_id):
            raise ClientDenied("client_state_unreadable")
        authority = self._authority()
        try:
            with self._lock, archive_publication.lock(self.path.parent):
                fenced = os.path.lexists(authority.path.parent) or os.path.lexists(self.path.parent / _AUTHORITY_MARKER)
                with (archive_publication.lock(authority.path.parent) if fenced else nullcontext()):
                    current = set(self._read_both())
                    (current.add if revoked else current.discard)(client_id)
                    if fenced and revoked:
                        authority._write(current)
                    self._write(current)
                    if fenced and not revoked:
                        authority._write(current)
        except (OSError, repo_archive.ArchiveError, vault.VaultError) as error:
            raise ClientDenied(getattr(error, "code", "client_state_unreadable")) from None


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

    def active(self, client_id):
        return client_id in self._clients and client_id not in self._revoked()

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
