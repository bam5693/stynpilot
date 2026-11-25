"""The owner's approval queue for YELLOW requests (standard library only).

An AI files a request; it waits here until the owner decides on his phone (G5), and
the executor (G4) runs only an *approved* request's exact stored plan. This module:

- stores the exact validated plan with its SHA-256; the request ID IS that hash;
- deduplicates by *what* is asked ("install htop on this device"): while such a request
  is pending, asking again (by any assistant, at any later second) returns the original
  request with its original exact plan and original expiry. Nothing is extended or
  re-hashed. Once it is decided or expired, a new ask files a new request;
- never approves anything: there is no AI-facing way to change a request's state;
- expires requests whose plan has expired;
- limits each AI client to a few pending requests, so a runaway assistant can't flood
  the owner's phone;
- records which enrolled client asked, so separate assistants stay distinguishable.

The database is a private file (0600, private folder), like the pairing database.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

STATES = ("pending", "approved", "denied", "expired", "running", "done", "failed", "needs_owner_intervention")
# The only legal moves. Owner-side code only: there is no AI-facing way to call transition().
_MOVES = {"pending": ("approved", "denied"), "approved": ("running", "needs_owner_intervention"),
          "running": ("done", "failed", "needs_owner_intervention")}
_SAFE_RESULT = ("ok", "stopped", "installed", "rollback_id", "restored", "restored_from_backup", "changed_anything",
                "not_restored", "needs_owner_intervention", "denied_by_owner", "backup_scope", "limits",
                "pending", "started", "rolled_back", "from_version", "to_version", "notes", "config_preserved",
                "action", "workspace", "entries", "skipped", "runner_user", "enabled", "selftest",
                "enrollment_open", "label", "kid", "passkeys_active")
KINDS = ("install", "rollback", "upgrade", "runner", "passkey", "release")
MAX_PENDING_PER_CLIENT = 5
_REQUEST_ID = re.compile(r"[a-f0-9]{64}\Z")


class RequestError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def request_id(payload):
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest(), canonical


class RequestStore:
    SCHEMA = 1

    def __init__(self, path, *, clock=time.time):
        target = Path(path)
        if not target.is_absolute():
            raise RequestError("absolute_path_required")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = os.lstat(target.parent)
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o077 or target.parent.is_symlink():
            raise RequestError("folder_not_private")
        if target.exists() or target.is_symlink():
            info = os.lstat(target)
            if target.is_symlink() or not target.is_file() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise RequestError("file_not_private")
        else:
            os.close(os.open(target, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600))
        self.path, self.clock, self._lock = str(target), clock, threading.Lock()
        with self._tx() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > self.SCHEMA:
                raise RequestError("store_newer_than_program")
            if version == 0:
                db.execute("""CREATE TABLE requests (
                    request_id TEXT PRIMARY KEY, logical_key TEXT NOT NULL, kind TEXT NOT NULL, software TEXT NOT NULL,
                    device TEXT NOT NULL, owner TEXT NOT NULL, client TEXT NOT NULL, client_name TEXT NOT NULL,
                    payload TEXT NOT NULL, summary TEXT NOT NULL,
                    state TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL,
                    decided REAL, result TEXT)""")
                db.execute("CREATE INDEX requests_logical ON requests(logical_key, state)")
                db.execute("PRAGMA user_version = %d" % self.SCHEMA)

    @contextmanager
    def _tx(self):
        with self._lock:
            db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
            db.row_factory = sqlite3.Row
            try:
                db.execute("BEGIN IMMEDIATE")
                try:
                    yield db
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
                db.execute("COMMIT")
            finally:
                db.close()

    def _expire(self, db):
        db.execute("UPDATE requests SET state='expired' WHERE state='pending' AND expires<=?", (self.clock(),))

    def submit(self, *, kind, software, device, owner, proposer, payload, summary, expires):
        """File a request. Returns (receipt, created_new). Idempotent for the same payload."""
        if kind not in KINDS or type(summary) is not list or not all(type(s) is str for s in summary):
            raise RequestError("invalid_request")
        if type(expires) not in (int, float) or expires <= self.clock():
            raise RequestError("expired")
        rid, canonical = request_id(payload)
        logical = "%s|%s|%s|%s" % (kind, software, owner, device)
        with self._tx() as db:
            self._expire(db)
            same = db.execute("SELECT * FROM requests WHERE logical_key=? AND state='pending' "
                              "ORDER BY created LIMIT 1", (logical,)).fetchone()
            if same is not None:
                return self._receipt(same), False        # original plan, original expiry
            row = db.execute("SELECT * FROM requests WHERE request_id=?", (rid,)).fetchone()
            if row is not None:
                if row["owner"] != owner or row["device"] != device:
                    raise RequestError("request_conflict")
                return self._receipt(row), False
            pending = db.execute("SELECT COUNT(*) FROM requests WHERE client=? AND state='pending'",
                                 (proposer.client,)).fetchone()[0]
            if pending >= MAX_PENDING_PER_CLIENT:
                raise RequestError("too_many_pending_requests")
            db.execute("INSERT INTO requests (request_id, logical_key, kind, software, device, owner, client, "
                       "client_name, payload, summary, state, created, expires) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (rid, logical, kind, software, device, owner, proposer.client, proposer.name, canonical,
                        json.dumps(summary[:16]), "pending", self.clock(), float(expires)))
            return self._receipt(db.execute("SELECT * FROM requests WHERE request_id=?", (rid,)).fetchone()), True

    def status(self, request_id_value, *, owner, device):
        """Safe status for any assistant acting for the same owner and device."""
        if type(request_id_value) is not str or not _REQUEST_ID.fullmatch(request_id_value):
            raise RequestError("unknown_request")
        with self._tx() as db:
            self._expire(db)
            row = db.execute("SELECT * FROM requests WHERE request_id=?", (request_id_value,)).fetchone()
        if row is None or row["owner"] != owner or row["device"] != device:
            raise RequestError("unknown_request")      # never reveal another owner's requests
        return self._receipt(row)

    def transition(self, request_id_value, from_state, to_state, *, result=None):
        """Owner-side compare-and-set. True if the move happened; False if the request was not in
        ``from_state`` (so two clicks or a replay can never decide twice). Illegal moves raise."""
        if type(request_id_value) is not str or not _REQUEST_ID.fullmatch(request_id_value):
            raise RequestError("unknown_request")
        if to_state not in _MOVES.get(from_state, ()):
            raise RequestError("illegal_transition")
        safe = None if result is None else json.dumps({k: result[k] for k in _SAFE_RESULT if k in result},
                                                      sort_keys=True)
        with self._tx() as db:
            self._expire(db)
            row = db.execute("SELECT state FROM requests WHERE request_id=?", (request_id_value,)).fetchone()
            if row is None:
                raise RequestError("unknown_request")
            if row["state"] != from_state:
                return False
            db.execute("UPDATE requests SET state=?, decided=COALESCE(decided, ?), result=COALESCE(?, result) "
                       "WHERE request_id=?", (to_state, self.clock(), safe, request_id_value))
            return True

    def in_flight(self):
        with self._tx() as db:
            return [r["request_id"] for r in db.execute(
                "SELECT request_id FROM requests WHERE state IN ('approved','running') ORDER BY created")]

    def recover_interrupted(self):
        """After a restart: anything approved or running may have changed the machine, so it is marked
        for the owner instead of being retried or silently reported as pending/running."""
        with self._tx() as db:
            rows = db.execute("SELECT request_id FROM requests WHERE state IN ('approved','running')").fetchall()
            for row in rows:
                db.execute("UPDATE requests SET state='needs_owner_intervention', result=? WHERE request_id=?",
                           (json.dumps({"ok": False, "stopped": "interrupted_by_restart_or_crash",
                                        "needs_owner_intervention": True}), row["request_id"]))
            return [row["request_id"] for row in rows]

    @staticmethod
    def _receipt(row):
        receipt = {"request_id": row["request_id"], "kind": row["kind"], "software": row["software"],
                   "state": row["state"], "requested_by": row["client_name"],
                   "summary": json.loads(row["summary"]), "expires_at": int(row["expires"]),
                   "approved_by_ai": False}
        if row["result"]:
            receipt["result"] = json.loads(row["result"])
        return receipt

    def payload(self, request_id_value):
        """The exact stored payload, for the owner's approval page and the executor (never for AIs)."""
        with self._tx() as db:
            row = db.execute("SELECT payload FROM requests WHERE request_id=?", (request_id_value,)).fetchone()
        return None if row is None else json.loads(row["payload"])
