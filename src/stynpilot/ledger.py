"""The install ledger: which installs StyNpilot actually made, and whether each can be undone.

The executor (G4) writes one entry per completed install: its rollback ID, the software,
owner and device, the request it came from, and the backup snapshot taken before the
change, with whether that snapshot was *verified restorable*. Nothing an AI sends is
ever written here.

A rollback request is accepted only for an entry that exists, belongs to the same owner,
device and software, has not been rolled back already, and has a verified snapshot.
Only then may the owner be told that his data will be restored. G4 re-checks the same
entry before it runs anything.

Installs made by the previous (GitLab) build are not in this ledger yet, so their
rollback stays with that build until its records are imported and checked.

Private SQLite file (0600, private folder), standard library only.
"""
from __future__ import annotations

import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

ROLLBACK_ID = re.compile(r"[a-f0-9]{16,64}\Z")


class LedgerError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class InstallLedger:
    SCHEMA = 1

    def __init__(self, path, *, clock=time.time):
        target = Path(path)
        if not target.is_absolute():
            raise LedgerError("absolute_path_required")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = os.lstat(target.parent)
        if target.parent.is_symlink() or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
            raise LedgerError("folder_not_private")
        if target.exists() or target.is_symlink():
            info = os.lstat(target)
            if target.is_symlink() or not target.is_file() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise LedgerError("file_not_private")
        else:
            os.close(os.open(target, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600))
        self.path, self.clock, self._lock = str(target), clock, threading.Lock()
        with self._tx() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > self.SCHEMA:
                raise LedgerError("ledger_newer_than_program")
            if version == 0:
                db.execute("""CREATE TABLE installs (
                    rollback_id TEXT PRIMARY KEY, software TEXT NOT NULL, owner TEXT NOT NULL,
                    device TEXT NOT NULL, request_id TEXT NOT NULL, snapshot_id TEXT NOT NULL,
                    snapshot_verified INTEGER NOT NULL CHECK(snapshot_verified IN (0,1)),
                    installed REAL NOT NULL, rolled_back REAL)""")
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

    def record(self, *, rollback_id, software, owner, device, request_id, snapshot_id, snapshot_verified):
        """Executor only (G4), after a completed install. Not reachable from any AI tool."""
        if type(rollback_id) is not str or not ROLLBACK_ID.fullmatch(rollback_id) or type(snapshot_verified) is not bool:
            raise LedgerError("invalid_entry")
        with self._tx() as db:
            db.execute("INSERT INTO installs VALUES (?,?,?,?,?,?,?,?,NULL)",
                       (rollback_id, software, owner, device, request_id, snapshot_id,
                        int(snapshot_verified), self.clock()))

    def mark_rolled_back(self, rollback_id):
        """Executor only (G4), after a verified restore."""
        with self._tx() as db:
            if db.execute("UPDATE installs SET rolled_back=? WHERE rollback_id=? AND rolled_back IS NULL",
                          (self.clock(), rollback_id)).rowcount != 1:
                raise LedgerError("unknown_rollback_id")

    def rollbackable(self, rollback_id, *, software, owner, device):
        """The entry if a rollback may be *requested*; otherwise LedgerError with the reason."""
        if type(rollback_id) is not str or not ROLLBACK_ID.fullmatch(rollback_id):
            raise LedgerError("invalid_rollback_id")
        with self._tx() as db:
            row = db.execute("SELECT * FROM installs WHERE rollback_id=?", (rollback_id,)).fetchone()
        if row is None or row["owner"] != owner or row["device"] != device:
            raise LedgerError("unknown_rollback_id")            # never reveal another owner's installs
        if row["software"] != software:
            raise LedgerError("rollback_id_is_for_other_software")
        if row["rolled_back"] is not None:
            raise LedgerError("already_rolled_back")
        if not row["snapshot_verified"]:
            raise LedgerError("no_verified_backup")
        return dict(row)
