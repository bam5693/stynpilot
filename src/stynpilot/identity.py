"""Owner identity and session revocation (standard library only).

Ported from the GitLab prototype (customer_identity.py, session_revocation.py).

- ``account_id`` turns a *verified* issuer + subject into a stable pseudonymous ID,
  so raw Auth0 subjects never reach storage or logs.
- Revocation stores remember "every token issued before time T is dead" per account.
  They fail closed: if the store can't be read, access is denied.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import threading
from pathlib import Path

_SUBJECT = re.compile(r"[^\x00-\x1f\x7f]{1,256}\Z")
_ACCOUNT = re.compile(r"acct_[a-f0-9]{40}\Z")


class TokenDenied(ValueError):
    """A bearer token was refused. Never put a token or claim in this error."""


class RevocationError(RuntimeError):
    """Revocation state could not be read or durably written."""


def account_id(*, verified_issuer: str, verified_subject: str) -> str:
    """Only call with claims from a token whose signature was already verified."""
    if (not isinstance(verified_issuer, str) or not verified_issuer.startswith("https://")
            or len(verified_issuer) > 1024
            or not isinstance(verified_subject, str) or not _SUBJECT.fullmatch(verified_subject)):
        raise ValueError("Verified issuer and subject required")
    digest = hashlib.sha256((verified_issuer + "\0" + verified_subject).encode()).hexdigest()
    return "acct_" + digest[:40]


def _check(issuer, account):
    if (not isinstance(issuer, str) or not issuer.startswith("https://") or len(issuer) > 1024
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)):
        raise RevocationError("Verified account required")


class MemoryRevocations:
    """For tests only: forgets everything when the process exits."""
    durable = False

    def __init__(self):
        self._rows, self._lock = {}, threading.RLock()

    def revoked_before(self, issuer, account):
        _check(issuer, account)
        with self._lock:
            return self._rows.get((issuer, account))

    def revoke_before(self, issuer, account, epoch_seconds):
        _check(issuer, account)
        if type(epoch_seconds) is not int or epoch_seconds < 0:
            raise RevocationError("Valid revocation timestamp required")
        with self._lock:
            key = (issuer, account)
            self._rows[key] = max(epoch_seconds, self._rows.get(key, 0))

    def close(self):
        return None


class SQLiteRevocations:
    """Durable store in a file only this user can read (0600, private parent folder)."""
    durable = True
    SCHEMA = 1

    def __init__(self, path, *, timeout_seconds=1.0):
        if type(timeout_seconds) not in (int, float) or not 0.1 <= timeout_seconds <= 10:
            raise RevocationError("SQLite timeout must be 0.1-10 seconds")
        target = Path(path).expanduser()
        if str(path) in ("", ":memory:") or str(path).startswith("file:"):
            raise RevocationError("A real local file path is required")
        self._lock = threading.RLock()
        try:
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            parent = target.parent.stat()
            if (target.parent.is_symlink() or parent.st_uid != os.geteuid() or parent.st_mode & 0o077):
                raise RevocationError("Revocation folder must be private to this user")
            if target.exists() or target.is_symlink():
                info = target.lstat()
                if target.is_symlink() or not target.is_file() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                    raise RevocationError("Revocation database must be a private regular file")
            else:
                os.close(os.open(target, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600))
            self._db = sqlite3.connect(str(target), timeout=timeout_seconds, isolation_level=None,
                                       check_same_thread=False)
            self._db.execute("PRAGMA busy_timeout = 1000")
            self._db.execute("PRAGMA synchronous = FULL")
            self._db.execute("PRAGMA journal_mode = WAL")
            self._migrate()
        except RevocationError:
            raise
        except (OSError, sqlite3.Error, ValueError) as error:
            raise RevocationError("Could not open revocation storage") from error

    def _migrate(self):
        version = int(self._db.execute("PRAGMA user_version").fetchone()[0])
        if version > self.SCHEMA:
            raise RevocationError("Revocation database is newer than this program")
        if version == 0:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute("""CREATE TABLE revocations (
                    issuer TEXT NOT NULL, account TEXT NOT NULL,
                    revoked_before INTEGER NOT NULL CHECK(revoked_before >= 0),
                    PRIMARY KEY (issuer, account))""")
                self._db.execute("PRAGMA user_version = %d" % self.SCHEMA)
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def revoked_before(self, issuer, account):
        _check(issuer, account)
        try:
            with self._lock:
                row = self._db.execute("SELECT revoked_before FROM revocations WHERE issuer=? AND account=?",
                                       (issuer, account)).fetchone()
            return int(row[0]) if row else None
        except sqlite3.Error as error:
            raise RevocationError("Could not read revocation state") from error

    def revoke_before(self, issuer, account, epoch_seconds):
        _check(issuer, account)
        if type(epoch_seconds) is not int or epoch_seconds < 0:
            raise RevocationError("Valid revocation timestamp required")
        try:
            with self._lock:
                self._db.execute("""INSERT INTO revocations (issuer, account, revoked_before) VALUES (?, ?, ?)
                    ON CONFLICT(issuer, account) DO UPDATE SET
                    revoked_before = MAX(revoked_before, excluded.revoked_before)""",
                                 (issuer, account, epoch_seconds))
        except sqlite3.Error as error:
            raise RevocationError("Could not save revocation state") from error

    def close(self):
        with self._lock:
            self._db.close()
