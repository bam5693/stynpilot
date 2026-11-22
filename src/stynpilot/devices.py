"""Owner device grants, read from the existing pairing database (standard library only).

The owner's computer already has a pairing database written by the GitLab prototype
(pairing_engine.py schema version 2, plus the device_permission_consent table). This
module reads that file **read-only** and returns the same answers the prototype did,
so upgrading keeps the existing pairing and nothing has to be re-paired.

Rules carried over exactly (auth0_pairing_adapter.PairingDeviceGrantStore and
device_permissions.SQLiteDevicePermissions):
- the owner ID must look like ``acct_<40 hex>`` and the device ID like ``dtdev_...``;
- a revoked device is reported as revoked, with health.read only;
- an expired device returns no grant at all;
- a live device gets health.read plus the scopes the owner consented to.

Opening fails closed unless the file is a private (0600) regular file owned by this
user, in a private folder, at a schema version this code knows.
"""
from __future__ import annotations

import os
import re
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

OWNER_ID = re.compile(r"acct_[a-f0-9]{40}\Z")
DEVICE_ID = re.compile(r"dtdev_[A-Za-z0-9_-]{8,64}\Z")
KNOWN_SCOPES = frozenset({
    "health.read", "workspace.read", "workspace.write", "development.execute", "tasks.coordinate",
    "system.read", "workspace.propose", "software.propose", "maintenance.propose",
    "development.file.read", "workspace.review",
})
SCHEMA_VERSION = 2


class DeviceStoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class DeviceGrant:
    owner_id: str
    device_id: str
    scopes: frozenset
    expires_at: float
    revoked: bool = False


def _private_file(path: Path):
    if not path.is_absolute():
        raise DeviceStoreError("Pairing database path must be absolute")
    try:
        info = os.lstat(path)
        parent = os.lstat(path.parent)
    except OSError as error:
        raise DeviceStoreError("Pairing database not found") from error
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise DeviceStoreError("Pairing database must be a private regular file owned by this user")
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
        raise DeviceStoreError("Pairing database folder must be private to this user")


class PairingDeviceGrants:
    """``get(owner_id=..., device_id=...)`` -> DeviceGrant or None. Never writes the file."""

    def __init__(self, path, *, clock=time.time):
        path = Path(path)
        _private_file(path)
        self.clock = clock
        self._lock = threading.Lock()
        try:
            self._db = sqlite3.connect("file:%s?mode=ro" % quote(str(path)), uri=True, timeout=3,
                                       check_same_thread=False)
            self._db.row_factory = sqlite3.Row
            version = self._db.execute("PRAGMA user_version").fetchone()[0]
            tables = {row[0] for row in self._db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        except sqlite3.Error as error:
            raise DeviceStoreError("Pairing database could not be opened read-only") from error
        if version != SCHEMA_VERSION or "devices" not in tables:
            self._db.close()
            raise DeviceStoreError("Unsupported pairing database version")
        self._has_consent = "device_permission_consent" in tables

    def get(self, *, owner_id, device_id):
        if (type(owner_id) is not str or not OWNER_ID.fullmatch(owner_id)
                or type(device_id) is not str or not DEVICE_ID.fullmatch(device_id)):
            return None
        try:
            with self._lock:
                row = self._db.execute("SELECT expires, revoked FROM devices WHERE device_id=? AND owner_id=?",
                                       (device_id, owner_id)).fetchone()
                if row is None:
                    return None
                expires, revoked = row["expires"], row["revoked"] is not None
                if type(expires) not in (int, float):
                    return None
                if revoked:
                    return DeviceGrant(owner_id, device_id, frozenset({"health.read"}), float(expires), True)
                if expires <= self.clock():
                    return None          # prototype: an expired device has no grant at all
                scopes = {"health.read"}
                if self._has_consent:
                    scopes |= {r[0] for r in self._db.execute(
                        "SELECT scope FROM device_permission_consent WHERE device_id=?", (device_id,))}
        except sqlite3.Error:
            return None
        if not scopes <= KNOWN_SCOPES:
            return None                  # an unknown scope in the file means something is wrong
        return DeviceGrant(owner_id, device_id, frozenset(scopes), float(expires), False)

    def paired_devices(self):
        """(owner_id, device_id) for every live paired device; the endpoint requires exactly one."""
        with self._lock:
            rows = self._db.execute("SELECT owner_id, device_id, expires FROM devices WHERE revoked IS NULL").fetchall()
        now = self.clock()
        return [(r["owner_id"], r["device_id"]) for r in rows
                if type(r["expires"]) in (int, float) and r["expires"] > now
                and OWNER_ID.fullmatch(r["owner_id"] or "") and DEVICE_ID.fullmatch(r["device_id"] or "")]

    def close(self):
        with self._lock:
            self._db.close()
