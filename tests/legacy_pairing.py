"""Builds a pairing database in the GitLab prototype's exact layout (schema version 2).

The SQL below is copied from GitLab pairing_engine.py and device_permissions.py, so
these tests prove the new code reads the file the owner's computer already has.
All identifiers are fictional.
"""
import os
import sqlite3
from pathlib import Path

LEGACY_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS pairing_requests (
        device_hash TEXT PRIMARY KEY, user_hash TEXT UNIQUE NOT NULL, device_name TEXT NOT NULL,
        created REAL NOT NULL, expires REAL NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','redeemed')),
        owner_id TEXT, last_poll REAL, redeemed_device_id TEXT)""",
    """CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, device_name TEXT NOT NULL,
        token_hash TEXT UNIQUE NOT NULL, created REAL NOT NULL, expires REAL NOT NULL, revoked REAL)""",
    """CREATE TABLE IF NOT EXISTS approval_limits (
        account_id TEXT PRIMARY KEY, window_start REAL NOT NULL, attempts INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS relay_presence (
        device_id TEXT PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,
        online INTEGER NOT NULL DEFAULT 0 CHECK(online IN (0,1)), last_seen REAL)""",
    """CREATE TABLE IF NOT EXISTS relay_tasks (
        task_id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
        state TEXT NOT NULL CHECK(state IN ('queued','delivered','done','failed')),
        created REAL NOT NULL, deadline REAL NOT NULL, error TEXT)""",
    """CREATE TABLE device_permission_consent (
        device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
        scope TEXT NOT NULL CHECK(scope IN (
            'workspace.read','workspace.write','development.execute','tasks.coordinate',
            'system.read','workspace.propose','software.propose','maintenance.propose',
            'development.file.read','workspace.review')),
        PRIMARY KEY(device_id, scope))""",
]


def make_pairing_db(folder: Path, devices, *, version=2):
    """devices: list of (device_id, owner_id, expires, revoked_or_None, [scopes])."""
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(folder, 0o700)
    path = folder / "pairing.sqlite3"
    db = sqlite3.connect(path)
    for statement in LEGACY_SCHEMA:
        db.execute(statement)
    for n, (device_id, owner_id, expires, revoked, scopes) in enumerate(devices):
        db.execute("INSERT INTO devices VALUES (?,?,?,?,?,?,?)",
                   (device_id, owner_id, "Test computer %d" % n, "hash-%d" % n, 1.0, expires, revoked))
        for scope in scopes:
            db.execute("INSERT INTO device_permission_consent VALUES (?,?)", (device_id, scope))
    db.execute("PRAGMA user_version = %d" % version)
    db.commit()
    db.close()
    os.chmod(path, 0o600)
    return path
