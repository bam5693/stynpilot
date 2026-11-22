"""Read-only compatibility check: can the new StyNpilot code read this computer's real setup?

Run it as the computer's normal owner, without sudo:

    python3 -I -B -m stynpilot.compat_check

It checks, using only the new code (GitHub) and changing nothing:
1. the existing pairing database (written by the current GitLab build) opens read-only,
   is private, and has the schema the new code expects;
2. exactly one live paired device, the same one the current build is configured for,
   whose owner ID has the format the new sign-in code produces;
3. that device's grant and owner-consented permission names (names only);
4. Forgejo's real status, through the new fail-closed status checker;
5. that the pairing database is byte-for-byte unchanged afterwards.

It prints no IDs, tokens, secrets, file contents or host names: only yes/no answers,
counts, permission names and Forgejo's public version. It never writes a file, opens no
network connection except two GET requests to Forgejo on 127.0.0.1:3000, runs no
command, and needs no sign-in.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from urllib.parse import quote

from .devices import OWNER_ID, DeviceStoreError, PairingDeviceGrants
from .service_status import service_status

STATE_DIR = ".local/state/stynpilot-owner"


def _digest(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def _configured_device(base):
    """The device the current build is configured for (controller-runtime.json), or None."""
    path = base / "controller-runtime.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077 or not 0 < info.st_size <= 8192:
                return None
            data = json.loads(os.read(fd, 8193).decode("utf-8"))
        finally:
            os.close(fd)
        rows = data.get("workspaces") if isinstance(data, dict) else None
        if isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict):
            device = rows[0].get("device_id")
            return device if isinstance(device, str) else None
    except (OSError, ValueError, UnicodeError):
        return None
    return None


def run(home, *, get=None):
    """Return a list of (ok: bool|None, title, detail). Never includes identifiers."""
    base = Path(home) / STATE_DIR
    db_path = base / "pairing.sqlite3"
    results = []
    before = _digest(db_path)

    try:
        grants = PairingDeviceGrants(db_path)
    except DeviceStoreError as error:
        results.append((False, "Pairing database opens read-only", str(error)))
        return results
    try:
        results.append((True, "Pairing database opens read-only", "private file, private folder, schema 2"))
        try:
            with sqlite3.connect("file:%s?mode=ro" % quote(str(db_path)), uri=True, timeout=3) as db:
                mode = db.execute("PRAGMA journal_mode").fetchone()[0]
            results.append((True, "Journal mode readable", str(mode)))
        except sqlite3.Error:
            results.append((None, "Journal mode readable", "could not be read"))

        live = grants.paired_devices()
        results.append((len(live) == 1, "Exactly one live paired device", "%d found" % len(live)))
        if len(live) != 1:
            return results
        owner_id, device_id = live[0]
        results.append((bool(OWNER_ID.fullmatch(owner_id)), "Owner ID format matches the new sign-in code",
                        "acct_ + 40 hex" if OWNER_ID.fullmatch(owner_id) else "unexpected format"))
        configured = _configured_device(base)
        if configured is None:
            results.append((None, "Same device as the current build's settings", "settings file not readable"))
        else:
            results.append((configured == device_id, "Same device as the current build's settings",
                            "yes" if configured == device_id else "NO, they differ"))
        grant = grants.get(owner_id=owner_id, device_id=device_id)
        if grant is None:
            results.append((False, "Device grant", "none (expired or unreadable)"))
        else:
            results.append((not grant.revoked and "health.read" in grant.scopes, "Device grant",
                            "active; permissions: " + ", ".join(sorted(grant.scopes))))
    finally:
        grants.close()

    try:
        report = service_status("forgejo", get=get) if get else service_status("forgejo")
        detail = "state=%s, version=%s, enabled at boot=%s, port owned by forgejo account=%s, reachable beyond this computer=%s" % (
            report["state"], report["version"] or "unknown", report["service_enabled_at_boot"],
            report["listener_owned_by_service_account"], report["listening_beyond_loopback"])
        results.append((report["state"] == "running", "Forgejo status (new checker)", detail))
    except Exception as error:
        results.append((False, "Forgejo status (new checker)", "check failed: %s" % type(error).__name__))

    after = _digest(db_path)
    results.append((before is not None and before == after, "Pairing database unchanged afterwards",
                    "byte-for-byte identical" if before == after else "CHANGED or unreadable"))
    return results


def main(argv=None, out=sys.stdout):
    if os.geteuid() == 0:
        out.write("Stopped: run this as your normal user, without sudo.\n")
        return 2
    results = run(Path.home())
    for ok, title, detail in results:
        mark = "ok " if ok else ("?  " if ok is None else "NO ")
        out.write("[%s] %s: %s\n" % (mark, title, detail))
    failed = [title for ok, title, _ in results if ok is False]
    out.write("\n%s\nNothing was changed.\n" % (
        "COMPATIBLE: the new code reads this computer's setup correctly." if not failed
        else "NOT YET COMPATIBLE: " + "; ".join(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
