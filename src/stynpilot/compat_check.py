"""Read-only compatibility check: can the new StyNpilot code read this computer's real setup?

Run it as the computer's normal owner, without sudo:

    python3 -I -B -m stynpilot.compat_check

It checks, using only the new code (GitHub), with every required check always reported:
1. the existing pairing database (written by the current GitLab build) opens read-only,
   is private, and has the schema the new code expects;
2. exactly one live paired device, the same one the current build is configured for,
   whose owner ID has the format the new sign-in code produces;
3. that device's grant and owner-consented permission names (names only);
4. whether the pairing database and its journal side files are byte-for-byte unchanged
   afterwards (it opens them read-only, but the running StyNpilot may write meanwhile);
5. separately, Forgejo's real status through the new fail-closed checker.

The pairing verdict is COMPATIBLE only if every required check positively passed;
anything not checked or not provable makes it INCONCLUSIVE, any failure NOT COMPATIBLE.

It prints no IDs, tokens, secrets, file contents or host names: only yes/no answers,
counts, permission names and Forgejo's public version. It never writes a file, runs no
command, needs no sign-in, and its only network use is up to three GET requests to
Forgejo on 127.0.0.1:3000 (health, version, and the front page if neither answered).
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


SIDE_FILES = ("", "-journal", "-wal", "-shm")
REQUIRED = (
    "Pairing database opens read-only",
    "Exactly one live paired device",
    "Owner ID format matches the new sign-in code",
    "Same device as the current build's settings",
    "Device grant",
    "Pairing database unchanged afterwards",
)
FORGEJO = "Forgejo status (new checker)"


def _fingerprint(db_path):
    """SHA-256 of the database and any journal side files; None if the main file can't be read."""
    out = {}
    for suffix in SIDE_FILES:
        path = Path(str(db_path) + suffix)
        try:
            out[suffix or "db"] = hashlib.sha256(path.read_bytes()).hexdigest()
        except FileNotFoundError:
            out[suffix or "db"] = None
        except OSError:
            return None
    return out if out["db"] is not None else None


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


def _pairing_checks(db_path, base):
    """Yield (ok, title, detail) for the pairing checks, stopping at the first that blocks the rest."""
    try:
        grants = PairingDeviceGrants(db_path)
    except DeviceStoreError as error:
        yield False, "Pairing database opens read-only", str(error)
        return
    try:
        yield True, "Pairing database opens read-only", "private file, private folder, schema 2"
        try:
            with sqlite3.connect("file:%s?mode=ro" % quote(str(db_path)), uri=True, timeout=3) as db:
                mode = db.execute("PRAGMA journal_mode").fetchone()[0]
            yield True, "Journal mode readable", str(mode)
        except sqlite3.Error:
            yield None, "Journal mode readable", "could not be read"
        live = grants.paired_devices()
        yield len(live) == 1, "Exactly one live paired device", "%d found" % len(live)
        if len(live) != 1:
            return
        owner_id, device_id = live[0]
        good = bool(OWNER_ID.fullmatch(owner_id))
        yield good, "Owner ID format matches the new sign-in code", "acct_ + 40 hex" if good else "unexpected format"
        configured = _configured_device(base)
        if configured is None:
            yield None, "Same device as the current build's settings", "settings file missing or not readable"
        else:
            yield (configured == device_id, "Same device as the current build's settings",
                   "yes" if configured == device_id else "NO, they differ")
        grant = grants.get(owner_id=owner_id, device_id=device_id)
        if grant is None:
            yield False, "Device grant", "none (expired or unreadable)"
        else:
            yield (not grant.revoked and "health.read" in grant.scopes, "Device grant",
                   "active; permissions: " + ", ".join(sorted(grant.scopes)))
    finally:
        grants.close()


def run(home, *, status=None):
    """Every REQUIRED check plus Forgejo, always: (ok True/False/None, title, detail). No identifiers."""
    base = Path(home) / STATE_DIR
    db_path = base / "pairing.sqlite3"
    before = _fingerprint(db_path)
    results = []
    try:
        results.extend(_pairing_checks(db_path, base))
    finally:
        after = _fingerprint(db_path)
        if before is None or after is None:
            results.append((None, "Pairing database unchanged afterwards", "could not fingerprint the file"))
        elif before == after:
            results.append((True, "Pairing database unchanged afterwards", "byte-for-byte identical, side files too"))
        else:
            results.append((None, "Pairing database unchanged afterwards",
                            "it CHANGED while this ran. This tool only reads it, so another program "
                            "(probably the running StyNpilot) wrote to it. Run the check again."))
    seen = {title for _, title, _ in results}
    for title in REQUIRED:
        if title not in seen:
            results.insert(len(results) - 1, (None, title, "not checked (an earlier check did not pass)"))
    try:
        report = (status or service_status)("forgejo")
        detail = ("state=%s, version=%s, enabled at boot=%s, port owned by forgejo account=%s, "
                  "reachable beyond this computer=%s" % (
                      report["state"], report["version"] or "unknown", report["service_enabled_at_boot"],
                      report["listener_owned_by_service_account"], report["listening_beyond_loopback"]))
        results.append((report["state"] == "running", FORGEJO, detail))
    except Exception as error:
        results.append((False, FORGEJO, "check failed: %s" % type(error).__name__))
    return results


def verdict(results):
    """PAIRING verdict from the required checks only: COMPATIBLE needs every one to be True."""
    required = {title: ok for ok, title, _ in results if title in REQUIRED}
    if any(required.get(title) is False for title in REQUIRED):
        return "NOT COMPATIBLE"
    if all(required.get(title) is True for title in REQUIRED):
        return "COMPATIBLE"
    return "INCONCLUSIVE"


def main(argv=None, out=sys.stdout, *, home=None, status=None):
    if os.geteuid() == 0:
        out.write("Stopped: run this as your normal user, without sudo.\n")
        return 2
    results = run(home or Path.home(), status=status)
    for ok, title, detail in results:
        mark = "ok " if ok else ("?  " if ok is None else "NO ")
        out.write("[%s] %s: %s\n" % (mark, title, detail))
    pairing = verdict(results)
    forgejo = next(ok for ok, title, _ in results if title == FORGEJO)
    unchanged = next(ok for ok, title, _ in results if title == "Pairing database unchanged afterwards")
    out.write("\nPAIRING: %s\n" % {
        "COMPATIBLE": "COMPATIBLE. The new code reads this computer's pairing correctly.",
        "NOT COMPATIBLE": "NOT COMPATIBLE. See the NO lines above.",
        "INCONCLUSIVE": "INCONCLUSIVE. Some required checks could not be proven (see the ? lines).",
    }[pairing])
    out.write("FORGEJO: %s\n" % ("verified running." if forgejo else "not verified running (see its line above)."))
    out.write("FILES: %s\n" % ("this check wrote nothing, and the pairing database is confirmed unchanged."
                                if unchanged else
                                "this check only reads, but the pairing database could not be confirmed unchanged."))
    return {"COMPATIBLE": 0, "INCONCLUSIVE": 3, "NOT COMPATIBLE": 1}[pairing]


if __name__ == "__main__":
    raise SystemExit(main())
