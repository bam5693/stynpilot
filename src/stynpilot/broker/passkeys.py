"""The owner's enrolled passkeys, kept by the ROOT installer (private state folder, survives restarts and upgrades).

What is stored: the public key of each passkey (never a secret), its label, whether it is synced or device-bound,
a signature counter, and a tamper-evident audit chain (every record contains the hash of the one before it).
A passkey is a *second kind of owner proof*. It never replaces the single-use root challenge: an approval is accepted
only if the passkey signed the exact challenge the installer issued for that request, plan and decision.

Enrollment is THREE steps, and the last one is what keeps it independent of the owner-side service:
1. an ordinary YELLOW request ("passkey enroll") is approved with AUTH0 ONLY (a passkey can never add another passkey). The
   installer then opens a short, single-use enrollment WINDOW tied to that request;
2. the owner's phone creates the passkey inside that window. The installer verifies it and stores it as PENDING: a pending
   passkey can approve nothing, and it expires after 15 minutes;
3. a second YELLOW request ("passkey activate") names the EXACT credential (its short ID and the SHA-256 of its public key). It is
   approved with AUTH0 ONLY, and the owner's sign-in carries a nonce that commits to that public-key hash. Only then does the
   installer activate that one key. Swapping the key after the owner approved is impossible: the hash is inside the signed proof.

Honest limit: registration uses attestation "none", so the installer cannot tell which device made the key, and a compromised
owner-side service could still show the owner a different summary than the one the installer rendered. What it cannot do is
activate any key the owner's Auth0 sign-in did not commit to, or enroll through a stolen passkey.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager

from .. import webauthn

WINDOW_SECONDS = 180
PENDING_SECONDS = 900
PUBHASH = re.compile(r"[a-f0-9]{64}\Z")
MAX_ATTEMPTS = 5
MAX_ACTIVE = 8
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _-]{0,39}\Z")
KID = re.compile(r"[a-f0-9]{16}\Z")
RETIREMENT_MINIMUM = 2
GENESIS = "0" * 64


def _append_audit(db, ts, event, data):
    row = db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    prev = row["hash"] if row else GENESIS
    body = json.dumps(data, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(("%s|%r|%s|%s" % (prev, ts, event, body)).encode()).hexdigest()
    db.execute("INSERT INTO audit (ts, event, data, prev, hash) VALUES (?,?,?,?,?)", (ts, event, body, prev, digest))


def quarantine_after_restore(path, *, clock=time.time):
    """After a backup restore: every restored passkey is QUARANTINED (cannot approve anything) until the owner re-confirms it at
    the computer's console. A backup is older than the present, so it may contain a passkey revoked later; this way a restore can
    never silently bring back approval power. Returns how many were quarantined."""
    db = sqlite3.connect(str(path), isolation_level=None, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        db.execute("BEGIN IMMEDIATE")
        count = db.execute("UPDATE passkeys SET quarantined=1 WHERE revoked IS NULL AND activated IS NOT NULL").rowcount
        _append_audit(db, clock(), "restored_from_backup", {"quarantined": count})
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise
    finally:
        db.close()
    return count


def quarantine_bytes(data, *, clock=time.time):
    """Quarantine a passkey database IMAGE before it is ever written where the installer could open it. Returns (bytes, count)."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        scratch = os.path.join(tmp, "p.sqlite3")
        with open(scratch, "wb") as handle:
            handle.write(data)
        count = quarantine_after_restore(scratch, clock=clock)
        db = sqlite3.connect(scratch)
        try:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            db.execute("PRAGMA journal_mode=DELETE")
        finally:
            db.close()
        with open(scratch, "rb") as handle:
            return handle.read(), count


class PasskeyError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def kid_of(credential_id):
    """Short public name of a passkey, safe to show anywhere."""
    return hashlib.sha256(credential_id.encode("ascii")).hexdigest()[:16]


class PasskeyStore:
    @staticmethod
    def check_identity(rp_id, origin):
        if type(rp_id) is not str or not re.fullmatch(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?", rp_id) or "." not in rp_id:
            raise ValueError("rp_id must be a lowercase host name")
        if type(origin) is not str or not (origin == "https://" + rp_id or (
                origin.startswith("https://" + rp_id + ":") and origin.rsplit(":", 1)[1].isdigit())):
            raise ValueError("origin must be https on the relying-party host")

    def __init__(self, path, *, rp_id, origin, clock=time.time):
        self.check_identity(rp_id, origin)
        self.path, self.rp_id, self.origin, self.clock = str(path), rp_id, origin, clock
        self._lock = threading.Lock()
        existed = os.path.exists(self.path)
        if not existed:
            os.close(os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600))
        info = os.lstat(self.path)
        if os.path.islink(self.path) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PasskeyError("passkey_store_not_private")
        with self._tx() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS passkeys (
                credential_id TEXT PRIMARY KEY, kid TEXT UNIQUE NOT NULL, public_key TEXT NOT NULL, label TEXT NOT NULL,
                backup_eligible INTEGER NOT NULL, backup_state INTEGER NOT NULL, aaguid TEXT NOT NULL,
                sign_count INTEGER NOT NULL, created REAL NOT NULL, last_used REAL, revoked REAL, enrolled_by TEXT NOT NULL,
                pubhash TEXT NOT NULL, activated REAL, quarantined INTEGER NOT NULL DEFAULT 0)""")
            db.execute("""CREATE TABLE IF NOT EXISTS windows (
                request_id TEXT PRIMARY KEY, challenge TEXT NOT NULL, label TEXT NOT NULL, expires REAL NOT NULL,
                attempts INTEGER NOT NULL, closed REAL, enrolled_by TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, event TEXT NOT NULL, data TEXT NOT NULL,
                prev TEXT NOT NULL, hash TEXT NOT NULL)""")

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

    # -- audit chain -------------------------------------------------------------------------------------------
    def _audit(self, db, event, data):
        _append_audit(db, self.clock(), event, data)

    def audit(self, event, data):
        with self._tx() as db:
            self._audit(db, event, data)

    def audit_ok(self):
        """True only if every record still chains to the one before it."""
        with self._tx() as db:
            prev = GENESIS
            for row in db.execute("SELECT * FROM audit ORDER BY seq"):
                good = hashlib.sha256(("%s|%r|%s|%s" % (prev, row["ts"], row["event"], row["data"])).encode()).hexdigest()
                if row["prev"] != prev or row["hash"] != good:
                    return False
                prev = row["hash"]
        return True

    def audit_tail(self, limit=20):
        with self._tx() as db:
            rows = db.execute("SELECT seq, ts, event, data FROM audit ORDER BY seq DESC LIMIT ?", (int(limit),)).fetchall()
        return [{"seq": r["seq"], "ts": r["ts"], "event": r["event"], "data": json.loads(r["data"])} for r in rows]

    # -- reading -----------------------------------------------------------------------------------------------
    @staticmethod
    def _public(row):
        return {"kid": row["kid"], "credential_id": row["credential_id"], "label": row["label"],
                "synced": bool(row["backup_state"]), "sync_capable": bool(row["backup_eligible"]),
                "created": int(row["created"]), "last_used": None if row["last_used"] is None else int(row["last_used"]),
                "revoked": row["revoked"] is not None, "pending": row["activated"] is None, "pub": row["pubhash"],
                "quarantined": bool(row["quarantined"])}

    def active(self):
        with self._tx() as db:
            return [self._public(r) for r in db.execute(
                "SELECT * FROM passkeys WHERE revoked IS NULL AND activated IS NOT NULL AND quarantined=0 ORDER BY created")]

    def quarantined(self):
        with self._tx() as db:
            return [self._public(r) for r in db.execute(
                "SELECT * FROM passkeys WHERE revoked IS NULL AND quarantined=1 ORDER BY created")]

    def reconfirm(self, kid, authorized_by):
        """Console only: the owner looked at a restored passkey and wants it back."""
        with self._tx() as db:
            row = db.execute("SELECT * FROM passkeys WHERE kid=? AND revoked IS NULL AND quarantined=1", (kid,)).fetchone()
            if row is None:
                raise PasskeyError("passkey_unknown")
            db.execute("UPDATE passkeys SET quarantined=0 WHERE kid=?", (kid,))
            self._audit(db, "reconfirmed_after_restore", {"kid": kid, "authorized_by": authorized_by})

    def pending(self):
        with self._tx() as db:
            return [self._public(r) for r in db.execute(
                "SELECT * FROM passkeys WHERE revoked IS NULL AND activated IS NULL AND created > ? ORDER BY created",
                (self.clock() - PENDING_SECONDS,))]

    def everything(self):
        with self._tx() as db:
            return [self._public(r) for r in db.execute("SELECT * FROM passkeys ORDER BY created")]

    def lookup(self, credential_id):
        """The pinned key for an ACTIVE passkey, or None (unknown or revoked)."""
        if type(credential_id) is not str or len(credential_id) > 200:
            return None
        with self._tx() as db:
            row = db.execute("SELECT * FROM passkeys WHERE credential_id=? AND revoked IS NULL AND activated IS NOT NULL "
                "AND quarantined=0",
                (credential_id,)).fetchone()
        return None if row is None else dict(row)

    def retirement_ready(self):
        """The old release-signing key may be retired only with at least two active passkeys enrolled."""
        return len(self.active()) >= RETIREMENT_MINIMUM

    # -- using a passkey -----------------------------------------------------------------------------------------
    def check_counter(self, row, auth):
        new, old = auth["sign_count"], row["sign_count"]
        if new == 0 and old == 0:
            return                                          # synced passkeys commonly never count
        if new <= old:
            raise PasskeyError("passkey_counter_went_backwards")   # a copied authenticator would look like this

    def record_use(self, credential_id, auth, *, request_id, decision):
        with self._tx() as db:
            db.execute("UPDATE passkeys SET sign_count=MAX(sign_count, ?), last_used=? WHERE credential_id=?",
                       (auth["sign_count"], self.clock(), credential_id))
            self._audit(db, "proof_accepted", {"kid": kid_of(credential_id), "request_id": request_id, "decision": decision,
                                         "user_verified": bool(auth["user_verified"]), "synced": bool(auth["backup_state"])})

    # -- enrollment ----------------------------------------------------------------------------------------------
    def open_window(self, request_id, label, enrolled_by):
        if type(label) is not str or not LABEL.fullmatch(label):
            raise PasskeyError("passkey_label_invalid")
        with self._tx() as db:
            if db.execute("SELECT COUNT(*) FROM passkeys WHERE revoked IS NULL AND (activated IS NOT NULL OR created > ?)",
                          (self.clock() - PENDING_SECONDS,)).fetchone()[0] >= MAX_ACTIVE:
                raise PasskeyError("too_many_passkeys")
            if db.execute("SELECT 1 FROM windows WHERE request_id=?", (request_id,)).fetchone():
                raise PasskeyError("enrollment_already_opened")
            db.execute("INSERT INTO windows VALUES (?,?,?,?,0,NULL,?)",
                       (request_id, secrets.token_hex(32), label, self.clock() + WINDOW_SECONDS, enrolled_by))
            self._audit(db, "enrollment_opened", {"request_id": request_id, "label": label, "authorized_by": enrolled_by})

    def _window(self, db, request_id):
        row = db.execute("SELECT * FROM windows WHERE request_id=?", (request_id,)).fetchone() if type(request_id) is str else None
        if row is None:
            raise PasskeyError("enrollment_not_open")
        if row["closed"] is not None:
            raise PasskeyError("enrollment_already_used")
        if row["expires"] <= self.clock():
            raise PasskeyError("enrollment_window_expired")
        if row["attempts"] >= MAX_ATTEMPTS:
            raise PasskeyError("enrollment_too_many_attempts")
        return row

    def begin(self, request_id):
        with self._tx() as db:
            row = self._window(db, request_id)
            others = [r["credential_id"] for r in db.execute("SELECT credential_id FROM passkeys WHERE revoked IS NULL")]
        # A NEW account handle per enrollment: phones replace a saved passkey that has the same site and account handle, so a
        # fixed handle would let the second passkey overwrite the first. "exclude" also stops the same authenticator re-enrolling.
        user = hashlib.sha256(b"stynpilot-passkey-user|" + bytes.fromhex(row["challenge"])).digest()[:16]
        return {"challenge": row["challenge"], "label": row["label"], "rp_id": self.rp_id, "origin": self.origin,
                "user_id": webauthn.b64u_encode(user), "exclude": others, "expires_in": max(1, int(row["expires"] - self.clock()))}

    def complete(self, request_id, response):
        with self._tx() as db:
            row = self._window(db, request_id)
            db.execute("UPDATE windows SET attempts=attempts+1 WHERE request_id=?", (request_id,))
        try:
            result = webauthn.verify_registration(response, rp_id=self.rp_id, origin=self.origin,
                                                  challenge=bytes.fromhex(row["challenge"]))
        except webauthn.WebAuthnError as error:
            self.audit("enrollment_refused", {"request_id": request_id, "code": error.code})
            raise PasskeyError("registration_" + error.code) from None
        with self._tx() as db:
            current = self._window(db, request_id)                 # re-checked: closed/expired while we verified?
            if db.execute("SELECT 1 FROM passkeys WHERE credential_id=?", (result["credential_id"],)).fetchone():
                raise PasskeyError("passkey_already_enrolled")
            db.execute("INSERT INTO passkeys (credential_id, kid, public_key, label, backup_eligible, backup_state, aaguid, sign_count, "
                       "created, enrolled_by, pubhash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                       (result["credential_id"], kid_of(result["credential_id"]), result["public_key"], current["label"],
                        int(result["backup_eligible"]), int(result["backup_state"]), result["aaguid"], result["sign_count"],
                        self.clock(), current["enrolled_by"], hashlib.sha256(bytes.fromhex(result["public_key"])).hexdigest()))
            db.execute("UPDATE windows SET closed=? WHERE request_id=?", (self.clock(), request_id))
            self._audit(db, "registered_pending", {"kid": kid_of(result["credential_id"]), "label": current["label"],
                                                   "synced": bool(result["backup_state"]), "request_id": request_id})
        return {"kid": kid_of(result["credential_id"]), "label": row["label"], "synced": bool(result["backup_state"]),
                "sync_capable": bool(result["backup_eligible"]),
                "pub": hashlib.sha256(bytes.fromhex(result["public_key"])).hexdigest()}

    def activate(self, kid, label, pub, request_id, authorized_by):
        """Make ONE pending passkey active: it must be the exact key (ID, label and public-key hash) the owner's proof committed to."""
        if type(kid) is not str or not KID.fullmatch(kid) or type(pub) is not str or not PUBHASH.fullmatch(pub):
            raise PasskeyError("passkey_unknown")
        with self._tx() as db:
            row = db.execute("SELECT * FROM passkeys WHERE kid=? AND revoked IS NULL", (kid,)).fetchone()
            if row is None or row["activated"] is not None or row["pubhash"] != pub or row["label"] != label:
                raise PasskeyError("passkey_unknown")
            if row["created"] <= self.clock() - PENDING_SECONDS:
                raise PasskeyError("pending_passkey_expired")
            if db.execute("SELECT COUNT(*) FROM passkeys WHERE revoked IS NULL AND activated IS NOT NULL").fetchone()[0] >= MAX_ACTIVE:
                raise PasskeyError("too_many_passkeys")
            db.execute("UPDATE passkeys SET activated=? WHERE kid=?", (self.clock(), kid))
            self._audit(db, "enrolled", {"kid": kid, "label": label, "pub": pub, "request_id": request_id,
                                         "authorized_by": authorized_by, "synced": bool(row["backup_state"])})
            return db.execute("SELECT COUNT(*) FROM passkeys WHERE revoked IS NULL AND activated IS NOT NULL").fetchone()[0]

    def revoke(self, kid, request_id):
        if type(kid) is not str or not KID.fullmatch(kid):
            raise PasskeyError("passkey_unknown")
        with self._tx() as db:
            row = db.execute("SELECT credential_id FROM passkeys WHERE kid=? AND revoked IS NULL", (kid,)).fetchone()
            if row is None:
                raise PasskeyError("passkey_unknown")
            db.execute("UPDATE passkeys SET revoked=? WHERE kid=?", (self.clock(), kid))
            self._audit(db, "revoked", {"kid": kid, "request_id": request_id})
            left = db.execute("SELECT COUNT(*) FROM passkeys WHERE revoked IS NULL AND activated IS NOT NULL").fetchone()[0]
        return left
