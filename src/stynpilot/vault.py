"""Dev22: encrypted, verified, automatic backups (the "vault"), one per side.

Two sides, kept apart exactly like the existing backups (backup.py): the OWNER side is run by the owner service as the owner and holds
the owner's state (request queue, revocations, provisioned marker, project roots), the owner settings file and the pairing database;
the ROOT side is run by the installer as root and holds the installer's ledgers, rollback snapshots, attention records, passkey
database, settings in /etc/stynpilot, the trusted-release-key addendum and release-transaction records. Neither side can read the other's
vault. Never included: the release signing key and the GitHub token (the release/ folder), and any file that looks like it carries a
secret (it is left out and reported, never copied).

Format of one backup file (``<side>-<YYYYmmdd-HHMMSS>-<8 hex>.stynvault``, mode 0600):
    b"STYNVLT1" | 2-byte header length | header JSON | AES-256-GCM ciphertext (tag included)
The header (format, side, created, version, key_id, nonce, size) is authenticated as associated data, so any change to it or to the
ciphertext fails decryption. Nonces are 96 random bits, checked against every nonce this vault ever used. The plaintext is a bundle:
the existing backup.py archive of the side's state (validated by backup.read_backup exactly as before) plus the extra files, each with
its SHA-256.

The key (``backup-key``, 0600, 48 bytes: b"STYNKEY1" + 8-byte id + 32-byte key) is created once. If it is missing while backups or the
vault index say a key existed, nothing is created: the vault reports ``backup_key_missing`` (a new key would silently orphan them).

Every backup is verified right after it is written (decrypt, bundle hashes, backup.read_backup, SQLite integrity_check); retention
never deletes the newest VERIFIED backup, never deletes anything to make space, and never touches files it did not create (legacy
backups and upgrade rollback records live elsewhere and are left alone). Recovery drills restore the newest verified backup into a fresh
private folder inside the vault, check it, and delete it; they never write to live state and open no network connections.
Nothing here raises into the service that runs it: every failure is recorded in the index and shown by the status.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import struct
import tempfile
import threading
import time
from pathlib import Path

from . import backup, statelock

MAGIC = b"STYNVLT1"
KEY_MAGIC = b"STYNKEY1"
BUNDLE_MAGIC = b"STYNBND1"
FORMAT = 1
SUFFIX = ".stynvault"
NAME = re.compile(r"(owner|root)-\d{8}-\d{6}-[0-9a-f]{8}\.stynvault\Z")
DAY = 86400
DUE_AFTER = DAY                        # a new backup is due when the newest verified one is older than this
DRILL_EVERY = 7 * DAY
FULL_CHECK_EVERY = 30 * DAY             # every retained backup is re-verified monthly
MANUAL_BACKUP_EVERY = 600              # rate limits for requests from assistants
MANUAL_DRILL_EVERY = 3600
OVERDUE_AFTER = 2 * DAY
DEFAULT_RETENTION = {"daily": 7, "weekly": 4}
RETENTION_LIMITS = {"daily": (1, 30), "weekly": (0, 12)}      # changing it is YELLOW (owner approval); these bounds always hold
SETTINGS = "settings.json"
POLICY_LOG = "policy.log"          # append-only, fsynced: every approved policy ever applied here (durable approval evidence)


def valid_retention(daily, weekly):
    for name, value in (("daily", daily), ("weekly", weekly)):
        low, high = RETENTION_LIMITS[name]
        if type(value) is not int or isinstance(value, bool) or not low <= value <= high:
            return False
    return True
# Conservative limits, checked from file sizes BEFORE anything is read (the real state is a few MB).
MAX_GATHER = 256 * 1024 * 1024          # everything one backup may read
MAX_ONE_FILE = 128 * 1024 * 1024        # any single state or extra file
MAX_BACKUP = MAX_GATHER + (16 << 20)     # a stored backup file (bundle + overhead)
MAX_EXTRA = 16 * 1024 * 1024            # one settings/extra file
SPACE_MARGIN = 64 * 1024 * 1024
CHILD_MEMORY = 1280 * 1024 * 1024       # address-space limit of the separate process that does the heavy work
CHILD_TIMEOUT = 1800
NONCE_LOG = "nonces.log"
OWNER_RESTORE_INTENT = "root-restore-intent.json"
ROTATION = "rotation.json"             # durable key-rotation journal (resumable at every step)
ROTATION_REQUESTS = "rotation-requests.log"   # append-only, fsynced, unbounded: every approval id ever spent on a rotation
ROTATION_RESULTS = "rotation-results.log"     # append-only, fsynced: '<request id> completed|cancelled', written BEFORE the journal ends
ROTATION_MODES = ("normal", "fresh_key", "lost_key")
_TRANSIENT = ("another_backup_operation_is_running", "another_change_is_still_running",
              "an_install_or_rollback_is_running_try_again_when_it_finishes", "backup_process_timed_out")
AWAIT_GRACE = 600                      # owner side: how long a fresh authorization marker is left to the approval flow itself
_HEX16 = re.compile(r"[0-9a-f]{16}\Z")
_RID = re.compile(r"[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[0-9a-f]{24}\Z")
_CLOSED_TORN = re.compile(r"[0-9a-f]{0,63}!\Z")
_OUTCOME = re.compile(r"[0-9a-f]{64} (completed|cancelled)\Z")
_SECRET_BYTES = (b"BEGIN PRIVATE KEY", b"BEGIN OPENSSH PRIVATE KEY", b"BEGIN RSA PRIVATE KEY", b"BEGIN EC PRIVATE KEY",
                 b"ghp_", b"github_pat_", b"gho_", b"ghs_")
_SECRET_KEY = re.compile(r"(token|secret|password|passphrase|private|api[_-]?key|credential)", re.I)


class VaultError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


# -- small safe-file helpers ---------------------------------------------------------------------------------------------------
def _fsync_dir(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_atomic(folder, name, data, mode=0o600):
    """Write ``folder/name`` all-or-nothing: exclusive temp file, fsync, rename, fsync the folder. Never through a link."""
    tmp = ".tmp-%s-%s" % (name, secrets.token_hex(4))
    fd = os.open(str(folder / tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fchmod(fd, mode)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        os.unlink(str(folder / tmp))
        raise
    os.close(fd)
    os.replace(str(folder / tmp), str(folder / name))
    _fsync_dir(folder)


def _read_private(path, limit, *, uid=None):
    """A regular file we own, not readable by others, opened without following links, read with a size limit."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != (os.geteuid() if uid is None else uid) or info.st_mode & 0o077:
            raise VaultError("file_not_private_or_not_ours")
        chunks, total = [], 0
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            total += len(block)
            if total > limit:
                raise VaultError("file_too_large")
            chunks.append(block)
    finally:
        os.close(fd)
    return b"".join(chunks)


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _read_lines(path, pattern, limit):
    """Lines of an append-only log, all of which must match ``pattern``. Only a final, unterminated, hex-only piece is tolerated:
    a write that did not finish (it is fsynced before use, so it was never used). Anything else: the history is uncertain."""
    data = _read_private(path, limit).decode("ascii", "replace")
    *complete, tail = data.split("\n")
    complete = [line for line in complete if not _CLOSED_TORN.fullmatch(line)]   # an unfinished write, closed later: never used
    if any(not pattern.fullmatch(line) for line in complete):
        raise VaultError("nonce_log_uncertain" if pattern is _NONCE else "log_uncertain")
    if tail and not re.fullmatch(r"[0-9a-f]{1,63}", tail):
        raise VaultError("nonce_log_uncertain" if pattern is _NONCE else "log_uncertain")
    return complete


def _append_line(path, line):
    """Append one line durably and CHECK it all landed (a short or failed write raises). A torn earlier line is closed first."""
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise VaultError("file_not_private_or_not_ours")
        data = (line + "\n").encode()
        if info.st_size and os.pread(fd, 1, info.st_size - 1) != b"\n":
            data = b"!\n" + data                        # close an unfinished earlier line, marked as such
        _write_all(fd, data)
        os.fsync(fd)
        if os.fstat(fd).st_size != info.st_size + len(data):
            raise VaultError("log_write_incomplete")
    finally:
        os.close(fd)
    _fsync_dir(Path(path).parent)


def _fsync_file(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _file_sha(path):
    digest = hashlib.sha256()
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            digest.update(block)
    finally:
        os.close(fd)
    return digest.hexdigest()


def _private_folder(path):
    """Create (0700) or check a folder: a real folder, ours, nobody else may enter (directory-mode verification)."""
    path = Path(path)
    try:
        path.mkdir(mode=0o700)
        os.chmod(str(path), 0o700)
    except FileExistsError:
        pass
    info = os.lstat(str(path))
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise VaultError("vault_folder_not_private_or_not_ours")
    return path


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _secret_free(name, data, allowed_keys=None):
    """Why a file may NOT be backed up, or None. No private-key or GitHub-token markers anywhere. A settings file with a known schema
    must be a JSON object whose top-level keys are within that schema (so a legitimate field such as token_endpoint is fine, and an
    unexpected field is refused); a file without a schema must have no secret-named key at any depth."""
    if any(marker in data for marker in _SECRET_BYTES):
        return "looks_like_a_secret"
    if allowed_keys is not None:
        try:
            doc = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeError):
            return "unreadable_json"
        if type(doc) is not dict or set(doc) - set(allowed_keys):
            return "unexpected_fields"
        return None
    if name.endswith(".json"):
        try:
            doc = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeError):
            return "unreadable_json"
        stack = [doc]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                for key, value in item.items():
                    if _SECRET_KEY.search(str(key)):
                        return "looks_like_a_secret"
                    stack.append(value)
            elif isinstance(item, list):
                stack.extend(item)
    return None


def _state_sizes(state_dir, side):
    """(total bytes, largest file) of what backup.make_backup will read, from sizes alone (nothing is opened)."""
    state_dir = Path(state_dir)
    names = list(backup.OWNER_FILES) if side == "owner" else list(backup.ROOT_DBS) + list(backup.ROOT_OPTIONAL_DBS)
    total = largest = 0
    for name in names:
        try:
            size = os.lstat(str(state_dir / name)).st_size
        except FileNotFoundError:
            continue
        total, largest = total + size, max(largest, size)
    if side == "root":
        for tree in backup.ROOT_TREES:
            for path in (state_dir / tree).rglob("*") if (state_dir / tree).is_dir() else ():
                if path.is_file() and not path.is_symlink():
                    size = path.lstat().st_size
                    total, largest = total + size, max(largest, size)
    return total, largest


def _passkeys_all_quarantined(data):
    """True only if the database opens and EVERY activated, non-revoked passkey is quarantined (as quarantine_after_restore makes
    them). Any SQLite error is a failure (fail closed)."""
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "p.sqlite3"
        copy.write_bytes(data)
        try:
            db = sqlite3.connect("file:%s?mode=ro" % copy, uri=True)
            try:
                live = db.execute("SELECT COUNT(*) FROM passkeys WHERE revoked IS NULL AND activated IS NOT NULL "
                                  "AND quarantined != 1").fetchone()[0]
                return live == 0
            finally:
                db.close()
        except sqlite3.Error:
            return False


def _sqlite_ok(data):
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "c.sqlite3"
        copy.write_bytes(data)
        try:
            db = sqlite3.connect("file:%s?mode=ro" % copy, uri=True)
            try:
                return db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            finally:
                db.close()
        except sqlite3.Error:
            return False


def _snapshot_sqlite(path):
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "copy.sqlite3"
        source = sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=10)
        dest = sqlite3.connect(str(target))
        try:
            source.backup(dest)
        finally:
            dest.close()
            source.close()
        return target.read_bytes()


# -- bundle (the plaintext) ----------------------------------------------------------------------------------------------------
def pack_bundle(meta, blobs):
    """meta: dict; blobs: {name: bytes}. Length-prefixed, every blob hashed in the index."""
    index = dict(meta, entries=[{"name": n, "size": len(b), "sha256": _sha(b)} for n, b in sorted(blobs.items())])
    head = json.dumps(index, sort_keys=True, separators=(",", ":")).encode()
    return BUNDLE_MAGIC + struct.pack(">I", len(head)) + head + b"".join(blobs[n] for n in sorted(blobs))


def unpack_bundle(data):
    if not data.startswith(BUNDLE_MAGIC) or len(data) < 12:
        raise VaultError("bundle_damaged")
    (size,) = struct.unpack(">I", data[8:12])
    if size > 1 << 20 or 12 + size > len(data):
        raise VaultError("bundle_damaged")
    try:
        index = json.loads(data[12:12 + size].decode())
    except (ValueError, UnicodeError):
        raise VaultError("bundle_damaged") from None
    entries = index.get("entries") if isinstance(index, dict) else None
    if not isinstance(entries, list):
        raise VaultError("bundle_damaged")
    at, blobs = 12 + size, {}
    for entry in entries:
        if (not isinstance(entry, dict) or set(entry) != {"name", "size", "sha256"} or type(entry["size"]) is not int
                or entry["size"] < 0 or not isinstance(entry["name"], str) or entry["name"] in blobs):
            raise VaultError("bundle_damaged")
        blob = data[at:at + entry["size"]]
        if len(blob) != entry["size"] or _sha(blob) != entry["sha256"]:
            raise VaultError("bundle_failed_its_hash_check")
        blobs[entry["name"]] = blob
        at += entry["size"]
    if at != len(data):
        raise VaultError("bundle_damaged")
    return index, blobs


# -- the vault -----------------------------------------------------------------------------------------------------------------
class Vault:
    """One side's vault. The heavy work (reading, encrypting, decrypting, restoring) runs in a SEPARATE short-lived process with
    its own memory limit, so running out of memory or a crash there can never take the owner service or the installer down."""

    def __init__(self, *, side, state_dir, folder, extras=(), version="", clock=time.time, retention=None, aesgcm=None,
                 space=shutil.disk_usage, isolate=False, limits=None, retention_source=None, prune_allowed=True):
        if side not in ("owner", "root"):
            raise ValueError("side")
        self.side, self.state_dir, self.folder = side, Path(state_dir), Path(folder)
        self.extras, self.version, self.clock, self.space = extras, version, clock, space
        self.retention = dict(DEFAULT_RETENTION, **(retention or {}))
        self.limits = dict({"gather": MAX_GATHER, "file": MAX_ONE_FILE, "extra": MAX_EXTRA, "memory": CHILD_MEMORY}, **(limits or {}))
        self.isolate = isolate
        self.retention_source = retention_source              # owner side: the installer's approved setting is the authority
        self.prune_allowed = prune_allowed                     # False on the owner side in Dev23 stage 1 (see service.owner_vault)
        self.authorization_source = None                       # owner side: rid -> 'authorized' | 'refused' | 'unknown' (installer record)
        self.on_rotation_finished = None                       # settles the request record (owner store / installer run) at the end
        self.change_running = None                             # root side: rid -> True while another installer change runs/pends
        self.tick_hooks = []                                   # small reconciliation steps run at the end of every tick
        self._aesgcm = aesgcm
        self._mutex = threading.Lock()
        self._held = threading.local()
        self.key_file = self.folder / "backup-key"
        self.index_file = "index.json"

    def _extra_list(self):
        """[(name, path, kind, required, allowed_keys)]; older 3-item entries mean optional with no schema."""
        out = []
        for item in self.extras:
            item = tuple(item)
            name, path, kind = item[:3]
            required = bool(item[3]) if len(item) > 3 else False
            allowed = (sorted(item[4]) if item[4] is not None else None) if len(item) > 4 else None
            out.append((name, str(path), kind, required, allowed))
        return out

    # .. retention settings (changed only through an owner-approved request) .....................................................
    def effective_retention(self):
        """The approved setting in the vault, else the built-in default (self.retention). ``trusted`` is False -- and nothing is
        pruned -- unless the settings file EXACTLY matches the LATEST entry of the durable approval log (policy.log), or neither
        exists (first-time default). Damage, a loose file, out-of-range values, a crash between the two writes, an older setting
        than the latest approval or any uncertainty all hold pruning."""
        path = self.folder / SETTINGS
        latest, evidence = self._latest_policy()
        if not os.path.lexists(str(path)):
            return dict(self.retention, approved=None, at=None, trusted=not evidence)
        try:
            data = json.loads(_read_private(path, 4096).decode())
            if (type(data) is dict and data.get("schema") == 1 and valid_retention(data.get("daily"), data.get("weekly"))
                    and type(data.get("request_id")) is str
                    and latest == (data["request_id"], data["daily"], data["weekly"])):
                return {"daily": data["daily"], "weekly": data["weekly"], "approved": data["request_id"], "at": data.get("at"),
                        "trusted": True}
        except (OSError, VaultError, ValueError, UnicodeError):
            pass
        return dict(self.retention, approved=None, at=None, trusted=False)

    def _latest_policy(self):
        """(latest (request_id, daily, weekly) or None, whether any evidence exists). A damaged last line -> (None, True)."""
        log = self.folder / POLICY_LOG
        if not os.path.lexists(str(log)):
            return None, False
        try:
            lines = [l for l in _read_private(log, 1 << 20).decode("ascii").splitlines() if l.strip()]
        except (OSError, VaultError, UnicodeError):
            return None, True
        if not lines:
            return None, False
        parts = lines[-1].split()
        if (len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]) or not parts[1].isdigit() or not parts[2].isdigit()
                or not valid_retention(int(parts[1]), int(parts[2]))):
            return None, True
        return (parts[0], int(parts[1]), int(parts[2])), True

    def _policy_evidence(self):
        return self._latest_policy()[1]

    def set_retention(self, daily, weekly, request_id):
        """Store an approved retention setting atomically. Bounds are enforced here too, whatever the caller checked."""
        if not valid_retention(daily, weekly) or type(request_id) is not str or not re.fullmatch(r"[0-9a-f]{64}", request_id):
            raise VaultError("retention_invalid")
        def write():
            fd = os.open(str(self.folder / POLICY_LOG), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                if os.fstat(fd).st_uid != os.geteuid() or os.fstat(fd).st_mode & 0o077:
                    raise VaultError("file_not_private_or_not_ours")
                os.write(fd, ("%s %d %d\n" % (request_id, daily, weekly)).encode())
                os.fsync(fd)                               # the evidence is durable BEFORE the setting takes effect
            finally:
                os.close(fd)
            _write_atomic(self.folder, SETTINGS, json.dumps({"schema": 1, "daily": daily, "weekly": weekly, "request_id": request_id,
                                                              "at": int(self.clock())}, sort_keys=True).encode())
            return {"ok": True, "daily": daily, "weekly": weekly}
        if getattr(self._held, "locked", False):
            return write()                                     # already inside this vault's lock (pruning under a lease)
        with self._mutex:
            _private_folder(self.folder)
            lock = os.open(str(self.folder / ".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX)              # waits for a running backup; never changes the rule under it
                return write()
            finally:
                os.close(lock)

    # .. index ..................................................................................................................
    def _valid_index(self, index):
        if type(index) is not dict or index.get("schema") != 1 or index.get("side") != self.side or type(index.get("backups")) is not dict:
            return False
        for name, info in index["backups"].items():
            if (not NAME.fullmatch(name) or not name.startswith(self.side + "-") or type(info) is not dict
                    or type(info.get("created")) is not int or type(info.get("size")) is not int
                    or info.get("verified_at") is not None and type(info["verified_at"]) is not int):
                return False
        return True

    def _index(self):
        try:
            data = _read_private(self.folder / self.index_file, 8 << 20)
            index = json.loads(data.decode())
            if self._valid_index(index):
                index.setdefault("manual", {})
                return index
        except FileNotFoundError:
            return self._empty()
        except (VaultError, ValueError, UnicodeError, OSError):
            pass
        return dict(self._empty(), damaged=True)

    def _empty(self):
        return {"schema": 1, "side": self.side, "key_id": None, "backups": {}, "last_attempt": None, "last_success": None,
                "last_error": None, "last_drill": None, "manual": {}}

    def _save(self, index):
        if index.pop("damaged", None):                       # never silently discard a damaged index: keep it aside, then rebuild
            try:
                os.replace(str(self.folder / self.index_file),
                           str(self.folder / ("index.damaged-%d.json" % int(self.clock()))))
            except FileNotFoundError:
                pass
        _write_atomic(self.folder, self.index_file, json.dumps(index, sort_keys=True).encode())

    def _rebuild(self, index):
        """After index damage: re-learn every backup file present from its own (authenticated) contents. Nothing is deleted."""
        for path in self._files():
            if path.name in index["backups"]:
                continue
            try:
                header, _, _ = self._verify(path.name, index)
                _, meta, _ = self.open_backup(path.name, index)          # completeness comes from the authenticated bundle itself
                excluded, incomplete = meta.get("excluded"), meta.get("incomplete")
                if not isinstance(excluded, list) or not isinstance(incomplete, list):
                    raise VaultError("bundle_metadata_missing")
                index["backups"][path.name] = {"created": int(header["created"]), "size": path.lstat().st_size,
                                               "verified_at": int(self.clock()), "checked_at": int(self.clock()),
                                               "excluded": [str(x)[:120] for x in excluded][:50],
                                               "incomplete": [str(x)[:60] for x in incomplete][:50]}
            except Exception:
                index["backups"][path.name] = {"created": int(path.lstat().st_mtime), "size": path.lstat().st_size,
                                               "verified_at": None, "failed": True, "excluded": [], "incomplete": ["unknown"]}
        index["rebuilt_at"] = int(self.clock())
        self._skip_retention = True                            # no retention in the same run as a rebuild

    # .. nonces: an append-only log, fsynced before a nonce is used, independent of the index ..................................
    def _nonces(self, index=None):
        used = set()
        try:
            used |= set(_read_lines(self.folder / NONCE_LOG, _NONCE, 64 << 20))   # an uncertain history raises: no new nonces
        except FileNotFoundError:
            # The log holds nonces of backups that retention already deleted; the surviving files cannot stand in for it. With a key
            # already in use, a missing log stops new backups; the way out is an owner-approved fresh_key rotation.
            if self.key_file.exists() or self._files() or (index or {}).get("key_id") or (index or {}).get("backups"):
                raise VaultError("nonce_log_missing") from None
        for path in self._files():                           # and every backup still present
            header = self._header_of(path.name)
            if header is not None:
                used.add(header["nonce"])
        return used

    def _record_nonce(self, nonce):
        _append_line(self.folder / NONCE_LOG, nonce)

    # .. key ....................................................................................................................
    def _files(self):
        return sorted(p for p in self.folder.iterdir() if NAME.fullmatch(p.name) and p.name.startswith(self.side + "-")
                      and p.is_file() and not p.is_symlink())

    def _need_missing_key(self):
        """Backups here whose key generation is NOT kept in keys/ (or whose header cannot be read): they need the missing key."""
        out = []
        for path in self._files():
            header = self._header_of(path.name)
            if header is None or not os.path.lexists(str(self.folder / "keys" / (header["key_id"] + ".key"))):
                out.append(path.name)
        return out

    def _key(self, index, *, create):
        try:
            raw = _read_private(self.key_file, 64)
        except FileNotFoundError:
            log = self.folder / NONCE_LOG
            used_log = log.exists() and (log.is_symlink() or log.stat().st_size > 0)
            if index.get("key_id") or self._need_missing_key() or index.get("damaged") or used_log:
                raise VaultError("backup_key_missing")          # never silently replace a key that existing backups need
            if log.exists():
                os.unlink(str(log))                             # an EMPTY log left by an interrupted first start: nothing depended on it
            if not create:
                raise VaultError("backup_key_missing")
            raw = KEY_MAGIC + secrets.token_bytes(8) + secrets.token_bytes(32)
            # the nonce log is born with the key, so from now on a missing log always means a LOST log
            log = os.open(str(self.folder / NONCE_LOG), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            os.fsync(log)
            os.close(log)
            fd = os.open(str(self.key_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                os.write(fd, raw)
                os.fsync(fd)
            finally:
                os.close(fd)
            _fsync_dir(self.folder)
        if len(raw) != 48 or not raw.startswith(KEY_MAGIC):
            raise VaultError("backup_key_damaged")
        key_id = raw[8:16].hex()
        if index.get("key_id") not in (None, key_id):
            raise VaultError("backup_key_does_not_match_the_vault")
        return key_id, raw[16:]

    # .. key generations (dev23 stage 2) ...........................................................................................
    # Generations: the active key is backup-key + nonces.log; every earlier generation is KEPT in keys/<id>.key (+ <id>.nonces when
    # its history exists). Kept generations are NEVER destroyed automatically in this stage (controlled retirement is a tracked
    # follow-up after Dev24 external recovery); they only ever decrypt, never encrypt.
    @property
    def keys_dir(self):
        return _private_folder(self.folder / "keys")

    def _read_key_file(self, path):
        raw = _read_private(path, 64)
        if len(raw) != 48 or not raw.startswith(KEY_MAGIC):
            raise VaultError("backup_key_damaged")
        return raw[8:16].hex(), raw[16:]

    def _key_for(self, index, key_id):
        """The key of generation ``key_id``: the active one, or one kept in keys/."""
        if not _HEX16.fullmatch(str(key_id)):
            raise VaultError("backup_damaged")
        try:
            active_id, active = self._read_key_file(self.key_file)
            if index.get("key_id") not in (None, active_id) and not self._rotation_active():
                raise VaultError("backup_key_does_not_match_the_vault")   # a swapped-in key is never trusted
            if active_id == key_id:
                return active
        except FileNotFoundError:
            pass
        try:
            kept_id, kept = self._read_key_file(self.folder / "keys" / (key_id + ".key"))
        except FileNotFoundError:
            raise VaultError("backup_made_with_another_key") from None
        if kept_id != key_id:
            raise VaultError("backup_key_damaged")
        return kept

    def generations(self):
        """Kept generations: ids and whether their nonce history exists. Never key material."""
        out = []
        folder = self.folder / "keys"
        if folder.is_dir():
            for path in sorted(folder.glob("*.key")):
                kid = path.name[:-4]
                if _HEX16.fullmatch(kid):
                    out.append({"key_id": kid, "nonce_history": (folder / (kid + ".nonces")).exists()})
        return out

    # .. the rotation journal (rotation.json): validated completely before anything acts on it ................................
    _JOURNAL_KEYS = {
        "awaiting_authorization": {"schema", "mode", "request_id", "state", "created", "expires_at"},
        "normal": {"schema", "mode", "request_id", "state", "started", "old_key_id", "new_key_id", "done", "kept_old"},
        "fresh_key": {"schema", "mode", "request_id", "state", "started", "old_key_id", "new_key_id"},
        "lost_key": {"schema", "mode", "request_id", "state", "started", "old_key_id", "moved"},
    }
    _JOURNAL_STATES = {"normal": ("reencrypt", "switch", "cleanup"), "fresh_key": ("switch", "cleanup"),
                       "lost_key": ("move_unreadable", "new_key")}

    def _valid_journal(self, j):
        if type(j) is not dict or j.get("schema") != 1 or j.get("mode") not in ROTATION_MODES:
            return False
        if not _RID.fullmatch(str(j.get("request_id"))):
            return False
        if j.get("state") == "awaiting_authorization":
            return (set(j) == self._JOURNAL_KEYS["awaiting_authorization"] and type(j["created"]) is int
                    and type(j["expires_at"]) is int)
        if set(j) != self._JOURNAL_KEYS[j["mode"]] or j["state"] not in self._JOURNAL_STATES[j["mode"]] or type(j["started"]) is not int:
            return False
        if j["mode"] == "lost_key":
            return ((j["old_key_id"] is None or bool(_HEX16.fullmatch(str(j["old_key_id"])))) and type(j["moved"]) is list
                    and all(type(n) is str and NAME.fullmatch(n) for n in j["moved"]))
        if not _HEX16.fullmatch(str(j["old_key_id"])) or not _HEX16.fullmatch(str(j["new_key_id"])) or j["old_key_id"] == j["new_key_id"]:
            return False
        if j["mode"] == "normal":
            return all(type(x) is list and all(type(n) is str and NAME.fullmatch(n) for n in x) for x in (j["done"], j["kept_old"]))
        return True

    def _journal(self):
        try:
            data = json.loads(_read_private(self.folder / ROTATION, 1 << 20).decode())
        except FileNotFoundError:
            return None
        except (OSError, VaultError, ValueError, UnicodeError):
            raise VaultError("key_rotation_journal_damaged") from None
        if not self._valid_journal(data):
            raise VaultError("key_rotation_journal_damaged")
        return data

    def _rotation_active(self):
        """A rotation that has started changing things (not merely awaiting the installer's authorization). Damaged = active."""
        if not os.path.lexists(str(self.folder / ROTATION)):
            return False
        try:
            return self._journal()["state"] != "awaiting_authorization"
        except VaultError:
            return True

    def rotation_progress(self):
        """Durable progress, read from the journal itself (never assumed)."""
        try:
            j = self._journal()
        except VaultError:
            return {"state": "journal_damaged"}
        if j is None:
            return None
        out = {"mode": j["mode"], "state": j["state"]}
        if j["state"] == "awaiting_authorization":
            return out
        if j["mode"] == "normal":
            out.update(reencrypted=len(j["done"]), left_with_old_key=len(j["kept_old"]))
        if j["mode"] == "lost_key":
            out.update(moved_unreadable=len(j["moved"]))
        return out

    def _save_journal(self, journal):
        if not self._valid_journal(journal):
            raise VaultError("key_rotation_journal_invalid")
        _write_atomic(self.folder, ROTATION, json.dumps(journal, sort_keys=True).encode())

    def _end_journal(self):
        os.unlink(str(self.folder / ROTATION))
        _fsync_dir(self.folder)

    # .. spent approvals: an append-only, fsynced, UNBOUNDED log (never a bounded list) .......................................
    def _spent(self):
        try:
            return set(_read_lines(self.folder / ROTATION_REQUESTS, _RID, 16 << 20))
        except FileNotFoundError:
            return set()

    def _spend(self, request_id):
        if request_id not in self._spent():
            _append_line(self.folder / ROTATION_REQUESTS, request_id)

    def _record_outcome(self, request_id, outcome):
        """Durable final outcome, written BEFORE the journal is removed, so completion can always be reconciled after a crash."""
        if self.rotation_outcome(request_id) is None:
            _append_line(self.folder / ROTATION_RESULTS, "%s %s" % (request_id, outcome))

    def rotation_outcome(self, request_id):
        """'completed' | 'cancelled' | None (never finished here). Read-only; safe from any thread."""
        try:
            lines = _read_lines(self.folder / ROTATION_RESULTS, _OUTCOME, 16 << 20)
        except (FileNotFoundError, VaultError):
            return None
        for line in lines:
            rid, outcome = line.split(" ")
            if rid == request_id:
                return outcome
        return None

    def journal_request(self):
        """(request id, state) of the journal present, or None. A damaged journal reports ('damaged', 'damaged')."""
        try:
            journal = self._journal()
        except VaultError:
            return ("damaged", "damaged")
        return None if journal is None else (journal["request_id"], journal["state"])

    def _new_key_files(self, folder):
        """A fresh key + its EMPTY nonce log in ``folder`` (both exclusive, fsynced). Returns the key id."""
        raw = KEY_MAGIC + secrets.token_bytes(8) + secrets.token_bytes(32)
        key_id = raw[8:16].hex()
        for name, data in ((key_id + ".nonces", b""), (key_id + ".key", raw)):
            fd = os.open(str(folder / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                _write_all(fd, data)
                os.fsync(fd)
            finally:
                os.close(fd)
        _fsync_dir(folder)
        return key_id

    # .. owner side: durable hand-off from the installer's authorization to the owner's own rotation ............................
    def reserve_root_restore(self, rid, expires):
        """On the owner side only. Serialize the root handoff with owner key-rotation preparation."""
        def reserve():
            if self.side != "owner" or not _RID.fullmatch(rid):
                raise VaultError("invalid_restore_reservation")
            if self._journal() is not None:
                raise VaultError("owner_key_rotation_in_progress")
            path = self.folder / OWNER_RESTORE_INTENT
            intent = {"rid": rid, "expires": expires}
            if os.path.lexists(path):
                if json.loads(_read_private(path, 1024)) != intent:
                    raise VaultError("root_restore_in_progress")
            else:
                _write_atomic(self.folder, OWNER_RESTORE_INTENT, json.dumps(intent).encode())
        self._locked(reserve)

    def reconcile_restore_intent(self, status):
        path = self.folder / OWNER_RESTORE_INTENT
        if self.side != "owner" or not os.path.lexists(path):
            return
        intent = _read_private(path, 1024)
        data = json.loads(intent)
        record = status(data["rid"])   # do not hold the owner vault lock during a socket call
        finished = (record.get("state") in ("done", "failed") and
                    (record.get("result") or {}).get("action") == "restore_root")
        if finished or (record.get("state") == "not_started" and self.clock() >= data["expires"]):
            def clear():
                if os.path.lexists(path) and _read_private(path, 1024) == intent:
                    path.unlink()
                    _fsync_dir(self.folder)
            self._locked(clear)

    def _op_prepare(self, mode, request_id, expires_at):
        """Before the installer is asked: a durable marker bound to the exact request, so a crash between the installer's
        authorization and the owner's rotation is found and finished (or dropped) later. Changes nothing else."""
        if self.side == "owner" and os.path.lexists(self.folder / OWNER_RESTORE_INTENT):
            raise VaultError("root_restore_in_progress")
        if mode not in ROTATION_MODES or not _RID.fullmatch(str(request_id)) or type(expires_at) is not int:
            raise VaultError("key_rotation_request_invalid")
        if request_id in self._spent():
            raise VaultError("key_rotation_request_already_used")
        journal = self._journal()
        if journal is not None:
            if journal["request_id"] == request_id:
                return {"ok": True, "state": journal["state"]}
            raise VaultError("another_key_rotation_is_in_progress")
        self._save_journal({"schema": 1, "mode": mode, "request_id": request_id, "state": "awaiting_authorization",
                            "created": int(self.clock()), "expires_at": expires_at})
        return {"ok": True, "state": "awaiting_authorization"}

    def _op_cancel(self, request_id):
        """The installer did NOT authorize it: drop the marker (nothing had changed) and spend the id."""
        journal = self._journal()
        if journal is None or journal["request_id"] != request_id or journal["state"] != "awaiting_authorization":
            raise VaultError("nothing_to_cancel")
        self._spend(request_id)
        self._record_outcome(request_id, "cancelled")
        self._end_journal()
        return {"ok": True, "cancelled": True}

    # .. rotation ...............................................................................................................
    def _op_rotate(self, mode, request_id):
        """Owner-approved key rotation, resumable at every step.
        normal: a new generation; every backup is re-encrypted and VERIFIED before it replaces the original.
        fresh_key: a new generation for NEW backups only (the way out of a lost nonce log): existing backups stay under their key,
                   which is kept and never encrypts again.
        lost_key: the active key is gone: backups that need it are preserved in unreadable/ (never deleted), and a fresh key starts.
        No generation is ever destroyed."""
        index = self._index()
        if index.get("damaged"):
            raise VaultError("vault_index_damaged_run_a_backup_first")
        journal = self._journal()
        if journal is None or journal["state"] == "awaiting_authorization":
            if request_id is None:
                return {"ok": True, "nothing_to_resume": True}
            if mode not in ROTATION_MODES or not _RID.fullmatch(str(request_id)):
                raise VaultError("key_rotation_request_invalid")
            if journal is not None and (journal["request_id"] != request_id or journal["mode"] != mode):
                raise VaultError("another_key_rotation_is_in_progress")
            if request_id in self._spent():
                raise VaultError("key_rotation_request_already_used")
            journal = self._begin(mode, request_id, index)
            self._save_journal(journal)                     # from here on it resumes after any interruption
            self._spend(request_id)                         # and this approval can never start another one
        elif request_id is not None and journal["request_id"] != request_id:
            raise VaultError("another_key_rotation_is_in_progress")
        return self._advance(journal)

    def _advance(self, journal):
        return {"normal": self._rotate_normal, "fresh_key": self._rotate_fresh, "lost_key": self._rotate_lost}[journal["mode"]](journal)

    def _begin(self, mode, request_id, index):
        now = int(self.clock())
        if mode == "lost_key":
            if os.path.lexists(str(self.key_file)):
                raise VaultError("key_is_present_use_normal_mode")
            return {"schema": 1, "mode": mode, "request_id": request_id, "state": "move_unreadable",
                    "old_key_id": index.get("key_id"), "moved": [], "started": now}
        try:
            old_id, _ = self._read_key_file(self.key_file)
        except FileNotFoundError:
            raise VaultError("backup_key_missing_use_lost_key_mode") from None
        if index.get("key_id") not in (None, old_id):
            raise VaultError("backup_key_does_not_match_the_vault")
        log_present = os.path.lexists(str(self.folder / NONCE_LOG))
        if mode == "normal" and not log_present:
            raise VaultError("nonce_log_missing_use_fresh_key_mode")
        if mode == "fresh_key" and log_present:
            try:
                self._nonces(index)
            except VaultError as error:
                if error.code != "nonce_log_uncertain":     # an UNCERTAIN history qualifies too
                    raise
            else:
                raise VaultError("nonce_log_is_fine_use_normal_mode")
        if mode == "normal" and log_present:
            self._nonces(index)                              # an uncertain history must not be carried on: use fresh_key
        new_id = self._new_key_files(self.keys_dir)
        if mode == "fresh_key":
            return {"schema": 1, "mode": mode, "request_id": request_id, "state": "switch", "old_key_id": old_id,
                    "new_key_id": new_id, "started": now}
        return {"schema": 1, "mode": mode, "request_id": request_id, "state": "reencrypt", "old_key_id": old_id,
                "new_key_id": new_id, "done": [], "kept_old": [], "started": now}

    def _reencrypt_one(self, path, index, journal, new_key, used, log):
        header, bundle = self._decrypt(path.name, index)
        digest = _sha(bundle)
        free = self.space(str(self.folder)).free
        if free < path.lstat().st_size + SPACE_MARGIN:
            raise VaultError("insufficient_storage")            # nothing is deleted to make room
        nonce = self._new_nonce(used)
        used.add(nonce)
        _append_line(log, nonce)                               # recorded (fully, fsynced, checked) BEFORE it is used
        head = json.dumps(dict(header, key_id=journal["new_key_id"], nonce=nonce), sort_keys=True, separators=(",", ":")).encode()
        aad = MAGIC + struct.pack(">H", len(head)) + head
        blob = aad + self._cipher(new_key).encrypt(bytes.fromhex(nonce), bundle, aad)
        del bundle
        temp = ".rotate-" + path.name
        _write_atomic(self.folder, temp, blob)
        del blob
        try:
            check, check_aad, body = self._parse(_read_private(self.folder / temp, MAX_BACKUP))
            again = self._cipher(new_key).decrypt(bytes.fromhex(check["nonce"]), body, check_aad)
            ok = (check["key_id"] == journal["new_key_id"] and _sha(again) == digest
                  and {k: v for k, v in check.items() if k not in ("key_id", "nonce")}
                  == {k: v for k, v in header.items() if k not in ("key_id", "nonce")})
        except Exception:
            ok = False
        if not ok:
            os.unlink(str(self.folder / temp))
            raise VaultError("reencrypted_backup_failed_verification")   # the original stays, untouched
        os.replace(str(self.folder / temp), str(path))              # only a VERIFIED copy replaces the original
        _fsync_dir(self.folder)
        if path.name in index["backups"]:
            index["backups"][path.name]["size"] = path.lstat().st_size
            self._save(index)

    def _switch(self, journal):
        """Make the new generation active. Order matters for an OLDER StyNpilot reading this vault after a rollback: the index
        names the new key FIRST, so until the new key is in place an older reader sees a key/index mismatch and refuses to make
        backups (fail closed) instead of pairing the old key with the new nonce log."""
        keys, old_id, new_id = self.keys_dir, journal["old_key_id"], journal["new_key_id"]
        if not (keys / (old_id + ".key")).exists():
            current = self._read_key_file(self.key_file)
            if current[0] != old_id:
                raise VaultError("key_rotation_journal_damaged")
            _write_atomic(keys, old_id + ".key", _read_private(self.key_file, 64))   # keep the old generation FIRST
        if (self.folder / NONCE_LOG).exists() and not (keys / (old_id + ".nonces")).exists() \
                and self._read_key_file(self.key_file)[0] == old_id:
            _write_atomic(keys, old_id + ".nonces", _read_private(self.folder / NONCE_LOG, 64 << 20))
        index = self._index()
        if index.get("key_id") != new_id:
            index["key_id"] = new_id
            self._save(index)
        if self._read_key_file(self.key_file)[0] != new_id:
            _write_atomic(self.folder, NONCE_LOG, _read_private(keys / (new_id + ".nonces"), 64 << 20))
            _write_atomic(self.folder, self.key_file.name, _read_private(keys / (new_id + ".key"), 64))
        journal["state"] = "cleanup"
        self._save_journal(journal)

    def _finish_generation(self, journal, summary):
        """Remove only the two staging COPIES of the now-active key (checked byte-identical first); no generation is destroyed."""
        keys, new_id = self.keys_dir, journal["new_key_id"]
        if self._read_key_file(self.key_file)[0] != new_id:
            raise VaultError("key_rotation_journal_damaged")
        staged = keys / (new_id + ".key")
        if staged.exists():
            if _read_private(staged, 64) != _read_private(self.key_file, 64):
                raise VaultError("key_rotation_journal_damaged")
            os.unlink(str(staged))
        staged_log = keys / (new_id + ".nonces")
        if staged_log.exists():
            active = _read_lines(self.folder / NONCE_LOG, _NONCE, 64 << 20)
            if not set(_read_lines(staged_log, _NONCE, 64 << 20)) <= set(active):
                raise VaultError("key_rotation_journal_damaged")
            os.unlink(str(staged_log))
        for leftover in self.folder.glob(".rotate-*"):
            os.unlink(str(leftover))
        _fsync_dir(keys)
        _fsync_dir(self.folder)
        self._spend(journal["request_id"])
        index = self._index()
        index["last_rotation"] = dict(summary, at=int(self.clock()), mode=journal["mode"], request_id=journal["request_id"])
        self._save(index)
        self._record_outcome(journal["request_id"], "completed")
        self._end_journal()
        return dict(summary, ok=True, mode=journal["mode"], request_id=journal["request_id"], generations_kept=len(self.generations()))

    def _rotate_normal(self, journal):
        index = self._index()
        old_id, new_id = journal["old_key_id"], journal["new_key_id"]
        if journal["state"] == "reencrypt":
            new_key = self._key_for(index, new_id)
            log = self.keys_dir / (new_id + ".nonces")
            used = set(_read_lines(log, _NONCE, 64 << 20))
            for path in self._files():
                header = self._header_of(path.name)
                if header is None or header["key_id"] != old_id:
                    continue                                    # done, another generation, or unreadable header (left as is)
                try:
                    self._reencrypt_one(path, index, journal, new_key, used, log)
                except VaultError as error:
                    if error.code in ("insufficient_storage", "reencrypted_backup_failed_verification"):
                        raise                                   # stop here; resumes later; nothing lost
                    if path.name not in journal["kept_old"]:
                        journal["kept_old"].append(path.name)   # cannot be opened now: left as is, its key is kept
                        self._save_journal(journal)
                    continue
                if path.name not in journal["done"]:
                    journal["done"].append(path.name)
                self._save_journal(journal)
            journal["state"] = "switch"
            self._save_journal(journal)
        if journal["state"] == "switch":
            self._switch(journal)
        if journal["state"] == "cleanup":
            return self._finish_generation(journal, {"reencrypted": len(journal["done"]), "left_with_old_key": len(journal["kept_old"])})
        raise VaultError("key_rotation_journal_damaged")

    def _rotate_fresh(self, journal):
        if journal["state"] == "switch":
            self._switch(journal)
        if journal["state"] == "cleanup":
            index = self._index()
            index["last_error"] = None if str((index.get("last_error") or {}).get("code", "")).startswith("nonce_log") else index.get("last_error")
            self._save(index)
            return self._finish_generation(journal, {"reencrypted": 0})
        raise VaultError("key_rotation_journal_damaged")

    def _preserve(self, source, folder, name):
        """Move ``source`` into ``folder`` WITHOUT ever overwriting: hard link (fails if the name exists), destination folder
        durable, byte-for-byte check, then remove the source and make that durable. An identical copy already there (an interrupted
        earlier move) counts as preserved; a different file there gets a new name. Returns the preserved name."""
        want = _file_sha(source)
        for n in range(1000):
            target = folder / (name if n == 0 else "%s.%d" % (name, n))
            if os.path.lexists(str(target)):
                if not target.is_symlink() and target.is_file() and _file_sha(target) == want:
                    _fsync_file(target)
                    _fsync_dir(folder)                          # an interrupted earlier move: make sure THAT entry is durable
                    break
                continue                                        # never overwrite a different preserved file
            os.link(str(source), str(target))
            _fsync_dir(folder)
            break
        else:
            raise VaultError("unreadable_folder_full")
        if _file_sha(target) != want:
            raise VaultError("preserved_copy_differs")
        os.unlink(str(source))
        _fsync_dir(source.parent)
        return target.name

    def _rotate_lost(self, journal):
        if journal["state"] == "move_unreadable":
            index = self._index()
            unreadable = _private_folder(self.folder / "unreadable")
            for path in self._files():
                header = self._header_of(path.name)
                if header is not None:
                    try:
                        self._key_for(index, header["key_id"])
                        continue                                # its generation is still here: it stays readable in place
                    except VaultError:
                        pass
                self._preserve(path, unreadable, path.name)
                if path.name not in journal["moved"]:
                    journal["moved"].append(path.name)
                    self._save_journal(journal)
            if (self.folder / NONCE_LOG).exists():
                self._preserve(self.folder / NONCE_LOG, unreadable, "nonces-%s.log" % (journal["old_key_id"] or "unknown"))
            # reconcile with the index: anything it lists that is no longer here but is in unreadable/ was moved (also by an
            # interrupted earlier run whose journal entry was lost)
            index = self._index()
            for name in list(index["backups"]):
                if not (self.folder / name).exists() and (unreadable / name).exists():
                    info = index["backups"].pop(name)
                    index.setdefault("unreadable", {})[name] = {"created": info.get("created"), "key_id": journal["old_key_id"]}
            for name in journal["moved"]:
                if name in index["backups"] and not (self.folder / name).exists():
                    index["backups"].pop(name)
                index.setdefault("unreadable", {}).setdefault(name, {"created": None, "key_id": journal["old_key_id"]})
            index["key_id"] = None
            self._save(index)
            journal["state"] = "new_key"
            self._save_journal(journal)
        if journal["state"] == "new_key":
            index = self._index()
            if not os.path.lexists(str(self.key_file)):
                index["key_id"] = None
                self._key(index, create=True)
            index = self._index()
            index["key_id"] = self._read_key_file(self.key_file)[0]
            index["last_error"] = None
            self._spend(journal["request_id"])
            index["last_rotation"] = {"at": int(self.clock()), "request_id": journal["request_id"], "mode": "lost_key",
                                      "moved_unreadable": len(journal["moved"])}
            self._save(index)
            self._record_outcome(journal["request_id"], "completed")
            self._end_journal()
            return {"ok": True, "mode": "lost_key", "request_id": journal["request_id"], "moved_unreadable": len(journal["moved"])}
        raise VaultError("key_rotation_journal_damaged")

    def _cipher(self, key):
        if self._aesgcm:
            return self._aesgcm(key)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key)

    # .. gather .................................................................................................................
    def _gather(self):
        """(bundle bytes, excluded, incomplete). Sizes are checked BEFORE anything is read."""
        total, largest = _state_sizes(self.state_dir, self.side)
        extras = self._extra_list()
        sizes = {}
        for name, path, kind, required, allowed in extras:
            try:
                info = os.lstat(path)
                sizes[name] = info.st_size if stat.S_ISREG(info.st_mode) else 0
            except FileNotFoundError:
                sizes[name] = 0
        total += sum(sizes.values())
        if total > self.limits["gather"] or largest > self.limits["file"]:
            raise VaultError("backup_too_large_for_the_limits")
        if self.space(str(self.folder)).free < 3 * total + SPACE_MARGIN:   # room for the temporary copies AND the backup, checked first
            raise VaultError("insufficient_storage")
        with tempfile.TemporaryDirectory(dir=str(self.work)) as tmp:
            archive = Path(tmp) / "state.tar"
            backup.make_backup(self.state_dir, archive, kind=self.side, clock=self.clock)
            blobs = {"state.tar": archive.read_bytes()}
        excluded, incomplete = [], []
        for name, path, kind, required, allowed in extras:
            path = Path(path)
            why = None
            try:
                if path.is_symlink():
                    why = "link"
                elif not path.is_file():
                    why = "missing"
                elif sizes[name] > self.limits["extra"]:
                    why = "too_large"
                else:
                    data = _snapshot_sqlite(path) if kind == "sqlite" else path.read_bytes()
                    if kind == "sqlite":
                        why = None if _sqlite_ok(data) else "database_damaged"
                    else:
                        why = _secret_free(name, data, allowed)
            except (OSError, sqlite3.Error):
                why = "unreadable"
            if why is None:
                blobs["extra/" + name] = data
            elif why != "missing" or required:
                excluded.append("%s:%s" % (name, why))
            if why is not None and required:
                incomplete.append(name)
        meta = {"format": FORMAT, "side": self.side, "created": int(self.clock()), "version": self.version, "excluded": excluded,
                "incomplete": incomplete, "extras": {n: {"kind": k} for n, _, k, _, _ in extras if "extra/" + n in blobs}}
        return pack_bundle(meta, blobs), excluded, incomplete

    @property
    def work(self):
        return _private_folder(self.folder / ".work")

    # .. create / verify ........................................................................................................
    def _new_nonce(self, used):
        for _ in range(8):
            nonce = secrets.token_bytes(12).hex()
            if nonce not in used:
                return nonce
        raise VaultError("nonce_generation_failed")

    def _create(self, index):
        used = self._nonces(index)                              # BEFORE a key exists: a missing log is only fine for the very first backup
        key_id, key = self._key(index, create=True)
        index["key_id"] = key_id
        bundle, excluded, incomplete = self._gather()
        free = self.space(str(self.folder)).free
        if free < 2 * len(bundle) + SPACE_MARGIN:
            raise VaultError("insufficient_storage")            # nothing is deleted to make room
        nonce = self._new_nonce(used)
        now = int(self.clock())
        header = json.dumps({"format": FORMAT, "side": self.side, "created": now, "version": self.version, "key_id": key_id,
                             "nonce": nonce, "size": len(bundle)}, sort_keys=True, separators=(",", ":")).encode()
        aad = MAGIC + struct.pack(">H", len(header)) + header
        blob = aad + self._cipher(key).encrypt(bytes.fromhex(nonce), bundle, aad)
        del bundle
        name = "%s-%s-%s%s" % (self.side, time.strftime("%Y%m%d-%H%M%S", time.gmtime(now)), secrets.token_hex(4), SUFFIX)
        self._record_nonce(nonce)                               # recorded BEFORE the backup can exist
        self._save(index)
        _write_atomic(self.folder, name, blob)
        index["backups"][name] = {"created": now, "size": len(blob), "verified_at": None, "excluded": excluded,
                                  "incomplete": incomplete}
        return name

    def _decrypt(self, name, index):
        """(header, bundle bytes) of one backup with whichever key generation made it (active or kept in keys/)."""
        if not NAME.fullmatch(name) or not name.startswith(self.side + "-"):
            raise VaultError("not_a_vault_backup")
        blob = _read_private(self.folder / name, MAX_BACKUP)
        header, aad, body = self._parse(blob)
        key = self._key_for(index, header["key_id"])
        try:
            bundle = self._cipher(key).decrypt(bytes.fromhex(header["nonce"]), body, aad)
        except Exception:
            raise VaultError("backup_failed_authentication_damaged_or_altered") from None
        if len(bundle) != header["size"]:
            raise VaultError("backup_damaged")
        return header, bundle

    @staticmethod
    def _parse(blob):
        if not blob.startswith(MAGIC) or len(blob) < 10:
            raise VaultError("backup_damaged")
        (size,) = struct.unpack(">H", blob[8:10])
        try:
            header = json.loads(blob[10:10 + size].decode())
        except (ValueError, UnicodeError):
            raise VaultError("backup_damaged") from None
        if (type(header) is not dict or set(header) != {"format", "side", "created", "version", "key_id", "nonce", "size"}
                or header["format"] != FORMAT or not re.fullmatch(r"[0-9a-f]{24}", str(header["nonce"]))
                or not re.fullmatch(r"[0-9a-f]{16}", str(header["key_id"])) or type(header["size"]) is not int
                or header["size"] > MAX_BACKUP):
            raise VaultError("backup_damaged")
        return header, blob[:10 + size], blob[10 + size:]

    def _header_of(self, name):
        try:
            with open(str(self.folder / name), "rb") as handle:
                return self._parse(handle.read(4096) + b"")[0]
        except Exception:
            return None

    def open_backup(self, name, index=None):
        """(header, bundle meta, blobs) of one backup, fully checked. Raises VaultError."""
        index = index or self._index()
        header, bundle = self._decrypt(name, index)
        if header["side"] != self.side:
            raise VaultError("backup_damaged")
        meta, blobs = unpack_bundle(bundle)
        if meta.get("side") != self.side or meta.get("format") != FORMAT or "state.tar" not in blobs:
            raise VaultError("backup_damaged")
        return header, meta, blobs

    def _verify(self, name, index, *, with_metadata=False):
        header, meta, blobs = self.open_backup(name, index)
        with tempfile.TemporaryDirectory(dir=str(self.work)) as tmp:
            archive = Path(tmp) / "state.tar"
            archive.write_bytes(blobs["state.tar"])
            try:
                _, files = backup.read_backup(str(archive), expected_kind=self.side)
            except backup.BackupError as error:
                raise VaultError("state_archive_invalid_" + str(error)[:60]) from None
        for member, data in list(files.items()) + [(n, b) for n, b in blobs.items() if n.startswith("extra/")]:
            if member.endswith(".sqlite3") and not _sqlite_ok(data):
                raise VaultError("database_failed_integrity_check")
        return (header, files, blobs, meta) if with_metadata else (header, files, blobs)

    # .. retention ..............................................................................................................
    def _retain(self, index, protect=None, allow_verify=True):
        skip, self._skip_retention = getattr(self, "_skip_retention", False), False
        if skip or index.get("damaged") or not self._valid_index(index):
            return []                                           # never delete anything on the strength of a doubtful index
        verified = sorted((info["created"], name) for name, info in index["backups"].items()
                          if info.get("verified_at") and (self.folder / name).is_file())
        if not verified:
            return []
        complete = [(c, n) for c, n in verified if not index["backups"][n].get("incomplete")]
        if complete:
            newest_complete = index["backups"][complete[-1][1]]
            if int(self.clock()) - (newest_complete.get("checked_at") or newest_complete["verified_at"]) > DAY:
                if not allow_verify:
                    index["prune_held"] = "newest_complete_backup_check_is_stale"
                    return []
                try:                                            # prune only on the strength of a FRESH check of the last good point
                    self._verify(complete[-1][1], index)
                    newest_complete["checked_at"] = int(self.clock())
                except Exception as error:
                    newest_complete["verified_at"], newest_complete["check_failed"] = None, True
                    newest_complete["check_error"] = str(getattr(error, "code", type(error).__name__))[:80]
                    index["prune_held"] = "newest_complete_backup_failed_its_check"
                    return []
        if not self.prune_allowed:
            index["prune_held"] = "owner_side_pruning_disabled_until_safe_coordination"
            return []
        retention = self.effective_retention()
        if not retention["trusted"]:
            index["prune_held"] = "retention_settings_untrusted"
            return []                                           # back up and verify, but delete nothing under a doubtful policy
        index.pop("prune_held", None)
        keep = {verified[-1][1], protect}                       # the newest VERIFIED backup (and the one just made) are never deleted
        if complete:
            keep.add(complete[-1][1])                           # ... nor the newest COMPLETE verified one, however many partial follow
        days, weeks = {}, {}
        for created, name in (complete or verified):            # the daily/weekly windows are filled with complete backups only
            days[time.strftime("%Y%m%d", time.gmtime(created))] = name
            weeks[time.strftime("%G%V", time.gmtime(created))] = name
        for groups, count in ((days, retention["daily"]), (weeks, retention["weekly"])):
            if count > 0:
                keep |= {name for _, name in sorted(groups.items())[-count:]}
        removed = []
        for name in list(index["backups"]):
            info = index["backups"][name]
            if name in keep or not NAME.fullmatch(name) or not name.startswith(self.side + "-") or info.get("check_failed"):
                continue                                        # a backup that failed a re-check is kept for inspection, never pruned
            if not info.get("verified_at") and not info.get("failed") and info["created"] >= verified[-1][0]:
                continue                                        # a newer, not-yet-verified backup is kept
            path = self.folder / name
            if path.is_symlink() or (path.exists() and not path.is_file()):
                continue
            try:
                os.unlink(str(path))
            except FileNotFoundError:
                pass
            del index["backups"][name]
            removed.append(name)
        if removed:
            _fsync_dir(self.folder)
        return removed

    # .. the operations (run inside the separate process when isolate=True) ......................................................
    def _locked(self, fn):
        with self._mutex:
            _private_folder(self.folder)
            lock = os.open(str(self.folder / ".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    raise VaultError("another_backup_operation_is_running") from None
                self._held.locked = True
                try:
                    return fn()
                finally:
                    self._held.locked = False
            finally:
                os.close(lock)

    def _load(self):
        index = self._index()
        if index.get("damaged"):
            self._rebuild(index)
        return index

    def _op_backup(self, manual):
        index = self._load()
        now = int(self.clock())
        if manual and now - index["manual"].get("backup", 0) < MANUAL_BACKUP_EVERY:
            return {"ok": False, "error": "rate_limited", "retry_after": MANUAL_BACKUP_EVERY - (now - index["manual"]["backup"])}
        if manual:
            index["manual"]["backup"] = now
        index["last_attempt"] = now
        try:
            name = self._create(index)
            self._verify(name, index)
            entry = index["backups"][name]
            entry["verified_at"] = entry["checked_at"] = int(self.clock())
            index["last_success"], index["last_error"] = int(self.clock()), None
            index.setdefault("full_check_at", int(self.clock()))   # durable start of the monthly schedule, independent of retention
            removed = self._retain(index, protect=name)
            self._save(index)
            return {"ok": True, "backup": name, "removed": len(removed), "excluded": entry["excluded"],
                    "complete": not entry["incomplete"]}
        except Exception as error:                              # recorded here, so even an unexpected failure is visible
            return self._failed(index, now, error)

    def _failed(self, index, now, error):
        code = getattr(error, "code", None) or (str(error) if isinstance(error, backup.BackupError) else type(error).__name__)
        index["last_error"] = {"at": now, "code": str(code)[:120]}
        try:
            self._save(index)
        except OSError:
            pass
        return {"ok": False, "error": str(code)[:120]}

    def _op_recheck(self, scope="daily"):
        """Re-verify backups that count. daily: the newest verified AND the newest COMPLETE verified one (independently of any newer
        incomplete backup); all: every retained backup (monthly). A backup that fails stops counting and is KEPT and reported
        (check_failed): a failed check never leads to cleanup. If the newest complete one failed, a new backup is due at once."""
        index = self._load()
        now = int(self.clock())
        verified = sorted((info["created"], name) for name, info in index["backups"].items() if info.get("verified_at"))
        if scope == "all":
            names = [n for _, n in verified]
        else:
            complete = [n for _, n in verified if not index["backups"][n].get("incomplete")]
            names = sorted({n for n in ([verified[-1][1]] if verified else []) + complete[-1:]})
        checked, failed = [], []
        for name in names:
            entry = index["backups"][name]
            try:
                if not (self.folder / name).is_file():
                    raise VaultError("verified_backup_file_missing")
                self._verify(name, index)
                entry["checked_at"] = now
                checked.append(name)
            except Exception as error:
                entry["verified_at"], entry["check_failed"] = None, True
                entry["check_error"] = str(getattr(error, "code", type(error).__name__))[:80]
                failed.append(name)
        if scope == "all":
            index["full_check_at"] = now
        if failed:
            index["last_error"] = {"at": now, "code": "newest_backup_failed_recheck_" + index["backups"][failed[-1]]["check_error"]}
        self._save(index)
        return {"ok": not failed, "checked": checked, "failed": failed} if not failed else \
            {"ok": False, "error": index["last_error"]["code"], "checked": checked, "failed": failed}

    def _op_drill(self, manual):
        index = self._load()
        now = int(self.clock())
        if manual and now - index["manual"].get("drill", 0) < MANUAL_DRILL_EVERY:
            return {"ok": False, "error": "rate_limited", "retry_after": MANUAL_DRILL_EVERY - (now - index["manual"]["drill"])}
        if manual:
            index["manual"]["drill"] = now
        verified = sorted((info["created"], name) for name, info in index["backups"].items() if info.get("verified_at"))
        result = {"at": now, "ok": False, "backup": verified[-1][1] if verified else None}
        try:
            if not verified:
                raise VaultError("no_verified_backup_to_drill")
            header, files, blobs = self._verify(verified[-1][1], index)
            with tempfile.TemporaryDirectory(dir=str(self.work)) as tmp:
                target = Path(tmp) / "restored"
                work = (self.folder / ".work").resolve()
                if target.resolve() == self.state_dir.resolve() or work not in target.resolve().parents or target.exists():
                    raise VaultError("drill_target_is_live_state")       # only ever a NEW folder inside the vault's scratch area
                archive = Path(tmp) / "state.tar"
                archive.write_bytes(blobs["state.tar"])
                manifest = backup.restore_backup(str(archive), target, kind=self.side)
                for name, data in files.items():                      # every restored state file equals the backup
                    restored = (target / name).read_bytes()
                    if name == "passkeys.sqlite3":
                        if not _passkeys_all_quarantined(restored):    # intentionally changed: must be quarantined, fail closed
                            raise VaultError("drill_passkeys_were_not_quarantined")
                    elif _sha(restored) != _sha(data):
                        raise VaultError("drill_restored_file_differs_" + name.split("/")[-1][:40])
                    if name.endswith(".sqlite3") and not _sqlite_ok(restored):
                        raise VaultError("drill_database_failed_integrity_check")
                extras = _private_folder(Path(tmp) / "extras")       # every extra recovered too, then checked
                count = 0
                for name, data in blobs.items():
                    if not name.startswith("extra/"):
                        continue
                    flat = name[len("extra/"):].replace("/", "__")
                    if not re.fullmatch(r"[A-Za-z0-9._-]{1,200}", flat) or flat.startswith("."):
                        raise VaultError("drill_extra_name_unsafe")
                    _write_atomic(extras, flat, data)
                    back = _read_private(extras / flat, self.limits["extra"] + 1)
                    if _sha(back) != _sha(data):
                        raise VaultError("drill_extra_differs")
                    if name.endswith(".sqlite3") and not _sqlite_ok(back):
                        raise VaultError("drill_extra_database_damaged")
                    if name.endswith(".json"):
                        json.loads(back.decode("utf-8"))
                    count += 1
                result.update(ok=True, files=len(manifest["files"]), extras=count)
        except Exception as error:
            code = getattr(error, "code", None) or (str(error) if isinstance(error, (backup.BackupError, ValueError)) else "") \
                or type(error).__name__
            result["error"] = str(code)[:120]
        index["last_drill"] = result
        self._save(index)
        return result

    def _op(self, op, manual=False, args=None):
        if self.side == "owner" and op == "rotate" and os.path.lexists(self.folder / OWNER_RESTORE_INTENT):
            raise VaultError("root_restore_in_progress")
        if self.side == "root":
            from . import root_restore
            if root_restore.held(self.state_dir):
                raise VaultError("root_restore_in_progress")
            if op == "restore_preview":
                if self._rotation_active():
                    raise VaultError("key_rotation_in_progress")
                return root_restore.preview(self, (args or {}).get("archive"))
        if op not in ("rotate", "rotate_prepare", "rotate_cancel") and self._rotation_active():
            raise VaultError("key_rotation_in_progress")           # nothing else runs until the rotation has finished or resumed
        args = args or {}
        return {"backup": lambda: self._op_backup(manual), "drill": lambda: self._op_drill(manual),
                "recheck": lambda: self._op_recheck("daily"), "recheck_all": lambda: self._op_recheck("all"),
                "rotate": lambda: self._op_rotate(args.get("mode"), args.get("request_id")),
                "rotate_prepare": lambda: self._op_prepare(args.get("mode"), args.get("request_id"), args.get("expires_at")),
                "rotate_cancel": lambda: self._op_cancel(args.get("request_id"))}[op]()

    # .. public ...................................................................................................................
    def _spec(self, op, manual, args=None):
        return {"args": args or {}, "side": self.side, "state_dir": str(self.state_dir), "folder": str(self.folder), "extras": self._extra_list(),
                "version": self.version, "retention": self.retention, "limits": self.limits, "op": op, "manual": manual,
                "prune_allowed": self.prune_allowed}

    def _adopt(self, theirs):
        """Owner side: take over the installer's policy. True only if it is valid, trusted and consistent with what we hold."""
        if not isinstance(theirs, dict) or theirs.get("trusted") is False or not valid_retention(theirs.get("daily"), theirs.get("weekly")):
            return False
        mine = self.effective_retention()
        if theirs.get("approved"):
            if (theirs["daily"], theirs["weekly"], theirs["approved"]) != (mine["daily"], mine["weekly"], mine["approved"]):
                self.set_retention(theirs["daily"], theirs["weekly"], theirs["approved"])
            return self.effective_retention()["trusted"]
        return not self._policy_evidence()                  # we hold an approval the installer no longer reports: not consistent

    def _sync_retention(self):
        """Owner side, before a run: keep the shown setting current (best effort). It NEVER allows pruning by itself."""
        if self.retention_source is None:
            return
        try:
            self._adopt(self.retention_source())
        except Exception:
            pass

    def _run(self, op, manual=False, args=None):
        self._sync_retention()
        return self._run_op(op, manual, args)

    def _run_op(self, op, manual=False, args=None):
        if not self.isolate:
            return self._guard(lambda: self._op(op, manual, args))
        with self._mutex:
            import subprocess
            import sys
            paths = [p for p in sys.path if p and os.path.isdir(p)]
            code = ("import sys,json;sys.path[:0]=json.loads(sys.argv[1]);from stynpilot.vault import _child;_child()")
            error = "backup_process_unavailable"
            try:
                done = subprocess.run([sys.executable, "-IB", "-X", "pycache_prefix=" + (sys.pycache_prefix or "/usr/lib/stynpilot/.source-only"), "-c", code, json.dumps(paths)], input=json.dumps(self._spec(op, manual, args)).encode(),
                                      capture_output=True, timeout=CHILD_TIMEOUT, close_fds=True)
                lines = done.stdout.decode("utf-8", "replace").strip().splitlines()
                result = json.loads(lines[-1][-65536:]) if done.returncode == 0 and lines else None
                if isinstance(result, dict) and result.get("error") != "backup_worker_memory_limit_unavailable":
                    return result
                error = result["error"] if isinstance(result, dict) else "backup_process_failed_exit_%d" % done.returncode
            except subprocess.TimeoutExpired:
                error = "backup_process_timed_out"
            except (OSError, ValueError):
                pass
        # the child died (memory limit, crash, timeout): record it from here; the service itself is unaffected
        self._guard(lambda: self._record_worker_failure(op, error))
        return {"ok": False, "error": error}

    def _record_worker_failure(self, op, error):
        index = self._index()
        if index.get("damaged"):
            return None                                       # never overwrite a damaged index from here; the next run rebuilds it
        now = int(self.clock())
        if op == "rotate":
            index["last_error"] = {"at": now, "code": "key_rotation_" + error}
        elif op == "drill":
            index["last_drill"] = {"at": now, "ok": False, "backup": None, "error": error}
        else:
            index["last_error"] = {"at": now, "code": ("recheck_" if op == "recheck" else "") + error}
            if op == "backup":
                index["last_attempt"] = now
        self._save(index)
        return None

    def backup_now(self, *, manual=False):
        return self._run("backup", manual)

    def drill(self, *, manual=False):
        return self._run("drill", manual)

    def recheck(self):
        return self._run("recheck")

    def recheck_all(self):
        return self._run("recheck_all")

    def rotate_key(self, mode, request_id):
        """Owner-approved (YELLOW) key rotation. request_id=None resumes an interrupted one. The result always carries the
        DURABLE state: rotation 'completed', 'in_progress' (journal present: it resumes) or 'failed' (nothing in progress)."""
        result = dict(self._rotate_exclusive(mode, request_id))
        if result.get("nothing_to_resume"):
            return result
        progress = self.rotation_progress()
        result["progress"] = progress
        if result.get("ok"):
            result["rotation"] = "completed"
        elif progress is not None and progress.get("state") != "awaiting_authorization":
            result["rotation"] = "in_progress"
        else:
            result["rotation"] = "failed"
        rid = result.get("request_id") or request_id
        if result["rotation"] == "completed" and rid:
            self._notify(rid, result)
        return result

    def _notify(self, rid, result):
        if self.on_rotation_finished is not None:
            try:
                self.on_rotation_finished(rid, result)
            except Exception:
                pass

    def _rotate_exclusive(self, mode, request_id):
        """Root side: the whole rotation step (start or resume) runs while holding the installer's operation lock, and only if
        no other installer change (install, rollback, upgrade, release) is running or pending - checked UNDER that lock, so a
        change can never start in between (the installer checks for an active journal under the same lock)."""
        if self.side != "root":
            return self._run("rotate", args={"mode": mode, "request_id": request_id})
        try:
            with statelock.operation(self.state_dir, "an_install_or_rollback_is_running_try_again_when_it_finishes"):
                if self.change_running is not None:
                    current = self.journal_request()
                    own = request_id or (current[0] if current else None)
                    try:
                        busy = self.change_running(own)
                    except Exception:
                        busy = True
                    if busy:
                        return {"ok": False, "error": "another_change_is_still_running"}
                return self._run("rotate", args={"mode": mode, "request_id": request_id})
        except statelock.Busy as busy:
            return {"ok": False, "error": busy.code}

    def prepare_rotation(self, mode, request_id, expires_at):
        """Owner side, BEFORE the installer is asked: the durable marker of an approved-but-not-yet-authorized rotation."""
        return self._guard(lambda: self._op_prepare(mode, request_id, expires_at))

    def _check_awaiting(self, journal):
        """Owner side: settle a marker whose hand-off was interrupted, by asking the installer's own durable record."""
        if self.authorization_source is None or self.clock() - journal["created"] < AWAIT_GRACE:
            return None
        verdict = self.authorization_source(journal["request_id"])
        if verdict == "authorized":
            result = self.rotate_key(journal["mode"], journal["request_id"])
            if result.get("rotation") == "failed" and result.get("error") not in _TRANSIENT:
                verdict = "refused"                             # it can never start (e.g. key state changed): end it honestly
                stopped = result.get("error")
            else:
                return result
        else:
            stopped = "installer_did_not_authorize"
        if verdict == "refused":
            result = self._guard(lambda: self._op_cancel(journal["request_id"]))
            if result.get("ok"):
                self._notify(journal["request_id"], {"ok": False, "stopped": stopped, "rotation": "failed",
                                                     "changed_anything": False})
            return result
        return {"ok": None, "waiting_for_installer": True}

    def tick(self):
        """What is due: re-check what counts (presence hourly; full daily check of the newest verified AND the newest complete
        verified backup; every retained backup monthly), the first backup at once, a missed or replacement one, a weekly drill."""
        done = {}
        try:
            journal = self._journal()
        except VaultError:
            journal = {"state": "damaged"}
        if journal is not None and journal["state"] == "awaiting_authorization":
            checked = self._check_awaiting(journal)
            if checked is not None:
                done["rotate"] = checked
        if self._rotation_active():
            done["rotate"] = self.rotate_key(None, None)        # an interrupted rotation finishes before anything else
            if self._rotation_active():
                self._run_hooks()
                return done
        index = self._index()
        now = int(self.clock())
        verified = sorted((i["created"], n, i) for n, i in index["backups"].items() if i.get("verified_at"))
        complete = [v for v in verified if not v[2].get("incomplete")]
        watched = {v[1]: v[2] for v in verified[-1:] + complete[-1:]}
        if any(not (self.folder / n).is_file() or now - (i.get("checked_at") or i["verified_at"]) >= DAY for n, i in watched.items()):
            done["recheck"] = self.recheck()
            index = self._index()
        if verified and now - (index.get("full_check_at") or now) >= FULL_CHECK_EVERY:
            done["recheck_all"] = self.recheck_all()
            index = self._index()
        newest = max((i["verified_at"] or 0 for i in index["backups"].values()), default=0)
        if now - newest >= DUE_AFTER or str((index.get("last_error") or {}).get("code", "")).startswith("newest_backup_failed_recheck"):
            last = index.get("last_attempt") or 0
            failed_recheck = str((index.get("last_error") or {}).get("code", "")).startswith("newest_backup_failed_recheck")
            if not index.get("last_error") or (failed_recheck and now - last >= 600) or now - last >= 3600:
                done["backup"] = self.backup_now()
        last_drill = (index.get("last_drill") or {}).get("at") or 0
        if now - last_drill >= DRILL_EVERY and (newest or done.get("backup", {}).get("ok")):
            done["drill"] = self.drill()
        self._run_hooks()
        return done

    def _run_hooks(self):
        for hook in list(self.tick_hooks):
            try:
                hook()
            except Exception:
                pass

    def _guard(self, fn):
        try:
            return self._locked(fn)
        except VaultError as error:
            return {"ok": False, "error": error.code}
        except Exception as error:                                # never into the service that runs us
            return {"ok": False, "error": "internal_" + type(error).__name__}

    def status(self):
        """Read-only health: metadata only (names, times, sizes, results). Never contents, keys or file paths outside the vault."""
        try:
            index = self._index()
            now = int(self.clock())
            present = {p.name for p in self._files()} if self.folder.is_dir() else set()
            backups = sorted(({"name": n, "created": i["created"], "size": i["size"], "verified": bool(i.get("verified_at")),
                               "present": n in present, "complete": not i.get("incomplete")} for n, i in index["backups"].items()),
                             key=lambda b: b["created"])
            verified = [b for b in backups if b["verified"] and b["present"]]
            problems = []
            if index.get("damaged"):
                problems.append("vault_index_damaged")
            if (present or index.get("key_id")) and not self.key_file.exists():
                problems.append("backup_key_missing")
            if (present or index.get("key_id")) and not (self.folder / NONCE_LOG).exists():
                problems.append("nonce_log_missing")
            rotating = self._rotation_active()
            progress = self.rotation_progress()
            if rotating:
                problems.append("key_rotation_incomplete")
            elif progress is not None:
                problems.append("key_rotation_awaiting_installer_authorization")
            if index.get("unreadable"):
                problems.append("unreadable_backups_kept:%d" % len(index["unreadable"]))
            if not verified:
                problems.append("no_verified_backup")
            elif now - verified[-1]["created"] > OVERDUE_AFTER:
                problems.append("backup_overdue")
            if any(b["verified"] and not b["present"] for b in backups):
                problems.append("verified_backup_file_missing")
            complete = [b for b in verified if b["complete"]]
            if verified and not verified[-1]["complete"]:
                problems.append("incomplete_backup:" + ",".join(index["backups"][verified[-1]["name"]].get("incomplete", [])))
            if not complete:
                problems.append("no_complete_verified_backup")
            elif now - complete[-1]["created"] > OVERDUE_AFTER:
                problems.append("complete_backup_overdue")
            retention = self.effective_retention()
            if not retention["trusted"]:
                problems.append("retention_settings_untrusted")
            if index.get("prune_held"):
                problems.append("pruning_on_hold:" + str(index["prune_held"]))
            bad = [n for n, i in index["backups"].items() if i.get("check_failed")]
            if bad:
                problems.append("backups_failed_a_recheck:%d" % len(bad))
            if index.get("last_error"):
                problems.append("last_backup_failed:" + index["last_error"]["code"])
            drill = index.get("last_drill")
            if drill and not drill.get("ok"):
                problems.append("last_recovery_drill_failed:" + str(drill.get("error")))
            try:
                free = self.space(str(self.folder)).free
                if verified and free < 2 * verified[-1]["size"] + SPACE_MARGIN:
                    problems.append("insufficient_storage")
            except OSError:
                free = None
            return {"side": self.side, "healthy": not problems, "problems": problems, "count": len(backups),
                    "newest_verified": verified[-1] if verified else None,
                    "newest_complete_verified": complete[-1] if complete else None,
                    "last_full_check": index.get("full_check_at"), "last_success": index.get("last_success"),
                    "last_error": index.get("last_error"), "last_drill": drill, "retention": self.effective_retention(),
                    "excluded_last_time": (index["backups"].get(verified[-1]["name"], {}).get("excluded") if verified else None),
                    "free_bytes": free, "encrypted": "AES-256-GCM",
                    "keys": {"active": index.get("key_id"), "rotation": progress,
                             "kept_generations": self.generations(),
                             "last_rotation": {k: v for k, v in (index.get("last_rotation") or {}).items() if k != "request_id"} or None}}
        except Exception as error:
            return {"side": self.side, "healthy": False, "problems": ["status_unreadable_" + type(error).__name__]}


def _child():
    """The separate process: memory-limited, does ONE operation, prints one JSON line. Its death cannot harm the service."""
    import resource
    import sys
    spec = json.loads(sys.stdin.read(1 << 20))
    try:
        limit = int(spec["limits"]["memory"])
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        if resource.getrlimit(resource.RLIMIT_AS)[0] != limit:
            raise OSError("limit not in force")
    except (ValueError, OSError, KeyError, TypeError):
        sys.stdout.write(json.dumps({"ok": False, "error": "backup_worker_memory_limit_unavailable"}) + "\n")
        return                                                # fail closed: no heavy work without the limit
    v = Vault(side=spec["side"], state_dir=spec["state_dir"], folder=spec["folder"], extras=[tuple(e) for e in spec["extras"]],
              version=spec["version"], retention=spec["retention"], limits=spec["limits"])
    v.prune_allowed = spec.get("prune_allowed") is True
    result = v._guard(lambda: v._op(spec["op"], spec["manual"], spec.get("args")))
    sys.stdout.write(json.dumps(result) + "\n")
def start_scheduler(vault, *, interval=3600, first_delay=30, stop=None):
    """Background thread: tick at start (after a short delay) and then every ``interval`` seconds. Never raises."""
    stop = stop or threading.Event()

    def loop():
        if stop.wait(first_delay):
            return
        while True:
            try:
                vault.tick()
            except Exception:
                pass
            if stop.wait(interval):
                return
    thread = threading.Thread(target=loop, name="stynpilot-vault-%s" % vault.side, daemon=True)
    thread.start()
    return stop, thread
